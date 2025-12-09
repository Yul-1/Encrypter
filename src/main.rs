use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use argon2::{
    password_hash::{SaltString, PasswordHasher},
    Argon2, Params, Algorithm, Version,
};
use rand::{Rng, RngCore};
use rand::distributions::Alphanumeric;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

// Configuration
const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const PROGRESS_THRESHOLD: u64 = 1024 * 1024; // 1MB

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  Encrypt: {} encrypt <path>", args[0]);
        eprintln!("  Decrypt: {} decrypt <path> <keyfile>", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];
    let path = &args[2];

    match command.as_str() {
        "encrypt" => encrypt_entry_point(path)?,
        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Error: Please specify the .key file for decryption.");
                std::process::exit(1);
            }
            decrypt_entry_point(path, &args[3])?;
        }
        _ => {
            eprintln!("Invalid command. Use 'encrypt' or 'decrypt'.");
            std::process::exit(1);
        }
    }

    Ok(())
}

// --- Entry Points ---

fn encrypt_entry_point(path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path_str);
    
    if !path.exists() {
        return Err("Path does not exist".into());
    }

    // Password setup
    let password = read_password("Enter password to protect the key: ")?;
    let password_confirm = read_password("Confirm password: ")?;
    
    if password != password_confirm {
        return Err("Passwords do not match".into());
    }

    // Generate master key
    let mut master_key = [0u8; 32];
    OsRng.fill_bytes(&mut master_key);

    // Encrypt the master key itself
    let protected_key = protect_key_with_password(&master_key, &password)?;
    
    // Determine key location
    let key_path = if path.is_dir() {
        let parent = path.parent().unwrap_or(Path::new("."));
        let stem = path.file_stem().unwrap_or(path.as_os_str());
        let mut p = parent.join(stem);
        p.set_extension("key");
        p
    } else {
        path.with_extension("key")
    };

    let final_key_path = get_unique_path(key_path)?;

    // Write key to disk immediately before processing files
    {
        let mut key_file = File::create(&final_key_path)?;
        key_file.write_all(&protected_key)?;
        key_file.sync_all()?;
    }

    println!("Master Key saved to: {}", final_key_path.display());
    println!("IMPORTANT: Keep this key safe. You cannot recover data without it.");

    // Start Encryption
    if path.is_file() {
        if let Err(e) = encrypt_file(path, &master_key) {
             eprintln!("Encryption failed: {}", e);
        }
    } else if path.is_dir() {
        if let Err(e) = encrypt_directory_recursive(path, &master_key) {
            eprintln!("Encryption process encountered errors: {}", e);
        }
    }

    Ok(())
}

fn decrypt_entry_point(path_str: &str, keyfile_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path_str);
    let key_path = Path::new(keyfile_str);
    
    if !path.exists() || !key_path.exists() {
        return Err("Target path or key file not found".into());
    }

    // Load Key
    let protected_key = fs::read(key_path)?;
    let password = read_password("Enter password: ")?;
    let master_key = recover_key_from_password(&protected_key, &password)?;

    println!("Password correct. Starting decryption...");

    let mut stats = EncryptionStats { total: 0, success: 0, errors: Vec::new() };

    // Decrypt
    if path.is_file() {
        stats.total = 1;
        match decrypt_file(path, &master_key) {
            Ok(_) => stats.success += 1,
            Err(e) => stats.errors.push(format!("File {}: {}", path.display(), e)),
        }
    } else if path.is_dir() {
        stats.total = WalkDir::new(path).into_iter().count(); 
        decrypt_directory_recursive(path, &master_key, &mut stats)?;
    }

    // Final Report
    if !stats.errors.is_empty() {
        println!("\nERRORS encountered:");
        for e in &stats.errors {
            println!(" - {}", e);
        }
        println!("\nWARNING: Key file was NOT deleted because errors occurred.");
    } else {
        println!("\nVerification: All operations successful.");
        fs::remove_file(key_path)?;
        println!("SUCCESS: Key file deleted securely.");
    }

    Ok(())
}

struct EncryptionStats {
    total: usize,
    success: usize,
    errors: Vec<String>,
}

// --- Recursive Logic ---

fn encrypt_directory_recursive(path: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    // Process contents FIRST (Bottom-Up)
    let entries: Vec<PathBuf> = fs::read_dir(path)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();

    for entry in entries {
        if entry.is_dir() {
            encrypt_directory_recursive(&entry, key)?;
        } else {
            encrypt_file(&entry, key)?;
        }
    }

    // Create Directory Marker
    let original_name = path.file_name()
        .ok_or("Invalid directory name")?
        .to_string_lossy()
        .to_string();
    
    let name_ciphertext = simple_encrypt_data(original_name.as_bytes(), key)?;
    
    let marker_path = path.join(".dirname.enc");
    fs::write(&marker_path, name_ciphertext)?;

    // Rename Directory
    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    
    let parent = path.parent().unwrap_or(Path::new("."));
    let new_path = parent.join(random_name);

    fs::rename(path, &new_path)?;
    println!("Encrypted Dir: {} -> {}", original_name, new_path.file_name().unwrap().to_string_lossy());

    Ok(())
}

fn decrypt_directory_recursive(path: &Path, key: &[u8; 32], stats: &mut EncryptionStats) -> Result<(), Box<dyn std::error::Error>> {
    // Check for Directory Marker (Top-Down)
    let marker_path = path.join(".dirname.enc");
    
    let current_path = if marker_path.exists() {
        let encrypted_name = fs::read(&marker_path)?;
        
        match simple_decrypt_data(&encrypted_name, key) {
            Ok(name_bytes) => {
                let original_name = String::from_utf8(name_bytes)
                    .map_err(|_| "Invalid UTF-8 in directory name")?;
                
                let parent = path.parent().unwrap_or(Path::new("."));
                let new_path = get_unique_path(parent.join(&original_name))?;

                fs::rename(path, &new_path)?;
                fs::remove_file(new_path.join(".dirname.enc"))?;
                
                println!("Restored Dir: {}", new_path.display());
                new_path
            },
            Err(e) => {
                stats.errors.push(format!("Failed to decrypt directory {}: {}", path.display(), e));
                path.to_path_buf()
            }
        }
    } else {
        path.to_path_buf()
    };

    // Process contents
    let entries: Vec<PathBuf> = match fs::read_dir(&current_path) {
        Ok(iter) => iter.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(e) => {
            stats.errors.push(format!("Cannot read dir {}: {}", current_path.display(), e));
            return Ok(());
        }
    };

    for entry in entries {
        if entry.is_dir() {
            decrypt_directory_recursive(&entry, key, stats)?;
        } else if entry.extension().and_then(|s| s.to_str()) == Some("enc") {
             match decrypt_file(&entry, key) {
                 Ok(_) => stats.success += 1,
                 Err(e) => stats.errors.push(format!("File {}: {}", entry.display(), e)),
             }
        }
    }

    Ok(())
}

// --- File Logic (Streaming / Chunked / XChaCha) ---

fn encrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(filepath)?;
    let file_size = metadata.len();
    
    // Output path setup
    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let encrypted_filename = format!("{}.enc", random_name);
    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let final_path = parent_dir.join(encrypted_filename);

    if final_path.exists() {
        return encrypt_file(filepath, key); 
    }

    println!("Encrypting: {}", filepath.display());

    let mut source_file = File::open(filepath)?;
    let mut dest_file = File::create(&final_path)?;

    // Generate a file-unique salt (20 bytes for XChaCha construction)
    // Nonce(24) = Salt(20) + Counter(4)
    let mut file_salt = [0u8; 20];
    OsRng.fill_bytes(&mut file_salt);
    dest_file.write_all(&file_salt)?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let mut chunk_counter: u32 = 0;

    // Encrypt Metadata (Filename) as Chunk 0
    let original_filename = filepath.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();
    let filename_bytes = original_filename.as_bytes();
    
    let nonce = create_nonce(&file_salt, chunk_counter);
    chunk_counter += 1;

    let encrypted_metadata = cipher.encrypt(&nonce, filename_bytes)
        .map_err(|e| format!("Encryption error (metadata): {}", e))?;
    
    // Write Metadata Block: [Len(4)][Ciphertext]
    let meta_len = encrypted_metadata.len() as u32;
    dest_file.write_all(&meta_len.to_le_bytes())?;
    dest_file.write_all(&encrypted_metadata)?;

    // Encrypt Content (Streaming)
    let pb = if file_size > PROGRESS_THRESHOLD {
        let p = ProgressBar::new(file_size);
        p.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"));
        Some(p)
    } else {
        None
    };

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == 0 { break; }

        let nonce = create_nonce(&file_salt, chunk_counter);
        
        let ciphertext = cipher.encrypt(&nonce, &buffer[..read_count])
            .map_err(|e| format!("Encryption error (chunk {}): {}", chunk_counter, e))?;

        // Write Chunk: [Len(4)][Ciphertext]
        let chunk_len = ciphertext.len() as u32;
        dest_file.write_all(&chunk_len.to_le_bytes())?;
        dest_file.write_all(&ciphertext)?;

        if let Some(ref p) = pb {
            p.inc(read_count as u64);
        }

        chunk_counter = chunk_counter.checked_add(1).ok_or("File too large (counter overflow)")?;
    }

    if let Some(p) = pb {
        p.finish_and_clear();
    }

    // Sync and remove original
    dest_file.sync_all()?;
    fs::remove_file(filepath)?;
    
    println!("Done: File encrypted.");
    Ok(())
}

fn decrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing: {}", filepath.display());

    let mut source_file = File::open(filepath)?;
    let file_len = source_file.metadata()?.len();

    if file_len < 20 { return Err("File too small".into()); }

    // Read File Salt (20 bytes)
    let mut file_salt = [0u8; 20];
    source_file.read_exact(&mut file_salt)?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let mut chunk_counter: u32 = 0;

    // Read Metadata Chunk (Chunk 0)
    let mut len_buf = [0u8; 4];
    source_file.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;
    
    if meta_len > 4096 { return Err("Metadata header too large, file likely corrupt".into()); }

    let mut meta_ciphertext = vec![0u8; meta_len];
    source_file.read_exact(&mut meta_ciphertext)?;

    let nonce = create_nonce(&file_salt, chunk_counter);
    chunk_counter += 1;

    let filename_bytes = cipher.decrypt(&nonce, meta_ciphertext.as_ref())
        .map_err(|_| "Decryption failed (Metadata): Wrong key or corrupt header")?;
    
    let original_name = String::from_utf8(filename_bytes)
        .map_err(|_| "Invalid UTF-8 in filename")?;

    // Prepare Output
    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let mut original_path = parent_dir.join(original_name);
    original_path = get_unique_path(original_path)?;
    
    let mut dest_file = File::create(&original_path)?;

    // Decrypt Content Chunks
    loop {
        let bytes_read = source_file.read(&mut len_buf)?;
        if bytes_read == 0 { break; } 
        if bytes_read < 4 { return Err("Truncated chunk header".into()); }

        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        if chunk_len > CHUNK_SIZE + 1024 { return Err("Invalid chunk size detected".into()); }

        let mut chunk_ciphertext = vec![0u8; chunk_len];
        source_file.read_exact(&mut chunk_ciphertext)?;

        let nonce = create_nonce(&file_salt, chunk_counter);
        
        let plaintext = cipher.decrypt(&nonce, chunk_ciphertext.as_ref())
            .map_err(|_| format!("Decryption failed at chunk {}", chunk_counter))?;
        
        dest_file.write_all(&plaintext)?;
        
        chunk_counter = chunk_counter.checked_add(1).ok_or("Counter overflow")?;
    }

    dest_file.sync_all()?;
    fs::remove_file(filepath)?;
    println!("Restored: {}", original_path.file_name().unwrap_or_default().to_string_lossy());

    Ok(())
}

// --- Helpers ---

// XChaCha20 uses 24-byte nonces. We combine a random 20-byte salt + 4-byte counter.
fn create_nonce(salt: &[u8; 20], counter: u32) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..20].copy_from_slice(salt);
    nonce_bytes[20..].copy_from_slice(&counter.to_be_bytes());
    *XNonce::from_slice(&nonce_bytes)
}

fn simple_encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    // XChaCha needs 24 bytes nonce. For simple data, we generate fully random 24 bytes.
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn simple_decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() < 24 { return Err("Data too short".into()); }
    
    let cipher = XChaCha20Poly1305::new(key.into());
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed".into())
}

fn protect_key_with_password(key: &[u8; 32], password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    
    // Argon2 Hardening: Use custom parameters instead of default
    let params = Params::new(
        65536,  // m_cost: 64 MB
        4,      // t_cost: 4 passes
        4,      // p_cost: 4 lanes
        None    // output len (default)
    ).map_err(|e| format!("Argon2 params error: {}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Hash error: {}", e))?;
    
    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    
    let protected = simple_encrypt_data(key, &derived_key)?;
    
    let mut result = Vec::new();
    result.extend_from_slice(salt.as_str().as_bytes());
    result.extend_from_slice(&protected);
    
    Ok(result)
}

fn recover_key_from_password(protected_key: &[u8], password: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if protected_key.len() < 22 { return Err("Invalid key file".into()); }
    
    let salt_str = std::str::from_utf8(&protected_key[..22])?;
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| format!("Invalid salt: {}", e))?;
    
    let encrypted_master_key = &protected_key[22..];
    
    // Must match the parameters used in encryption
    let params = Params::new(65536, 4, 4, None).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "Wrong password")?;
    
    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    
    let decrypted_bytes = simple_decrypt_data(encrypted_master_key, &derived_key)
        .map_err(|_| "Wrong password or corrupted key")?;
    
    let mut master_key = [0u8; 32];
    if decrypted_bytes.len() != 32 { return Err("Invalid key length".into()); }
    master_key.copy_from_slice(&decrypted_bytes);
    
    Ok(master_key)
}

fn read_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    if password.is_empty() { return Err("Password cannot be empty".into()); }
    Ok(password)
}

fn get_unique_path(path: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !path.exists() { return Ok(path); }
    
    let parent = path.parent().ok_or("Invalid path")?;
    let stem = path.file_stem().and_then(|s| s.to_str()).ok_or("Invalid name")?;
    let extension = path.extension().and_then(|s| s.to_str());
    
    for i in 1..10000 {
        let new_name = if let Some(ext) = extension {
            format!("{}_{}.{}", stem, i, ext)
        } else {
            format!("{}_{}", stem, i)
        };
        let new_path = parent.join(new_name);
        if !new_path.exists() { return Ok(new_path); }
    }
    Err("Too many duplicates".into())
}