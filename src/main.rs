use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
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

    // Save Master Key (Encrypted with password)
    // We save it OUTSIDE the target structure to avoid encrypting the key itself loop
    let protected_key = protect_key_with_password(&master_key, &password)?;
    
    // Determine key location: sibling to the target
    let key_path = if path.is_dir() {
        // If encrypting "Folder", key is "Folder.key"
        let parent = path.parent().unwrap_or(Path::new("."));
        let stem = path.file_stem().unwrap_or(path.as_os_str());
        let mut p = parent.join(stem);
        p.set_extension("key");
        p
    } else {
        path.with_extension("key")
    };

    let final_key_path = get_unique_path(key_path)?;

    // Start Encryption
    if path.is_file() {
        encrypt_file(path, &master_key)?;
    } else if path.is_dir() {
        encrypt_directory_recursive(path, &master_key)?;
    }

    // Only write key if encryption didn't panic/fail
    fs::write(&final_key_path, &protected_key)?;
    println!("SUCCESS: Master Key saved to: {}", final_key_path.display());
    println!("IMPORTANT: Keep this key safe. You cannot recover data without it.");

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

    // Stats
    let mut stats = EncryptionStats { total: 0, success: 0, errors: Vec::new() };

    // Decrypt
    if path.is_file() {
        stats.total = 1;
        match decrypt_file(path, &master_key) {
            Ok(_) => stats.success += 1,
            Err(e) => stats.errors.push(format!("File {}: {}", path.display(), e)),
        }
    } else if path.is_dir() {
        // We do a rough count first just for the user (optional, but helpful)
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
        // Securely remove key file
        fs::remove_file(key_path)?;
        println!("SUCCESS: Key file deleted securely.");
    }

    Ok(())
}

struct EncryptionStats {
    total: usize, // Approximate
    success: usize,
    errors: Vec<String>,
}

// --- Recursive Logic ---

fn encrypt_directory_recursive(path: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Process contents FIRST (Bottom-Up)
    // We collect entries to avoid holding a lock on the directory iterator while modifying contents
    let entries: Vec<PathBuf> = fs::read_dir(path)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();

    for entry in entries {
        if entry.is_dir() {
            encrypt_directory_recursive(&entry, key)?;
        } else {
            // Check if it is a previously existing key file and encrypt it too
            // or simply a regular file
            encrypt_file(&entry, key)?;
        }
    }

    // 2. Create Directory Marker (contains original name)
    let original_name = path.file_name()
        .ok_or("Invalid directory name")?
        .to_string_lossy()
        .to_string();
    
    // Encrypt the name string
    let name_ciphertext = simple_encrypt_data(original_name.as_bytes(), key)?;
    
    // Write marker file
    let marker_path = path.join(".dirname.enc");
    fs::write(&marker_path, name_ciphertext)?;

    // 3. Rename Directory
    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    
    let parent = path.parent().unwrap_or(Path::new("."));
    let new_path = parent.join(random_name);

    // Atomic rename
    fs::rename(path, &new_path)?;
    println!("Encrypted Dir: {} -> {}", original_name, new_path.file_name().unwrap().to_string_lossy());

    Ok(())
}

fn decrypt_directory_recursive(path: &Path, key: &[u8; 32], stats: &mut EncryptionStats) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Check for Directory Marker (Top-Down)
    let marker_path = path.join(".dirname.enc");
    
    let current_path = if marker_path.exists() {
        // Decrypt directory name
        let encrypted_name = fs::read(&marker_path)?;
        
        match simple_decrypt_data(&encrypted_name, key) {
            Ok(name_bytes) => {
                let original_name = String::from_utf8(name_bytes)
                    .map_err(|_| "Invalid UTF-8 in directory name")?;
                
                let parent = path.parent().unwrap_or(Path::new("."));
                let new_path = get_unique_path(parent.join(&original_name))?;

                fs::rename(path, &new_path)?;
                // Remove marker
                fs::remove_file(new_path.join(".dirname.enc"))?;
                
                println!("Restored Dir: {}", new_path.display());
                new_path // Use new path for children
            },
            Err(e) => {
                stats.errors.push(format!("Failed to decrypt directory {}: {}", path.display(), e));
                path.to_path_buf() // Continue with current path on error
            }
        }
    } else {
        path.to_path_buf()
    };

    // 2. Process contents
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
             // Only attempt to decrypt .enc files
             match decrypt_file(&entry, key) {
                 Ok(_) => stats.success += 1,
                 Err(e) => stats.errors.push(format!("File {}: {}", entry.display(), e)),
             }
        }
    }

    Ok(())
}

// --- File Logic ---

fn encrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(filepath)?;
    let file_size = metadata.len();
    
    // Output path: [random].enc
    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let encrypted_filename = format!("{}.enc", random_name);
    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let final_path = parent_dir.join(encrypted_filename);

    if final_path.exists() {
        return encrypt_file(filepath, key); // Retry if collision
    }

    println!("Encrypting: {}", filepath.display());

    // Prepare Payload: [Len(4)][OriginalName][Content]
    let original_filename = filepath.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();
    let filename_bytes = original_filename.as_bytes();
    let filename_len = filename_bytes.len() as u32;

    let mut file = File::open(filepath)?;
    let mut payload = Vec::with_capacity(4 + filename_bytes.len() + file_size as usize);
    
    payload.extend_from_slice(&filename_len.to_le_bytes());
    payload.extend_from_slice(filename_bytes);

    if file_size > PROGRESS_THRESHOLD {
        let pb = ProgressBar::new(file_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"));
        
        let mut chunk = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file.read(&mut chunk)?;
            if n == 0 { break; }
            payload.extend_from_slice(&chunk[..n]);
            pb.inc(n as u64);
        }
        pb.finish_and_clear();
    } else {
        file.read_to_end(&mut payload)?;
    }

    // Encrypt
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload.as_ref())
        .map_err(|e| format!("Encryption error: {}", e))?;

    // Combine: [Nonce][Ciphertext]
    let mut final_data = nonce_bytes.to_vec();
    final_data.extend_from_slice(&ciphertext);
    
    // Safety: Write to a file, then remove original ONLY if write succeeded
    fs::write(&final_path, final_data)?;
    fs::remove_file(filepath)?;
    
    println!("Done: File encrypted.");
    Ok(())
}

fn decrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing: {}", filepath.display());

    let encrypted_data = fs::read(filepath)?;

    if encrypted_data.len() < 12 + 4 { 
        return Err("File too small".into());
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: Wrong key or corrupted data")?;

    // Parse Payload: [Len][Name][Content]
    if plaintext.len() < 4 { return Err("Invalid payload".into()); }
    
    let name_len_bytes: [u8; 4] = plaintext[..4].try_into()?;
    let name_len = u32::from_le_bytes(name_len_bytes) as usize;

    if plaintext.len() < 4 + name_len { return Err("Payload truncated".into()); }

    let name_bytes = &plaintext[4..4+name_len];
    let original_name = std::str::from_utf8(name_bytes)
        .map_err(|_| "Original filename is not valid UTF-8")?;
    
    let content = &plaintext[4+name_len..];

    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let mut original_path = parent_dir.join(original_name);
    original_path = get_unique_path(original_path)?;

    // Safety: Write new file, then delete encrypted one
    fs::write(&original_path, content)?;
    fs::remove_file(filepath)?;
    
    println!("Restored: {}", original_path.file_name().unwrap_or_default().to_string_lossy());
    
    Ok(())
}

// --- Helpers ---

fn simple_encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn simple_decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() < 12 { return Err("Data too short".into()); }
    
    let cipher = ChaCha20Poly1305::new(key.into());
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed".into())
}

fn protect_key_with_password(key: &[u8; 32], password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Hash error: {}", e))?;
    
    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    
    // Encrypt the master key itself using the derived key
    let protected = simple_encrypt_data(key, &derived_key)?;
    
    // Format: Salt(22) + EncryptedMasterKey(Nonce+Cipher)
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
    
    let argon2 = Argon2::default();
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