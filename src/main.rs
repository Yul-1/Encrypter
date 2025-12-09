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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const CHUNK_SIZE: usize = 4096 * 1024;
const PROGRESS_THRESHOLD: u64 = 1024 * 1024;
const CHUNK_TYPE_DATA: u8 = 0;
const CHUNK_TYPE_EOF: u8 = 1;
const MAX_DEPTH: usize = 50;

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureKey {
    key: [u8; 32],
}

impl SecureKey {
    fn new(data: [u8; 32]) -> Self {
        Self { key: data }
    }
    
    fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

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

fn encrypt_entry_point(path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path_str);
    
    if !path.exists() {
        return Err("Path does not exist".into());
    }

    let mut password = read_password("Enter password to protect the key: ")?;
    let mut password_confirm = read_password("Confirm password: ")?;
    
    if password != password_confirm {
        return Err("Passwords do not match".into());
    }

    let mut master_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut master_key_bytes);
    let master_key = SecureKey::new(master_key_bytes);

    let protected_key = protect_key_with_password(&master_key, &password)?;
    
    password.zeroize();
    password_confirm.zeroize();
    
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

    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        
        #[cfg(unix)]
        options.mode(0o600);

        let mut key_file = options.open(&final_key_path)?;
        key_file.write_all(&protected_key)?;
        key_file.sync_all()?;
    }

    println!("Master Key saved to: {}", final_key_path.display());
    println!("IMPORTANT: Keep this key safe. You cannot recover data without it.");

    if path.is_file() {
        if let Err(e) = encrypt_file(path, &master_key) {
             eprintln!("Encryption failed: {}", e);
        }
    } else if path.is_dir() {
        if let Err(e) = encrypt_directory_recursive(path, &master_key, 0) {
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

    let protected_key = fs::read(key_path)?;
    let mut password = read_password("Enter password: ")?;
    
    let master_key = recover_key_from_password(&protected_key, &password)?;
    password.zeroize();

    println!("Password correct. Starting decryption...");

    let mut stats = EncryptionStats { total: 0, success: 0, errors: Vec::new() };

    if path.is_file() {
        stats.total = 1;
        match decrypt_file(path, &master_key) {
            Ok(_) => stats.success += 1,
            Err(e) => stats.errors.push(format!("File {}: {}", path.display(), e)),
        }
    } else if path.is_dir() {
        stats.total = WalkDir::new(path).into_iter().count(); 
        decrypt_directory_recursive(path, &master_key, &mut stats, 0)?;
    }

    if !stats.errors.is_empty() {
        println!("\nERRORS encountered:");
        for e in &stats.errors {
            println!(" - {}", e);
        }
        println!("\nWARNING: Key file was NOT deleted because errors occurred.");
    } else {
        println!("\nVerification: All operations successful.");
        secure_delete(key_path)?;
        println!("SUCCESS: Key file deleted securely.");
    }

    Ok(())
}

struct EncryptionStats {
    total: usize,
    success: usize,
    errors: Vec<String>,
}

fn encrypt_directory_recursive(path: &Path, key: &SecureKey, depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    if depth > MAX_DEPTH {
        return Err(format!("Directory depth limit exceeded at {}", path.display()).into());
    }

    let entries: Vec<PathBuf> = fs::read_dir(path)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();

    for entry in entries {
        if entry.is_dir() {
            encrypt_directory_recursive(&entry, key, depth + 1)?;
        } else {
            encrypt_file(&entry, key)?;
        }
    }

    let original_name = path.file_name()
        .ok_or("Invalid directory name")?
        .to_string_lossy()
        .to_string();
    
    let name_ciphertext = simple_encrypt_data(original_name.as_bytes(), key)?;
    
    let marker_path = path.join(".dirname.enc");
    fs::write(&marker_path, name_ciphertext)?;

    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    
    let parent = path.parent().unwrap_or(Path::new("."));
    let new_path = parent.join(random_name);

    fs::rename(path, &new_path)?;
    println!("Encrypted Dir: {} -> {}", original_name, new_path.file_name().unwrap_or_default().to_string_lossy());

    Ok(())
}

fn decrypt_directory_recursive(path: &Path, key: &SecureKey, stats: &mut EncryptionStats, depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    if depth > MAX_DEPTH {
        stats.errors.push(format!("Recursion limit reached at {}", path.display()));
        return Ok(());
    }

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
                
                let marker_in_new_path = new_path.join(".dirname.enc");
                if marker_in_new_path.exists() {
                    if let Err(e) = secure_delete(&marker_in_new_path) {
                        eprintln!("Warning: Failed to securely delete marker {}: {}", marker_in_new_path.display(), e);
                    }
                }
                
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

    let entries: Vec<PathBuf> = match fs::read_dir(&current_path) {
        Ok(iter) => iter.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(e) => {
            stats.errors.push(format!("Cannot read dir {}: {}", current_path.display(), e));
            return Ok(());
        }
    };

    for entry in entries {
        if entry.is_dir() {
            decrypt_directory_recursive(&entry, key, stats, depth + 1)?;
        } else if entry.extension().and_then(|s| s.to_str()) == Some("enc") {
             match decrypt_file(&entry, key) {
                 Ok(_) => stats.success += 1,
                 Err(e) => stats.errors.push(format!("File {}: {}", entry.display(), e)),
             }
        }
    }

    Ok(())
}

fn encrypt_file(filepath: &Path, key: &SecureKey) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(filepath)?;
    let file_size = metadata.len();
    
    // Generate random filename for the encrypted output
    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let encrypted_filename = format!("{}.enc", random_name);
    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let final_path = parent_dir.join(encrypted_filename);

    // Prevent overwriting existing files with the same random name (unlikely but safe)
    if final_path.exists() {
        return encrypt_file(filepath, key); 
    }

    println!("Encrypting: {}", filepath.display());

    let mut source_file = File::open(filepath)?;
    let mut dest_file = File::create(&final_path)?;
    let mut hasher = Sha256::new();

    // Generate and write file salt
    let mut file_salt = [0u8; 20];
    OsRng.fill_bytes(&mut file_salt);
    dest_file.write_all(&file_salt)?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut chunk_counter: u32 = 0;

    // Encrypt filename metadata
    let original_filename = filepath.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();
    let filename_bytes = original_filename.as_bytes();
    
    let nonce = create_nonce(&file_salt, chunk_counter);
    chunk_counter += 1;

    let encrypted_metadata = cipher.encrypt(&nonce, filename_bytes)
        .map_err(|e| format!("Encryption error (metadata): {}", e))?;
    
    // Write metadata block
    dest_file.write_all(&[CHUNK_TYPE_DATA])?;
    let meta_len = encrypted_metadata.len() as u32;
    dest_file.write_all(&meta_len.to_le_bytes())?;
    dest_file.write_all(&encrypted_metadata)?;

    // Setup Progress Bar
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
        // Some zeroize implementations might affect length, or previous loop logic might have sliced it.
        // This ensures read() always has space to write to.
        if buffer.len() < CHUNK_SIZE {
            buffer.resize(CHUNK_SIZE, 0);
        }

        // This prevents creating tiny chunks if the OS returns a partial read.
        let mut read_count = 0;
        while read_count < CHUNK_SIZE {
            let n = source_file.read(&mut buffer[read_count..])?;
            if n == 0 { break; }
            read_count += n;
        }

        if read_count == 0 { break; }

        // Calculate hash of the plaintext chunk
        hasher.update(&buffer[..read_count]);

        let nonce = create_nonce(&file_salt, chunk_counter);
        
        let ciphertext = cipher.encrypt(&nonce, &buffer[..read_count])
            .map_err(|e| format!("Encryption error (chunk {}): {}", chunk_counter, e))?;

        // Write chunk to disk
        dest_file.write_all(&[CHUNK_TYPE_DATA])?;
        let chunk_len = ciphertext.len() as u32;
        dest_file.write_all(&chunk_len.to_le_bytes())?;
        dest_file.write_all(&ciphertext)?;

        // Securely clear the buffer memory
        buffer.zeroize();

        if let Some(ref p) = pb {
            p.inc(read_count as u64);
        }

        chunk_counter = chunk_counter.checked_add(1).ok_or("File too large (counter overflow)")?;
    }

    if let Some(p) = pb {
        p.finish_and_clear();
    }

    // Finalize Integrity Hash
    let final_hash = hasher.finalize();
    let nonce = create_nonce(&file_salt, chunk_counter);
    let encrypted_hash = cipher.encrypt(&nonce, final_hash.as_slice())
        .map_err(|e| format!("Encryption error (hash): {}", e))?;
    
    // Write EOF block
    dest_file.write_all(&[CHUNK_TYPE_EOF])?;
    dest_file.write_all(&encrypted_hash)?;

    dest_file.sync_all()?;
    
    // Cleanup source file
    drop(source_file);
    secure_delete(filepath)?;
    
    println!("Done: File encrypted and integrity secured.");
    Ok(())
}

fn decrypt_file(filepath: &Path, key: &SecureKey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing: {}", filepath.display());

    let mut source_file = File::open(filepath)?;
    let file_len = source_file.metadata()?.len();

    if file_len < 20 { return Err("File too small".into()); }

    let mut file_salt = [0u8; 20];
    source_file.read_exact(&mut file_salt)?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut chunk_counter: u32 = 0;
    let mut hasher = Sha256::new();
    let mut type_buf = [0u8; 1];

    // Read metadata header
    source_file.read_exact(&mut type_buf)?;
    if type_buf[0] != CHUNK_TYPE_DATA {
         return Err("Invalid file structure: Expected metadata block".into());
    }

    let mut len_buf = [0u8; 4];
    source_file.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;
    
    if meta_len > 4096 { return Err("Metadata header too large".into()); }

    let mut meta_ciphertext = vec![0u8; meta_len];
    source_file.read_exact(&mut meta_ciphertext)?;

    let nonce = create_nonce(&file_salt, chunk_counter);
    chunk_counter += 1;

    let filename_bytes = cipher.decrypt(&nonce, meta_ciphertext.as_ref())
        .map_err(|_| "Decryption failed (Metadata): Wrong key or corrupt header")?;
    
    let original_name = String::from_utf8(filename_bytes)
        .map_err(|_| "Invalid UTF-8 in filename")?;

    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let mut final_path = parent_dir.join(original_name);
    final_path = get_unique_path(final_path)?;
    
    let random_temp_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    
    let temp_path = parent_dir.join(format!(".{}.tmp", random_temp_name));

    let mut dest_file = File::create(&temp_path)?;
    let mut integrity_verified = false;

    // Optimization: Reusable buffer for ciphertext reading to avoid allocation loop
    let mut ciphertext_buffer = Vec::with_capacity(CHUNK_SIZE + 1024);

    loop {
        let bytes_read = source_file.read(&mut type_buf)?;
        if bytes_read == 0 { break; } 

        if type_buf[0] == CHUNK_TYPE_EOF {
            let nonce = create_nonce(&file_salt, chunk_counter);
            
            // Expected hash length: 32 bytes (SHA256) + 16 bytes (Poly1305 tag)
            let hash_len = 32 + 16; 
            let mut hash_ciphertext = vec![0u8; hash_len];
            source_file.read_exact(&mut hash_ciphertext)?;

            let stored_hash = cipher.decrypt(&nonce, hash_ciphertext.as_ref())
                .map_err(|_| "Integrity Check Failed: Footer corrupted")?;

            let calculated_hash = hasher.finalize();

            if stored_hash.as_slice() != calculated_hash.as_slice() {
                drop(dest_file);
                secure_delete(&temp_path)?;
                return Err("CRITICAL: Integrity Mismatch. File content has been modified or truncated.".into());
            }
            
            integrity_verified = true;
            break; 
        } else if type_buf[0] == CHUNK_TYPE_DATA {
            source_file.read_exact(&mut len_buf)?;
            let chunk_len = u32::from_le_bytes(len_buf) as usize;
            
            if chunk_len > CHUNK_SIZE + 1024 { 
                drop(dest_file);
                secure_delete(&temp_path)?;
                return Err("Invalid chunk size".into()); 
            }

            // Ensure buffer has enough space for the incoming chunk
            if ciphertext_buffer.len() < chunk_len {
                ciphertext_buffer.resize(chunk_len, 0);
            }

            // Read exactly chunk_len bytes into the buffer
            source_file.read_exact(&mut ciphertext_buffer[..chunk_len])?;

            let nonce = create_nonce(&file_salt, chunk_counter);
            
            let mut plaintext = cipher.decrypt(&nonce, &ciphertext_buffer[..chunk_len])
                .map_err(|_| format!("Decryption failed at chunk {}", chunk_counter))?;
            
            hasher.update(&plaintext);
            dest_file.write_all(&plaintext)?;
            
            // Securely clear the plaintext from memory
            plaintext.zeroize();
            
            chunk_counter = chunk_counter.checked_add(1).ok_or("Counter overflow")?;
        } else {
            drop(dest_file);
            secure_delete(&temp_path)?;
            return Err("Unknown chunk type found".into());
        }
    }

    if !integrity_verified {
        drop(dest_file);
        secure_delete(&temp_path)?;
        return Err("CRITICAL: Truncated file. Integrity footer missing.".into());
    }

    dest_file.sync_all()?;
    drop(dest_file);
    
    if let Err(e) = fs::rename(&temp_path, &final_path) {
        secure_delete(&temp_path)?;
        return Err(format!("Failed to rename temp file to final destination: {}", e).into());
    }
    
    drop(source_file);
    secure_delete(filepath)?;
    
    println!("Restored and Verified: {}", final_path.file_name().unwrap_or_default().to_string_lossy());

    Ok(())
}

fn create_nonce(salt: &[u8; 20], counter: u32) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..20].copy_from_slice(salt);
    nonce_bytes[20..].copy_from_slice(&counter.to_be_bytes());
    *XNonce::from_slice(&nonce_bytes)
}

fn simple_encrypt_data(data: &[u8], key: &SecureKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn simple_decrypt_data(data: &[u8], key: &SecureKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() < 24 { return Err("Data too short".into()); }
    
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed".into())
}

fn protect_key_with_password(key: &SecureKey, password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    
    let params = Params::new(65536, 4, 4, None).map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Hash error: {}", e))?;
    
    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    let secure_derived = SecureKey::new(derived_key);
    
    let protected = simple_encrypt_data(key.as_bytes(), &secure_derived)?;
    
    let salt_str = salt.as_str();
    let salt_len = salt_str.len() as u32;

    let mut result = Vec::new();
    result.extend_from_slice(&salt_len.to_le_bytes());
    result.extend_from_slice(salt_str.as_bytes());
    result.extend_from_slice(&protected);
    
    Ok(result)
}

fn recover_key_from_password(protected_key: &[u8], password: &str) -> Result<SecureKey, Box<dyn std::error::Error>> {
    if protected_key.len() < 4 { return Err("Invalid key file format".into()); }
    
    let (len_bytes, rest) = protected_key.split_at(4);
    let salt_len = u32::from_le_bytes(len_bytes.try_into()?) as usize;
    
    if rest.len() < salt_len { return Err("Key file truncated".into()); }
    let (salt_bytes, encrypted_master_key) = rest.split_at(salt_len);

    let salt_str = std::str::from_utf8(salt_bytes)?;
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| format!("Invalid salt: {}", e))?;
    
    let params = Params::new(65536, 4, 4, None).map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "Wrong password")?;
    
    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    let secure_derived = SecureKey::new(derived_key);
    
    let decrypted_bytes = simple_decrypt_data(encrypted_master_key, &secure_derived)
        .map_err(|_| "Wrong password or corrupted key")?;
    
    if decrypted_bytes.len() != 32 { return Err("Invalid key length".into()); }
    
    let mut master_key_arr = [0u8; 32];
    master_key_arr.copy_from_slice(&decrypted_bytes);
    
    Ok(SecureKey::new(master_key_arr))
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

fn secure_delete(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    let len = metadata.len();
    
    {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut rng = OsRng;
        let buffer_size = 4096 * 1024; // 4MB chunks
        let mut buffer = vec![0u8; buffer_size];
        let mut written_bytes = 0;

        file.seek(SeekFrom::Start(0))?;

        while written_bytes < len {
            let remaining = len - written_bytes;
            let to_write = std::cmp::min(remaining, buffer_size as u64) as usize;
            
            rng.fill_bytes(&mut buffer[0..to_write]);
            file.write_all(&buffer[0..to_write])?;
            
            written_bytes += to_write as u64;
        }
        file.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}