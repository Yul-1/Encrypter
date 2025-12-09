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

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const PROGRESS_THRESHOLD: u64 = 1024 * 1024; // 1MB

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Uso:");
        eprintln!("  Criptare:   {} encrypt <file|cartella>", args[0]);
        eprintln!("  Decriptare: {} decrypt <file|cartella> <keyfile>", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];
    let path = &args[2];

    match command.as_str() {
        "encrypt" => encrypt_path(path)?,
        "decrypt" => {
            if args.len() < 4 {
                eprintln!("Specifica il file .key per decriptare");
                std::process::exit(1);
            }
            decrypt_path(path, &args[3])?;
        }
        _ => {
            eprintln!("Comando non valido. Usa 'encrypt' o 'decrypt'");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn encrypt_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    
    // Ask for password
    let password = read_password("Inserisci password per proteggere la chiave: ")?;
    let password_confirm = read_password("Conferma password: ")?;
    
    if password != password_confirm {
        return Err("Le password non corrispondono".into());
    }

    // Generate random master key
    let mut master_key = [0u8; 32];
    OsRng.fill_bytes(&mut master_key);

    // Encrypt master key with user password
    let protected_key = protect_key_with_password(&master_key, &password)?;
    
    if path.is_file() {
        // Encrypt single file
        encrypt_file(path, &master_key)?;
        
        // Save .key file next to the encrypted file (using original name + .key for identification)
        // Note: The encrypted file itself will have a random name.
        let key_path = path.with_extension("key");
        
        // Handle collision for key file if exists
        let key_path = get_unique_path(key_path)?;
        
        fs::write(&key_path, &protected_key)?;
        println!("✓ Chiave salvata: {}", key_path.display());
        
    } else if path.is_dir() {
        let files: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            // Skip existing key files or unrelated files if necessary
            .collect();

        println!("Trovati {} file da criptare", files.len());
        
        for file in &files {
            // Check if file is likely a key or already encrypted (optional safety)
             if file.extension().and_then(|s| s.to_str()) == Some("key") {
                 continue;
             }
            encrypt_file(file, &master_key)?;
        }

        // Save master key in the root folder
        let key_path = get_unique_path(path.join("master.key"))?;
        fs::write(&key_path, &protected_key)?;
        println!("✓ Chiave master salvata: {}", key_path.display());
    } else {
        return Err("Percorso non valido".into());
    }

    println!("\n  IMPORTANTE: Conserva la chiave e ricorda la password!");
    Ok(())
}

fn decrypt_path(path: &str, keyfile: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path_obj = Path::new(path);
    let key_path = Path::new(keyfile);
    
    // Read protected key
    let protected_key = fs::read(key_path)?;
    
    // Ask password
    let password = read_password("Inserisci password: ")?;
    
    // Recover master key
    let master_key = recover_key_from_password(&protected_key, &password)?;

    let mut success_count = 0;
    let total_files; // FIX: Removed "= 0" to avoid unused assignment warning
    let mut errors = Vec::new();

    if path_obj.is_file() {
        // Single file decryption
        total_files = 1;
        match decrypt_file(path_obj, &master_key) {
            Ok(_) => success_count += 1,
            Err(e) => errors.push(format!("{}: {}", path_obj.display(), e)),
        }
    } else if path_obj.is_dir() {
        // Batch decryption
        let files: Vec<PathBuf> = WalkDir::new(path_obj)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file() && 
                       e.path().extension().and_then(|s| s.to_str()) == Some("enc"))
            .map(|e| e.path().to_path_buf())
            .collect();

        total_files = files.len();
        println!("Trovati {} file candidati (.enc)", total_files);
        
        for file in &files {
            match decrypt_file(file, &master_key) {
                Ok(_) => success_count += 1,
                Err(e) => errors.push(format!("{}: {}", file.display(), e)),
            }
        }
    } else {
        return Err("Percorso non valido".into());
    }

    // Reporting
    if !errors.is_empty() {
        println!("\n  Errori riscontrati durante la decrittazione:");
        for err in &errors {
            println!("  - {}", err);
        }
        println!("\n La chiave NON è stata eliminata perché si sono verificati degli errori.");
        return Err("Decrittazione completata parzialmente con errori.".into());
    }

    if total_files > 0 && success_count == total_files {
        println!("\nVerifica completata: {}/{} file decriptati correttamente.", success_count, total_files);
        
        // Securely remove the key file
        fs::remove_file(key_path)?;
        println!("✓ Chiave eliminata definitivamente: {}", key_path.display());
    } else if total_files == 0 {
        println!("Nessun file criptato (.enc) trovato in questo percorso.");
    }

    Ok(())
}

fn encrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(filepath)?;
    let file_size = metadata.len();
    
    // Generate a random filename to hide the original name
    // Format: [16 random chars].enc
    let random_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let encrypted_filename = format!("{}.enc", random_name);
    
    // Determine output path in the same directory
    let parent_dir = filepath.parent().unwrap_or_else(|| Path::new("."));
    let encrypted_path = parent_dir.join(encrypted_filename);

    // Ensure we don't overwrite an existing file (highly unlikely with 16 chars, but safe)
    if encrypted_path.exists() {
        return encrypt_file(filepath, key); // Retry recursion if collision
    }

    println!("Criptando: {}", filepath.display());

    // 1. Prepare Metadata (Original Filename)
    let original_filename = filepath.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();
    let filename_bytes = original_filename.as_bytes();
    let filename_len = filename_bytes.len() as u32;

    // 2. Read content
    let progress = if file_size > PROGRESS_THRESHOLD {
        let pb = ProgressBar::new(file_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"));
        Some(pb)
    } else {
        None
    };

    let mut file = File::open(filepath)?;
    
    // Construct the payload buffer: [Len (4b)][Name Bytes][Content]
    // Reserve memory: 4 + name_len + file_size
    let mut payload = Vec::with_capacity(4 + filename_bytes.len() + file_size as usize);
    
    // Write Header
    payload.extend_from_slice(&filename_len.to_le_bytes());
    payload.extend_from_slice(filename_bytes);

    // Write Content
    if let Some(pb) = &progress {
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

    // 3. Encrypt
    let cipher = ChaCha20Poly1305::new(key.into());
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload.as_ref())
        .map_err(|e| format!("Errore di crittografia: {}", e))?;

    // 4. Save to Disk: [Nonce][Ciphertext]
    let mut final_data = nonce_bytes.to_vec();
    final_data.extend_from_slice(&ciphertext);
    
    fs::write(&encrypted_path, final_data)?;
    
    // Remove original file
    fs::remove_file(filepath)?;
    
    println!("✓ Criptato: {} → {}", filepath.file_name().unwrap_or_default().to_string_lossy(), encrypted_path.file_name().unwrap().to_string_lossy());
    
    Ok(())
}

fn decrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {

    println!("Elaborazione: {}", filepath.display());

    // Read encrypted file
    let encrypted_data = fs::read(filepath)?;

    if encrypted_data.len() < 12 + 4 { // Nonce + Len + min
        return Err("File troppo piccolo o corrotto".into());
    }

    // Setup cipher
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Split Nonce and Ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decrittografia fallita: chiave errata o dati corrotti")?;

    // --- Parse Payload ---
    // Format: [Len (4B u32 LE)][Name][Content]
    
    if plaintext.len() < 4 {
        return Err("Payload non valido (header mancante)".into());
    }

    let name_len_bytes: [u8; 4] = plaintext[..4].try_into()?;
    let name_len = u32::from_le_bytes(name_len_bytes) as usize;

    if plaintext.len() < 4 + name_len {
        return Err("Payload non valido (nome troncato)".into());
    }

    // Extract original filename
    let name_bytes = &plaintext[4..4+name_len];
    let original_name = std::str::from_utf8(name_bytes)
        .map_err(|_| "Nome file originale non è UTF-8 valido")?;

    // Extract content
    let content = &plaintext[4+name_len..];

    // Determine output path
    let parent_dir = filepath.parent().unwrap_or_else(|| Path::new("."));
    let mut original_path = parent_dir.join(original_name);

    // Check collision
    original_path = get_unique_path(original_path)?;

    // Write decrypted file
    fs::write(&original_path, content)?;
    
    // Remove encrypted file
    fs::remove_file(filepath)?;
    
    println!("✓ Ripristinato: {}", original_path.display());
    
    Ok(())
}

fn protect_key_with_password(key: &[u8; 32], password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    // Derive Key
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Errore hash password: {}", e))?;
    
    let hash_output = password_hash.hash
        .ok_or("Hash non generato")?;
    let derived_key_bytes = hash_output.as_bytes();
    
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes[..32]);
    
    let cipher = ChaCha20Poly1305::new(&derived_key.into());
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, key.as_ref())
        .map_err(|e| format!("Errore protezione chiave: {}", e))?;
    
    // Format: Salt (22) + Nonce (12) + Ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(salt.as_str().as_bytes());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

fn recover_key_from_password(protected_key: &[u8], password: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if protected_key.len() < 34 {
        return Err("Chiave protetta non valida".into());
    }
    
    let salt_str = std::str::from_utf8(&protected_key[..22])?;
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| format!("Salt non valido: {}", e))?;
    let nonce_bytes = &protected_key[22..34];
    let ciphertext = &protected_key[34..];
    
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "Password errata")?;
    
    let hash_output = password_hash.hash
        .ok_or("Hash non generato")?;
    let derived_key_bytes = hash_output.as_bytes();
    
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes[..32]);
    
    let cipher = ChaCha20Poly1305::new(&derived_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let key_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Password errata o chiave corrotta")?;
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    
    Ok(key)
}

fn read_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    if password.is_empty() {
        return Err("Password non può essere vuota".into());
    }
    
    Ok(password)
}

fn get_unique_path(path: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(path);
    }
    
    let parent = path.parent().ok_or("Path non valido")?;
    let stem = path.file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Nome file non valido")?;
    let extension = path.extension()
        .and_then(|s| s.to_str());
    
    for i in 1..10000 {
        let new_name = if let Some(ext) = extension {
            format!("{}_{}.{}", stem, i, ext)
        } else {
            format!("{}_{}", stem, i)
        };
        
        let new_path = parent.join(new_name);
        if !new_path.exists() {
            return Ok(new_path);
        }
    }
    
    Err("Troppi file duplicati (limite 10000)".into())
}