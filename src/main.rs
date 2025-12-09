use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::RngCore;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const PROGRESS_THRESHOLD: u64 = 1024 * 1024; // 1MB - mostra progress per file > 1MB

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
    
    // Chiedi password
    let password = read_password("Inserisci password per proteggere la chiave: ")?;
    let password_confirm = read_password("Conferma password: ")?;
    
    if password != password_confirm {
        return Err("Le password non corrispondono".into());
    }

    // Genera chiave master
    let mut master_key = [0u8; 32];
    OsRng.fill_bytes(&mut master_key);

    // Cripta la chiave master con la password
    let protected_key = protect_key_with_password(&master_key, &password)?;
    
    if path.is_file() {
        // Trova suffisso libero per entrambi i file
        let base_encrypted = path.with_extension(
            format!("{}.encrypted", 
                    path.extension().and_then(|s| s.to_str()).unwrap_or("")
            )
        );
        let base_key = path.with_extension("key");
        
        let (encrypted_path, key_path) = find_paired_unique_paths(base_encrypted, base_key)?;
        
        // Cripta file
        encrypt_file_to_path(path, &master_key, &encrypted_path)?;
        
        // Salva chiave protetta
        fs::write(&key_path, &protected_key)?;
        println!("✓ Chiave salvata: {}", key_path.display());
    } else if path.is_dir() {
        let files: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        println!("Trovati {} file da criptare", files.len());
        
        for file in &files {
            encrypt_file(file, &master_key)?;
        }

        // Salva chiave protetta nella cartella con path unico
        let key_path = get_unique_path(path.join("master.key"))?;
        fs::write(&key_path, &protected_key)?;
        println!("✓ Chiave master salvata: {}", key_path.display());
    } else {
        return Err("Percorso non valido".into());
    }

    println!("\n⚠️  IMPORTANTE: Conserva la chiave e ricorda la password!");
    Ok(())
}

fn decrypt_path(path: &str, keyfile: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    
    // Leggi chiave protetta
    let protected_key = fs::read(keyfile)?;
    
    // Chiedi password
    let password = read_password("Inserisci password: ")?;
    
    // Recupera chiave master
    let master_key = recover_key_from_password(&protected_key, &password)?;

    if path.is_file() {
        decrypt_file(path, &master_key)?;
    } else if path.is_dir() {
        let files: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file() && 
                       e.path().extension().and_then(|s| s.to_str()) == Some("encrypted"))
            .map(|e| e.path().to_path_buf())
            .collect();

        println!("Trovati {} file da decriptare", files.len());
        
        for file in &files {
            decrypt_file(file, &master_key)?;
        }
    } else {
        return Err("Percorso non valido".into());
    }

    Ok(())
}

fn encrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    // Trova path unico per il file criptato
    let encrypted_path = get_unique_path(
        filepath.with_extension(
            format!("{}.encrypted", 
                    filepath.extension().and_then(|s| s.to_str()).unwrap_or("")
            )
        )
    )?;
    
    encrypt_file_to_path(filepath, key, &encrypted_path)
}

fn encrypt_file_to_path(filepath: &Path, key: &[u8; 32], encrypted_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(filepath)?;
    let file_size = metadata.len();
    
    println!("Criptando: {}", filepath.display());
    
    let progress = if file_size > PROGRESS_THRESHOLD {
        let pb = ProgressBar::new(file_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"));
        Some(pb)
    } else {
        None
    };

    // Leggi file
    let mut file = File::open(filepath)?;
    let mut buffer = Vec::new();
    
    if let Some(pb) = &progress {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file.read(&mut chunk)?;
            if n == 0 { break; }
            buffer.extend_from_slice(&chunk[..n]);
            pb.inc(n as u64);
        }
        pb.finish_and_clear();
    } else {
        file.read_to_end(&mut buffer)?;
    }

    // Setup cipher
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Genera nonce unico
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Cripta
    let ciphertext = cipher
        .encrypt(nonce, buffer.as_ref())
        .map_err(|e| format!("Errore di crittografia: {}", e))?;

    // Combina nonce + ciphertext
    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    
    fs::write(encrypted_path, encrypted_data)?;
    
    // Rimuovi file originale
    fs::remove_file(filepath)?;
    
    println!("✓ Criptato: {} → {}", filepath.display(), encrypted_path.display());
    
    Ok(())
}

fn decrypt_file(filepath: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(filepath)?;
    let file_size = metadata.len();
    
    println!("Decriptando: {}", filepath.display());
    
    let progress = if file_size > PROGRESS_THRESHOLD {
        let pb = ProgressBar::new(file_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"));
        Some(pb)
    } else {
        None
    };

    // Leggi file criptato
    let encrypted_data = fs::read(filepath)?;
    
    if let Some(pb) = &progress {
        pb.inc(file_size);
        pb.finish_and_clear();
    }
    
    if encrypted_data.len() < 12 {
        return Err("File criptato corrotto o troppo piccolo".into());
    }

    // Setup cipher
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Estrai nonce e ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decripta
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decrittografia fallita: password errata o file corrotto")?;

    // Determina nome file originale (rimuovi .encrypted)
    let mut original_path = if let Some(stem) = filepath.file_stem() {
        let stem_str = stem.to_string_lossy();
        if let Some(pos) = stem_str.rfind('.') {
            filepath.with_file_name(format!("{}.{}", 
                &stem_str[..pos],
                &stem_str[pos+1..]
            ))
        } else {
            filepath.with_file_name(stem)
        }
    } else {
        return Err("Nome file non valido".into());
    };

    // Genera path unico se esiste già
    original_path = get_unique_path(original_path)?;

    // Salva file decriptato
    fs::write(&original_path, plaintext)?;
    
    // Rimuovi file criptato
    fs::remove_file(filepath)?;
    
    println!("✓ Decriptato: {} → {}", filepath.display(), original_path.display());
    
    Ok(())
}

fn protect_key_with_password(key: &[u8; 32], password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    // Deriva chiave da password usando Argon2id
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Errore hash password: {}", e))?;
    
    let hash_output = password_hash.hash
        .ok_or("Hash non generato")?;
    let derived_key_bytes = hash_output.as_bytes();
    
    // Usa i primi 32 byte come chiave per ChaCha20
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes[..32]);
    
    let cipher = ChaCha20Poly1305::new(&derived_key.into());
    
    // Genera nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Cripta la chiave master
    let ciphertext = cipher
        .encrypt(nonce, key.as_ref())
        .map_err(|e| format!("Errore protezione chiave: {}", e))?;
    
    // Formato: salt (22 bytes) + nonce (12 bytes) + ciphertext
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
    
    // Estrai componenti
    let salt_str = std::str::from_utf8(&protected_key[..22])?;
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| format!("Salt non valido: {}", e))?;
    let nonce_bytes = &protected_key[22..34];
    let ciphertext = &protected_key[34..];
    
    let argon2 = Argon2::default();
    
    // Deriva chiave da password
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
    
    // Decripta la chiave master
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
    
    // Cerca un numero incrementale libero
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

fn find_paired_unique_paths(encrypted_base: PathBuf, key_base: PathBuf) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    // Se nessuno esiste, usa i path base
    if !encrypted_base.exists() && !key_base.exists() {
        return Ok((encrypted_base, key_base));
    }
    
    let enc_parent = encrypted_base.parent().ok_or("Path non valido")?;
    let enc_stem = encrypted_base.file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Nome file non valido")?;
    let enc_ext = encrypted_base.extension()
        .and_then(|s| s.to_str());
    
    let key_parent = key_base.parent().ok_or("Path non valido")?;
    let key_stem = key_base.file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Nome file non valido")?;
    let key_ext = key_base.extension()
        .and_then(|s| s.to_str());
    
    // Cerca una coppia di numeri liberi
    for i in 1..10000 {
        let enc_name = if let Some(ext) = enc_ext {
            format!("{}_{}.{}", enc_stem, i, ext)
        } else {
            format!("{}_{}", enc_stem, i)
        };
        
        let key_name = if let Some(ext) = key_ext {
            format!("{}_{}.{}", key_stem, i, ext)
        } else {
            format!("{}_{}", key_stem, i)
        };
        
        let enc_path = enc_parent.join(&enc_name);
        let key_path = key_parent.join(&key_name);
        
        // Entrambi devono essere liberi
        if !enc_path.exists() && !key_path.exists() {
            return Ok((enc_path, key_path));
        }
    }
    
    Err("Troppi file duplicati (limite 10000)".into())
}