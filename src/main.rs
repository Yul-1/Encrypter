use encrypt::crypto::{self, SecureKey};
use encrypt::fsops::{self, EncryptionStats};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;

fn main() -> crypto::Result<()> {
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

fn encrypt_entry_point(path_str: &str) -> crypto::Result<()> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err("Path does not exist".into());
    }

    let mut password = read_password("Enter password to protect the key: ")?;
    let mut password_confirm = read_password("Confirm password: ")?;

    if password != password_confirm {
        return Err("Passwords do not match".into());
    }

    let master_key = SecureKey::generate();
    let protected_key = crypto::protect_key_with_password(&master_key, &password)?;

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

    let final_key_path = fsops::get_unique_path(key_path)?;
    fsops::write_key_file(&final_key_path, &protected_key)?;

    println!("Master Key saved to: {}", final_key_path.display());
    println!("IMPORTANT: Keep this key safe. You cannot recover data without it.");

    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file() {
        if let Err(e) = fsops::encrypt_file(path, &master_key) {
            eprintln!("Encryption failed: {}", e);
        }
    } else if metadata.is_dir() {
        if let Err(e) = fsops::encrypt_directory_recursive(path, &master_key, 0) {
            eprintln!("Encryption process encountered errors: {}", e);
        }
    } else {
        eprintln!("Target is neither a regular file nor a directory.");
    }

    Ok(())
}

fn decrypt_entry_point(path_str: &str, keyfile_str: &str) -> crypto::Result<()> {
    let path = Path::new(path_str);
    let key_path = Path::new(keyfile_str);

    if !path.exists() || !key_path.exists() {
        return Err("Target path or key file not found".into());
    }

    let protected_key = fs::read(key_path)?;
    let mut password = read_password("Enter password: ")?;

    let master_key = crypto::recover_key_from_password(&protected_key, &password)?;
    password.zeroize();

    println!("Password correct. Starting decryption...");

    let mut stats = EncryptionStats::new();

    let metadata = fs::symlink_metadata(path)?;

    if metadata.is_file() {
        stats.total = 1;
        match fsops::decrypt_file(path, &master_key) {
            Ok(_) => stats.success += 1,
            Err(e) => stats.errors.push(format!("File {}: {}", path.display(), e)),
        }
    } else if metadata.is_dir() {
        stats.total = fsops::count_encrypted_payloads(path);
        fsops::decrypt_directory_recursive(path, &master_key, &mut stats, 0)?;
    } else {
        return Err("Target type not supported".into());
    }

    if !stats.errors.is_empty() {
        println!("\nERRORS encountered:");
        for e in &stats.errors {
            println!(" - {}", e);
        }
        println!("\nWARNING: Key file was NOT deleted because errors occurred.");
    } else {
        println!("\nVerification: All operations successful.");
        fsops::secure_delete(key_path)?;
        println!("SUCCESS: Key file deleted securely.");
    }

    Ok(())
}

fn read_password(prompt: &str) -> crypto::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    Ok(password)
}
