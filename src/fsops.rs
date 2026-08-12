//! Filesystem-facing operations for the CLI.
//!
//! Everything that creates, renames or destroys files on disk lives here and is
//! compiled only into the `encrypt` binary. The web service is built without
//! this module, so no network-reachable code path can reach `secure_delete`.

use crate::crypto::{self, Result, SecureKey, StreamDecryptor};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const PROGRESS_THRESHOLD: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 50;
const DIR_MARKER: &str = ".dirname.enc";
/// Bounds the retry loop when a random ciphertext name already exists
const MAX_NAME_ATTEMPTS: usize = 64;

pub struct EncryptionStats {
    pub total: usize,
    pub success: usize,
    pub errors: Vec<String>,
}

impl EncryptionStats {
    pub fn new() -> Self {
        Self {
            total: 0,
            success: 0,
            errors: Vec::new(),
        }
    }
}

impl Default for EncryptionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts the real `.enc` payloads in a tree, ignoring directory name markers.
pub fn count_encrypted_payloads(path: &Path) -> usize {
    WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
                && entry.file_name() != DIR_MARKER
        })
        .count()
}

pub fn write_key_file(path: &Path, protected_key: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut key_file = options.open(path)?;
    key_file.write_all(protected_key)?;
    key_file.sync_all()?;
    Ok(())
}

fn progress_bar(file_size: u64) -> Result<Option<ProgressBar>> {
    if file_size <= PROGRESS_THRESHOLD {
        return Ok(None);
    }
    let p = ProgressBar::new(file_size);
    p.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"),
    );
    Ok(Some(p))
}

fn reserve_ciphertext_path(parent_dir: &Path) -> Result<PathBuf> {
    for _ in 0..MAX_NAME_ATTEMPTS {
        let candidate = parent_dir.join(format!("{}.enc", crypto::random_name(16)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("Unable to allocate a unique ciphertext name".into())
}

pub fn encrypt_file(filepath: &Path, key: &SecureKey) -> Result<()> {
    let metadata = fs::symlink_metadata(filepath)?;
    if metadata.file_type().is_symlink() {
        println!("Skipping symlink: {}", filepath.display());
        return Ok(());
    }
    let file_size = metadata.len();

    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let final_path = reserve_ciphertext_path(parent_dir)?;

    println!("Encrypting: {}", filepath.display());

    let original_filename = filepath
        .file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();

    let mut source_file = File::open(filepath)?;
    let mut dest_file = File::create(&final_path)?;

    let pb = progress_bar(file_size)?;

    let outcome = {
        let mut on_progress = |n: u64| {
            if let Some(ref p) = pb {
                p.inc(n);
            }
        };
        crypto::encrypt_stream(
            &mut source_file,
            &mut dest_file,
            key,
            &original_filename,
            &mut on_progress,
        )
    };

    if let Some(p) = pb {
        p.finish_and_clear();
    }

    // A partial ciphertext would later fail integrity checks and block key removal
    if let Err(e) = outcome {
        drop(dest_file);
        let _ = fs::remove_file(&final_path);
        return Err(e);
    }

    dest_file.sync_all()?;
    drop(dest_file);

    drop(source_file);
    secure_delete(filepath)?;

    println!("Done: File encrypted and integrity secured.");
    Ok(())
}

pub fn decrypt_file(filepath: &Path, key: &SecureKey) -> Result<()> {
    println!("Processing: {}", filepath.display());

    let mut source_file = File::open(filepath)?;

    let (decryptor, original_name_string) = StreamDecryptor::open(&mut source_file, key)?;

    // Only the basename from the metadata is honoured: a crafted container
    // must not be able to steer the output anywhere else
    let original_name = Path::new(&original_name_string)
        .file_name()
        .ok_or("Invalid filename in metadata")?;

    let parent_dir = filepath.parent().unwrap_or(Path::new("."));
    let final_path = get_unique_path(parent_dir.join(original_name))?;

    let temp_path = parent_dir.join(format!(".{}.tmp", crypto::random_name(16)));
    let mut dest_file = File::create(&temp_path)?;

    let outcome = decryptor.decrypt_body(&mut source_file, &mut dest_file, &mut |_| {});

    if let Err(e) = outcome {
        drop(dest_file);
        secure_delete(&temp_path)?;
        return Err(e);
    }

    dest_file.sync_all()?;
    drop(dest_file);

    if let Err(e) = fs::rename(&temp_path, &final_path) {
        secure_delete(&temp_path)?;
        return Err(format!("Failed to rename temp file to final destination: {}", e).into());
    }

    drop(source_file);
    secure_delete(filepath)?;

    println!(
        "Restored and Verified: {}",
        final_path.file_name().unwrap_or_default().to_string_lossy()
    );

    Ok(())
}

pub fn encrypt_directory_recursive(path: &Path, key: &SecureKey, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(format!("Directory depth limit exceeded at {}", path.display()).into());
    }

    let entries: Vec<PathBuf> = fs::read_dir(path)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();

    for entry in entries {
        let symlink_meta = fs::symlink_metadata(&entry)?;

        if symlink_meta.file_type().is_symlink() {
            println!("Skipping symlink: {}", entry.display());
            continue;
        }

        if symlink_meta.is_dir() {
            encrypt_directory_recursive(&entry, key, depth + 1)?;
        } else if symlink_meta.is_file() {
            encrypt_file(&entry, key)?;
        }
    }

    let original_name = path
        .file_name()
        .ok_or("Invalid directory name")?
        .to_string_lossy()
        .to_string();

    let name_ciphertext = crypto::simple_encrypt_data(original_name.as_bytes(), key)?;

    let marker_path = path.join(DIR_MARKER);
    fs::write(&marker_path, name_ciphertext)?;

    let parent = path.parent().unwrap_or(Path::new("."));
    let new_path = parent.join(crypto::random_name(16));

    fs::rename(path, &new_path)?;
    println!(
        "Encrypted Dir: {} -> {}",
        original_name,
        new_path.file_name().unwrap_or_default().to_string_lossy()
    );

    Ok(())
}

pub fn decrypt_directory_recursive(
    path: &Path,
    key: &SecureKey,
    stats: &mut EncryptionStats,
    depth: usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        stats
            .errors
            .push(format!("Recursion limit reached at {}", path.display()));
        return Ok(());
    }

    let marker_path = path.join(DIR_MARKER);

    let current_path = if marker_path.exists() {
        let encrypted_name = fs::read(&marker_path)?;

        match crypto::simple_decrypt_data(&encrypted_name, key) {
            Ok(name_bytes) => {
                let original_name =
                    String::from_utf8(name_bytes).map_err(|_| "Invalid UTF-8 in directory name")?;

                let parent = path.parent().unwrap_or(Path::new("."));
                let safe_dir_name = Path::new(&original_name)
                    .file_name()
                    .ok_or("Invalid directory name in metadata")?;

                let new_path = get_unique_path(parent.join(safe_dir_name))?;

                fs::rename(path, &new_path)?;

                let marker_in_new_path = new_path.join(DIR_MARKER);
                if marker_in_new_path.exists() {
                    if let Err(e) = secure_delete(&marker_in_new_path) {
                        eprintln!(
                            "Warning: Failed to securely delete marker {}: {}",
                            marker_in_new_path.display(),
                            e
                        );
                    }
                }

                println!("Restored Dir: {}", new_path.display());
                new_path
            }
            Err(e) => {
                stats.errors.push(format!(
                    "Failed to decrypt directory {}: {}",
                    path.display(),
                    e
                ));
                path.to_path_buf()
            }
        }
    } else {
        path.to_path_buf()
    };

    let entries: Vec<PathBuf> = match fs::read_dir(&current_path) {
        Ok(iter) => iter.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(e) => {
            stats
                .errors
                .push(format!("Cannot read dir {}: {}", current_path.display(), e));
            return Ok(());
        }
    };

    for entry in entries {
        let symlink_meta = match fs::symlink_metadata(&entry) {
            Ok(m) => m,
            Err(e) => {
                stats
                    .errors
                    .push(format!("Cannot read metadata {}: {}", entry.display(), e));
                continue;
            }
        };

        if symlink_meta.file_type().is_symlink() {
            println!("Skipping symlink: {}", entry.display());
            continue;
        }

        if symlink_meta.is_dir() {
            decrypt_directory_recursive(&entry, key, stats, depth + 1)?;
        } else if symlink_meta.is_file() {
            if entry.file_name().and_then(|s| s.to_str()) == Some(DIR_MARKER) {
                continue; // directory name marker, not a data payload
            }
            if entry.extension().and_then(|s| s.to_str()) == Some("enc") {
                match decrypt_file(&entry, key) {
                    Ok(_) => stats.success += 1,
                    Err(e) => stats
                        .errors
                        .push(format!("File {}: {}", entry.display(), e)),
                }
            }
        }
    }

    Ok(())
}

pub fn get_unique_path(path: PathBuf) -> Result<PathBuf> {
    if !path.exists() {
        return Ok(path);
    }

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
        if !new_path.exists() {
            return Ok(new_path);
        }
    }
    Err("Too many duplicates".into())
}

/// Overwrites the file with random data before unlinking it.
///
/// Symlinks are unlinked directly: following them would scribble over the target.
pub fn secure_delete(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;

    if metadata.file_type().is_symlink() {
        fs::remove_file(path)?;
        return Ok(());
    }

    let len = metadata.len();

    {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut rng = OsRng;
        let buffer_size = 4096 * 1024;
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
