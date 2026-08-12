//! Core cryptographic primitives and the on-disk container format.
//!
//! This module never touches the filesystem: it operates on `Read`/`Write`
//! streams only, so the same code path serves the privileged CLI and the
//! unprivileged web service without sharing any file-destroying logic.
//!
//! Container layout (unchanged since 0.5.6):
//!   salt(16) | [0][len u32][encrypted filename] | ([0][len u32][encrypted chunk])* | [1][encrypted sha256]

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::distributions::Alphanumeric;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors must be `Send + Sync` so the web service can move them across
/// `spawn_blocking` boundaries.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const CHUNK_SIZE: usize = 4096 * 1024;
pub const CHUNK_TYPE_DATA: u8 = 0;
pub const CHUNK_TYPE_EOF: u8 = 1;

/// Ciphertext + tag of the SHA-256 integrity footer.
const HASH_FOOTER_LEN: usize = 32 + 16;
/// Bounds the attacker-controlled allocation when parsing the metadata block.
const MAX_METADATA_LEN: usize = 4096;
const SALT_LEN: usize = 16;
const MAX_KEYFILE_SALT_LEN: usize = 128;

const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    key: [u8; 32],
}

impl SecureKey {
    pub fn new(data: [u8; 32]) -> Self {
        Self { key: data }
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { key: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Alphanumeric identifier used for ciphertext names, temp names and key names.
pub fn random_name(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn create_nonce(salt: &[u8; SALT_LEN], counter: u64) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..SALT_LEN].copy_from_slice(salt);
    nonce_bytes[SALT_LEN..].copy_from_slice(&counter.to_be_bytes());
    *XNonce::from_slice(&nonce_bytes)
}

/// Encrypts `source` into `dest`, embedding `original_filename` as the first block.
///
/// `progress` is invoked with the number of plaintext bytes consumed per chunk.
pub fn encrypt_stream<R: Read, W: Write>(
    source: &mut R,
    dest: &mut W,
    key: &SecureKey,
    original_filename: &str,
    progress: &mut dyn FnMut(u64),
) -> Result<()> {
    let mut file_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut file_salt);
    dest.write_all(&file_salt)?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut chunk_counter: u64 = 0;
    let mut hasher = Sha256::new();

    let nonce = create_nonce(&file_salt, chunk_counter);
    chunk_counter = chunk_counter
        .checked_add(1)
        .ok_or("File too large (counter overflow)")?;

    let encrypted_metadata = cipher
        .encrypt(&nonce, original_filename.as_bytes())
        .map_err(|e| format!("Encryption error (metadata): {}", e))?;

    // Refuse names the decryptor would later reject as an oversized header
    if encrypted_metadata.len() > MAX_METADATA_LEN {
        return Err("Filename too long to store in metadata".into());
    }

    dest.write_all(&[CHUNK_TYPE_DATA])?;
    dest.write_all(&(encrypted_metadata.len() as u32).to_le_bytes())?;
    dest.write_all(&encrypted_metadata)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        // Vec::zeroize clears the length, so the working area is restored each pass
        if buffer.len() < CHUNK_SIZE {
            buffer.resize(CHUNK_SIZE, 0);
        }

        let mut read_count = 0;
        while read_count < CHUNK_SIZE {
            let n = source.read(&mut buffer[read_count..])?;
            if n == 0 {
                break;
            }
            read_count += n;
        }

        if read_count == 0 {
            break;
        }

        hasher.update(&buffer[..read_count]);

        let nonce = create_nonce(&file_salt, chunk_counter);
        let ciphertext = cipher
            .encrypt(&nonce, &buffer[..read_count])
            .map_err(|e| format!("Encryption error (chunk {}): {}", chunk_counter, e))?;

        dest.write_all(&[CHUNK_TYPE_DATA])?;
        dest.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        dest.write_all(&ciphertext)?;

        buffer.zeroize();

        progress(read_count as u64);

        chunk_counter = chunk_counter
            .checked_add(1)
            .ok_or("File too large (counter overflow)")?;
    }

    let final_hash = hasher.finalize();
    let nonce = create_nonce(&file_salt, chunk_counter);
    let encrypted_hash = cipher
        .encrypt(&nonce, final_hash.as_slice())
        .map_err(|e| format!("Encryption error (hash): {}", e))?;

    dest.write_all(&[CHUNK_TYPE_EOF])?;
    dest.write_all(&encrypted_hash)?;

    Ok(())
}

/// Decryption is split in two phases so callers learn the original filename
/// before they have to choose a destination for the plaintext.
pub struct StreamDecryptor {
    cipher: XChaCha20Poly1305,
    salt: [u8; SALT_LEN],
    chunk_counter: u64,
    hasher: Sha256,
}

impl StreamDecryptor {
    /// Reads the salt and the encrypted metadata block, returning the original filename.
    pub fn open<R: Read>(source: &mut R, key: &SecureKey) -> Result<(Self, String)> {
        let mut file_salt = [0u8; SALT_LEN];
        source
            .read_exact(&mut file_salt)
            .map_err(|_| "File too small")?;

        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let mut chunk_counter: u64 = 0;

        let mut type_buf = [0u8; 1];
        source.read_exact(&mut type_buf)?;
        if type_buf[0] != CHUNK_TYPE_DATA {
            return Err("Invalid file structure: Expected metadata block".into());
        }

        let mut len_buf = [0u8; 4];
        source.read_exact(&mut len_buf)?;
        let meta_len = u32::from_le_bytes(len_buf) as usize;

        if meta_len > MAX_METADATA_LEN {
            return Err("Metadata header too large".into());
        }

        let mut meta_ciphertext = vec![0u8; meta_len];
        source.read_exact(&mut meta_ciphertext)?;

        let nonce = create_nonce(&file_salt, chunk_counter);
        chunk_counter = chunk_counter.checked_add(1).ok_or("Counter overflow")?;

        let filename_bytes = cipher
            .decrypt(&nonce, meta_ciphertext.as_ref())
            .map_err(|_| "Decryption failed (Metadata): Wrong key or corrupt header")?;

        let original_name =
            String::from_utf8(filename_bytes).map_err(|_| "Invalid UTF-8 in filename")?;

        Ok((
            Self {
                cipher,
                salt: file_salt,
                chunk_counter,
                hasher: Sha256::new(),
            },
            original_name,
        ))
    }

    /// Streams the payload into `dest` and verifies the integrity footer.
    ///
    /// Plaintext is written before verification completes, so on error the
    /// caller must discard whatever it wrote.
    pub fn decrypt_body<R: Read, W: Write>(
        mut self,
        source: &mut R,
        dest: &mut W,
        progress: &mut dyn FnMut(u64),
    ) -> Result<()> {
        let mut type_buf = [0u8; 1];
        let mut len_buf = [0u8; 4];
        let mut ciphertext_buffer = Vec::with_capacity(CHUNK_SIZE + 1024);
        let mut integrity_verified = false;

        loop {
            let bytes_read = source.read(&mut type_buf)?;
            if bytes_read == 0 {
                break;
            }

            if type_buf[0] == CHUNK_TYPE_EOF {
                let nonce = create_nonce(&self.salt, self.chunk_counter);

                let mut hash_ciphertext = vec![0u8; HASH_FOOTER_LEN];
                source.read_exact(&mut hash_ciphertext)?;

                let stored_hash = self
                    .cipher
                    .decrypt(&nonce, hash_ciphertext.as_ref())
                    .map_err(|_| "Integrity Check Failed: Footer corrupted")?;

                let calculated_hash = self.hasher.finalize();

                if stored_hash.as_slice() != calculated_hash.as_slice() {
                    return Err(
                        "CRITICAL: Integrity Mismatch. File content has been modified or truncated."
                            .into(),
                    );
                }

                integrity_verified = true;
                break;
            } else if type_buf[0] == CHUNK_TYPE_DATA {
                source.read_exact(&mut len_buf)?;
                let chunk_len = u32::from_le_bytes(len_buf) as usize;

                if chunk_len > CHUNK_SIZE + 1024 {
                    return Err("Invalid chunk size".into());
                }

                if ciphertext_buffer.len() < chunk_len {
                    ciphertext_buffer.resize(chunk_len, 0);
                }

                source.read_exact(&mut ciphertext_buffer[..chunk_len])?;

                let nonce = create_nonce(&self.salt, self.chunk_counter);

                let mut plaintext = self
                    .cipher
                    .decrypt(&nonce, &ciphertext_buffer[..chunk_len])
                    .map_err(|_| format!("Decryption failed at chunk {}", self.chunk_counter))?;

                self.hasher.update(&plaintext);
                dest.write_all(&plaintext)?;
                progress(plaintext.len() as u64);

                plaintext.zeroize();

                self.chunk_counter = self.chunk_counter.checked_add(1).ok_or("Counter overflow")?;
            } else {
                return Err("Unknown chunk type found".into());
            }
        }

        if !integrity_verified {
            return Err("CRITICAL: Truncated file. Integrity footer missing.".into());
        }

        Ok(())
    }
}

pub fn simple_encrypt_data(data: &[u8], key: &SecureKey) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn simple_decrypt_data(data: &[u8], key: &SecureKey) -> Result<Vec<u8>> {
    if data.len() < 24 {
        return Err("Data too short".into());
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed".into())
}

fn argon2_params() -> Result<Params> {
    Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|e| format!("Argon2 params error: {}", e).into())
}

/// Derives a key from `password` with Argon2id and returns `salt_len | salt | encrypted master key`.
pub fn protect_key_with_password(key: &SecureKey, password: &str) -> Result<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params()?);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Hash error: {}", e))?;

    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    let secure_derived = SecureKey::new(derived_key);

    let protected = simple_encrypt_data(key.as_bytes(), &secure_derived)?;

    derived_key.zeroize();

    let salt_str = salt.as_str();
    let salt_len = salt_str.len() as u32;

    let mut result = Vec::new();
    result.extend_from_slice(&salt_len.to_le_bytes());
    result.extend_from_slice(salt_str.as_bytes());
    result.extend_from_slice(&protected);

    Ok(result)
}

pub fn recover_key_from_password(protected_key: &[u8], password: &str) -> Result<SecureKey> {
    if protected_key.len() < 4 {
        return Err("Invalid key file format".into());
    }

    let (len_bytes, rest) = protected_key.split_at(4);
    let salt_len = u32::from_le_bytes(len_bytes.try_into()?) as usize;
    if salt_len == 0 || salt_len > MAX_KEYFILE_SALT_LEN {
        return Err("Invalid salt length".into());
    }

    if rest.len() < salt_len {
        return Err("Key file truncated".into());
    }
    let (salt_bytes, encrypted_master_key) = rest.split_at(salt_len);

    let salt_str = std::str::from_utf8(salt_bytes)?;
    let salt = SaltString::from_b64(salt_str).map_err(|e| format!("Invalid salt: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params()?);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "Wrong password")?;

    let derived_key_bytes = password_hash.hash.ok_or("Hash failed")?;
    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&derived_key_bytes.as_bytes()[..32]);
    let secure_derived = SecureKey::new(derived_key);

    let decrypted_bytes = simple_decrypt_data(encrypted_master_key, &secure_derived)
        .map_err(|_| "Wrong password or corrupted key")?;

    derived_key.zeroize();

    if decrypted_bytes.len() != 32 {
        return Err("Invalid key length".into());
    }

    let mut master_key_arr = [0u8; 32];
    master_key_arr.copy_from_slice(&decrypted_bytes);

    let mut decrypted_bytes_owned = decrypted_bytes;
    decrypted_bytes_owned.zeroize();

    Ok(SecureKey::new(master_key_arr))
}
