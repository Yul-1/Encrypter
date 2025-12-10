# Encrypt

## Overview
Rust CLI utility to encrypt or decrypt files and directories with XChaCha20-Poly1305 authenticated encryption. A per-user master key is generated, protected with a password via Argon2id, and stored in a `.key` file. File contents, file names, and directory names are encrypted; integrity is verified on decrypt; original plaintext is securely overwritten and removed.

## Features
- XChaCha20-Poly1305 streaming encryption with per-file 16-byte salt and per-chunk nonces.
- Argon2id key derivation (memory-hard) to protect the master key; key material zeroized in memory.
- File integrity verification (SHA-256 over plaintext) checked before restoring output.
- File and directory name encryption; directories are temporarily renamed to random identifiers with `.dirname.enc` markers to recover originals.
- Secure delete: plaintext files are overwritten with cryptographically random data before removal; symlinks are removed without overwrite.
- Progress bar for large files; recursion limited to depth 50 to avoid runaway traversals.
- Unique-path handling to avoid collisions on decrypt.

## Build
```bash
cargo build --release
```
The compiled binary will be at `target/release/encrypt` (or `encrypt.exe` on Windows).

## Usage
Generate a password-protected key and encrypt:
```bash
./encrypt encrypt <path>
```
- `<path>` can be a file or directory.
- A 32-byte master key is generated and saved as `<path>.key` (or alongside the directory with the same stem). Existing names are deduplicated automatically.
- You will be prompted twice for the password protecting the key file.

Decrypt:
```bash
./encrypt decrypt <path> <keyfile>
```
- `<path>` is the encrypted file or directory to restore.
- `<keyfile>` is the `.key` produced during encryption.
- On full success the key file is securely deleted; on errors it is preserved.

Notes:
- Only files with `.enc` extension are treated as encrypted payloads during directory decrypt; `.dirname.enc` markers are skipped automatically.
- Recursion stops at depth 50; overly deep trees are reported as errors.
- Ensure the `.key` file is stored separately from encrypted data; loss of the password or key makes recovery impossible.

## How It Works
- A random 32-byte master key is generated per encryption run.
- The master key is encrypted with Argon2id-derived key (Params: memory 65,536 KB, iterations 4, parallelism 4) and stored in the `.key` file (salt + encrypted master key).
- For each file:
  - A random salt seeds nonces; the original filename is encrypted as the first chunk.
  - File data is processed in 4 MiB chunks; each chunk uses a unique nonce (salt + counter).
  - A SHA-256 hash over plaintext is encrypted and written as the footer for integrity.
  - After successful write, the plaintext file is securely overwritten and deleted.
- For directories:
  - Contents are encrypted recursively; directory names are encrypted into `.dirname.enc` markers and the on-disk directory is renamed to a random 16-character identifier.
  - On decrypt, the marker restores the original name (with collision avoidance) and markers are securely removed.

## Security Notes
- Memory zeroization is applied to secrets (`Zeroize`/`ZeroizeOnDrop`).
- Key files are created with restrictive permissions on Unix (0600).
- Symlinks are skipped during traversal and are not overwritten during secure delete; they are removed directly.
- Integrity is verified before restoring plaintext; failures leave temp files wiped.
- Path traversal protections and symlink handling were reinforced in 0.5.4.

## Version History
- 0.5.6: Switched to 16-byte salts with 64-bit chunk counters, skipped symlinks during traversal, and hardened key parsing/zeroization.
- 0.5.5: Skips `.dirname.enc` during decrypt; stats count only real `.enc` payloads.
- 0.5.4: Hardened traversal and symlink handling to keep operations confined to the target tree.
- 0.5.3: Fixed critical truncation risk in chunked encryption/decryption read/write loops.
- 0.5.2: Added overwrite-based secure delete, Unix 0600 for key files, clearer errors, and safer collision handling.
- 0.5.1: Added SHA-256 integrity footer verification and systematic memory zeroization of secrets.
- 0.5.0: Switched to streaming 4 MiB chunking with XChaCha20-Poly1305 and persistent master key handling for large files.
- 0.4.2: Encrypted directory names via `.dirname.enc`; directories renamed to random identifiers during encryption and restored on decrypt.
- 0.4.1: Moved `.key` storage outside encrypted directories to avoid trapping the key inside bulk operations.
- 0.4.0: Encrypted original filenames (stored as metadata) and renamed ciphertexts to random 16-char `.enc`; improved collision avoidance and reporting.
- 0.3.0: First public ChaCha20-Poly1305 release with Argon2-protected master key, directory recursion, progress bar, and paired unique paths for encrypted/key outputs.
- 0.2.0 (legacy): Migration to ChaCha20-Poly1305; added Argon2 password protection, directory traversal, and progress for files >1 MB; stored `master.key` inside the target and used `.encrypted` suffix; full in-memory processing without name encryption or integrity checks.
- 0.1.0 (legacy): AES-256-GCM single-file flow; raw 32-byte key saved in `.key` without password; full in-memory encrypt/decrypt; no integrity, no directory support.

## Data Handling Caveats
- Losing either the password or the `.key` file makes decryption impossible by design.
- Do not reuse `.key` files across unrelated encryption runs; each run generates a fresh master key.
- Keep sufficient disk space for temporary files during decrypt; outputs are written to temp names before final rename.
