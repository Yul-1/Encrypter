# Encrypt

## Overview
Rust utility to encrypt or decrypt files and directories with XChaCha20-Poly1305 authenticated encryption. A per-run master key is generated, protected with a password via Argon2id, and stored in a `.key` file. File contents, file names, and directory names are encrypted; integrity is verified on decrypt; original plaintext is securely overwritten and removed by the CLI (the web interface never touches your files).

Two binaries are produced from one codebase:

| Binary | Feature | Purpose |
| --- | --- | --- |
| `encrypt` | `cli` | Interactive tool. Encrypts and decrypts files and directories in place, and securely deletes the originals. Typically run with elevated privileges. |
| `encrypt-web` | `web` | Minimal drag & drop HTTP service. Encrypts an uploaded copy in memory and returns the ciphertext plus its key file. Never decrypts, never writes to disk. |

The two feature sets are mutually exclusive at build time: the CLI binary contains no HTTP stack, and the web binary is not linked against the filesystem module (`src/fsops.rs`) that performs secure deletion and directory recursion.

Only the web service is containerized. The CLI is a plain standalone binary — it is the privileged, filesystem-facing tool, and wrapping it in a container would add volume mounts, uid mapping and TTY friction without buying any safety.

## Features
- XChaCha20-Poly1305 streaming encryption with per-file 16-byte salt and per-chunk nonces.
- Argon2id key derivation (memory-hard) to protect the master key; key material zeroized in memory.
- File integrity verification (SHA-256 over plaintext) checked before restoring output.
- File and directory name encryption; directories are temporarily renamed to random identifiers with `.dirname.enc` markers to recover originals.
- Secure delete: plaintext files are overwritten with cryptographically random data before removal; symlinks are removed without overwrite.
- Progress bar for large files; recursion limited to depth 50 to avoid runaway traversals.
- Unique-path handling to avoid collisions on decrypt.
- Browser front end with drag & drop upload, real upload progress, and paired `.enc` / `.key` downloads.

## Build

### CLI
```bash
cargo build --release        # -> target/release/encrypt (encrypt.exe on Windows)
```
Without a local Rust toolchain, `./scripts/build-cli.sh` borrows a throwaway `rust` container as a compiler and emits `dist/encrypt`, a statically linked musl binary that runs on any Linux and needs nothing installed — Docker included:
```bash
./scripts/build-cli.sh
./dist/encrypt encrypt ./secret.pdf
```

### Web service
```bash
docker build --target web -t encrypt-web:0.6.0 .
# or, natively:
cargo build --release --no-default-features --features web
```

## Usage (CLI)
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
- The password prompt reads from `/dev/tty`, so the CLI needs a terminal. To script it, allocate a pty (`script -qec "encrypt encrypt ./file" /dev/null`).
- Only files with `.enc` extension are treated as encrypted payloads during directory decrypt; `.dirname.enc` markers are skipped automatically.
- Recursion stops at depth 50; overly deep trees are reported as errors.
- Ensure the `.key` file is stored separately from encrypted data; loss of the password or key makes recovery impossible.

## Web interface
```bash
docker compose up -d --build
# http://127.0.0.1:8085
```
Drop a file on the page (or click to pick one), type a password twice, and the browser downloads two files: the ciphertext `<random>.enc` and its key `<random>.key`, sharing the same stem. There is no decrypt endpoint by design, so restore them with the CLI:
```bash
./dist/encrypt decrypt <random>.enc <random>.key
```

The uploaded file is a copy made by the browser, so **the original on your disk is never modified or deleted** — unlike the CLI, which overwrites and removes the plaintext by design.

### Configuration
| Variable | Default | Meaning |
| --- | --- | --- |
| `ENCRYPT_WEB_BIND` | `127.0.0.1:8080` | Listen address. The compose file sets `0.0.0.0:8080` inside the container and publishes it only on the host loopback, port 8085. |
| `ENCRYPT_WEB_MAX_UPLOAD_MB` | `64` | Upload ceiling, clamped to 512. Larger uploads get HTTP 413. |
| `ENCRYPT_WEB_CONCURRENCY` | `2` | Simultaneous encryption workers, clamped to 16. |
| `ENCRYPT_WEB_TOKEN` | unset | When set, every POST must carry a matching `X-Encrypt-Token` header (constant-time comparison). The bundled page does not send it, so this is meant for deployments behind a proxy that injects the header. |
| `ENCRYPT_WEB_ALLOW_ROOT` | unset | Set to `1` to bypass the refusal to run as uid 0. |

`GET /api/config` exposes `max_upload_bytes` and `min_password_length` so the page can reject an oversized file before starting the upload: the server-side limit fires mid-stream, and browsers report that as a bare network error rather than the 413.

Peak memory is bounded by `ENCRYPT_WEB_CONCURRENCY x ENCRYPT_WEB_MAX_UPLOAD_MB x 2` plus 64 MiB of Argon2id state per worker: a worker slot is taken *before* the request body is buffered, so extra clients queue instead of accumulating in memory. Measured peak with the defaults and four parallel 60 MiB uploads: 81 MiB against the 512 MiB compose limit.

### Troubleshooting
Every request is logged as one line on stderr — method, path, status, request size, duration — with no filenames and no passwords:
```bash
docker compose logs -f encrypt-web
# POST /api/encrypt -> 200 in=3145992B 214ms
```
If the browser reports a dropped connection and no matching line appears in the log, the request never reached the service: check that the container is up (`docker compose ps`) and that the page is loaded from the same host and port it posts to.

## How It Works
- A random 32-byte master key is generated per encryption run.
- The master key is encrypted with an Argon2id-derived key (Params: memory 65,536 KB, iterations 4, parallelism 4) and stored in the `.key` file (salt + encrypted master key).
- For each file:
  - A random salt seeds nonces; the original filename is encrypted as the first chunk.
  - File data is processed in 4 MiB chunks; each chunk uses a unique nonce (salt + counter).
  - A SHA-256 hash over plaintext is encrypted and written as the footer for integrity.
  - After successful write, the plaintext file is securely overwritten and deleted (CLI only).
- For directories:
  - Contents are encrypted recursively; directory names are encrypted into `.dirname.enc` markers and the on-disk directory is renamed to a random 16-character identifier.
  - On decrypt, the marker restores the original name (with collision avoidance) and markers are securely removed.
- In the web service the same container format is produced entirely in memory; the key file is returned base64-encoded in the `X-Encrypt-Key` response header and rebuilt as a download by the page.

## Security Notes
- Memory zeroization is applied to secrets (`Zeroize`/`ZeroizeOnDrop`).
- Key files are created with restrictive permissions on Unix (0600).
- Symlinks are skipped during traversal and are not overwritten during secure delete; they are removed directly.
- Integrity is verified before restoring plaintext; failures leave temp files wiped.
- Path traversal protections and symlink handling were reinforced in 0.5.4.

### Web service threat model
The CLI is designed to run privileged and to destroy plaintext. The HTTP service is the opposite, and the separation is enforced by the build:

- **Encryption only.** There is no decrypt endpoint, so the server never parses attacker-supplied ciphertext or key files.
- **No filesystem access.** Nothing is written to disk; the container runs with a read-only root filesystem, all capabilities dropped, and `no-new-privileges`.
- **No secure-delete code.** `src/fsops.rs` is behind the `cli` feature and is absent from the web binary.
- **Refuses to run as root** unless `ENCRYPT_WEB_ALLOW_ROOT=1` is set explicitly.
- **Same-origin only.** Cross-origin and cross-site POSTs are rejected with 403 (`Origin` / `Sec-Fetch-Site` checks), so another page cannot drive the endpoint.
- **Bounded work.** Upload size limit, worker semaphore, queue wait and upload timeouts bound CPU and memory.
- **Strict CSP.** `default-src 'none'`, no inline script or style, no external assets, no CDN.
- **Minimal logging.** Filenames and passwords are never logged.

Residual risks you must accept or mitigate yourself:
- Plaintext transits the server process memory. Run it on a machine you trust.
- There is **no authentication and no TLS by default**. Do not expose it beyond loopback without a reverse proxy providing TLS and authentication; set `ENCRYPT_WEB_TOKEN` if it must leave loopback.
- The password travels in the request body. Over plain HTTP that is only acceptable on loopback.

## Testing
```bash
./scripts/build-cli.sh
./scripts/test-cli.sh                     # roundtrips, tree handling, failure modes
docker compose up -d --build
./scripts/test-web.sh                     # HTTP contract, hardening, decrypt roundtrip
```
`test-web.sh` closes the loop with the standalone CLI binary: it uploads through HTTP and decrypts the result with `dist/encrypt`, which is exactly what a user does.
`scripts/test-cli.sh` also verifies on-disk format compatibility against an older build when given one:
```bash
ENCRYPT_REF_BIN=/path/to/0.5.6/encrypt ./scripts/test-cli.sh
```
`MANUAL-TESTS.md` covers what the automated suites cannot reach: the browser drag & drop flow, the interactive prompts and the end-to-end decryption of browser-produced artifacts.

## Version History
- 0.6.0: Split into a library plus `encrypt` and `encrypt-web` binaries behind mutually exclusive features; added the drag & drop web interface, Docker images for both, and the automated test suites. Container format unchanged and verified compatible with 0.5.6 in both directions.
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
- The web interface returns two files. If you close the page after downloading only the ciphertext, the data is unrecoverable.
