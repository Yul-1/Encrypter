# Changelog

## [2026-08-12]

### Added
- `COMMANDS.md`: command reference covering build, encrypt, decrypt, scripted prompts, service management, the HTTP endpoint and the test suites. Every command in it was run verbatim before being written down.
- `scripts/build-cli.sh`: produces `dist/encrypt`, a standalone statically linked musl binary. It uses a throwaway `rust` container as a compiler when no local toolchain is present, but the resulting binary has no runtime dependency on Docker.
- Per-request logging on the web service (method, path, status, request size, duration); filenames and passwords are never logged.
- `GET /api/config`, exposing `max_upload_bytes` and `min_password_length`, so the page rejects an oversized file before starting an upload the server would abort mid-stream (browsers surface that abort as a bare network error instead of the 413).
- `encrypt-web` binary: minimal HTTP service with a drag & drop page that encrypts an uploaded copy in memory and returns the ciphertext plus its password-protected key file as two downloads. Encryption only; no decrypt endpoint.
- Web hardening: refusal to start as uid 0 (override with `ENCRYPT_WEB_ALLOW_ROOT=1`), same-origin enforcement on POST via `Origin` and `Sec-Fetch-Site`, upload size limit, worker semaphore acquired before body buffering, queue and upload timeouts, optional `ENCRYPT_WEB_TOKEN` with constant-time comparison, strict CSP and security headers, and minimal logging that never records filenames or passwords.
- Multi-stage `Dockerfile` building the distroless web image, `docker-compose.yml` publishing the service on `127.0.0.1:8085` with read-only rootfs, dropped capabilities, `no-new-privileges` and memory/pids limits, and `.dockerignore`.
- `scripts/test-cli.sh` (29 checks: roundtrips across chunk boundaries, unicode names, nested trees, symlink skipping, key file permissions, wrong password, truncation, bit flips, on-disk format compatibility with 0.5.6 in both directions) and `scripts/test-web.sh` (46 checks: HTTP contract, security headers, decrypt roundtrip closed with the standalone CLI, input validation, upload limit, cross-origin rejection, hostile filenames, container hardening, root refusal, token mode, concurrency under load).
- `MANUAL-TESTS.md` with the browser and interactive checks the automated suites cannot cover, including full decryption of browser-produced artifacts.

### Changed
- The web service no longer restarts on its own: the compose restart policy is `no`, so it comes up only when started deliberately with `docker compose up -d`.
- Only the web encrypter is containerized. The `cli` image target was removed: the CLI is the privileged, filesystem-facing tool and ships as a plain binary, without volume mounts, uid mapping or TTY friction. Both test suites now drive that binary directly.
- The web page shows the file size against the server limit as soon as a file is dropped, and reports dropped connections, aborts and timeouts distinctly.
- Split the single-file CLI into `src/lib.rs`, `src/crypto.rs` (stream-based core, no filesystem access) and `src/fsops.rs` (filesystem operations). `src/main.rs` now only handles arguments and prompts.
- `cli` and `web` are mutually exclusive cargo features: the privileged CLI binary contains no HTTP stack, and the network-facing binary is not linked against the secure-delete and directory-recursion code.
- Error type unified to `Box<dyn Error + Send + Sync>` so failures can cross thread boundaries in the web service.
- Version bumped to 0.6.0. The on-disk container format is unchanged and verified byte-compatible with 0.5.6 in both directions.

### Fixed
- A failed encryption no longer leaves a partial `.enc` file behind; the incomplete output is removed and the plaintext source is left untouched.
- Encryption now rejects a filename whose encrypted metadata would exceed the 4096-byte header limit the decryptor enforces, instead of producing an unreadable container.
- Replaced the unbounded recursion used to resolve ciphertext name collisions with a bounded retry loop.
