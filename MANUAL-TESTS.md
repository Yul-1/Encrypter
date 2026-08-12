# Manual test checklist

What `scripts/test-cli.sh` and `scripts/test-web.sh` cannot reach: the interactive prompts, the browser drag & drop flow, the two-file download, and the human judgement calls. Work through this before releasing, and after any change to the container format or to the web service.

Legend: **Do** = what to run, **Expect** = what must happen. Anything else is a failure worth investigating before shipping.

---

## 0. Preparation

```bash
cd /path/to/Encrypt
./scripts/build-cli.sh            # -> dist/encrypt, standalone, no Docker at runtime
docker compose up -d --build      # only the web encrypter is containerized
export ENC="$PWD/dist/encrypt"
mkdir -p /tmp/enc-manual && cd /tmp/enc-manual
head -c 3000000 /dev/urandom > sample.bin
sha256sum sample.bin | tee sample.sha
```

- [ ] **Do** `ldd "$ENC"`
      **Expect** `not a dynamic executable` / `statically linked` (when built by the script): the CLI depends on nothing, Docker included.

- [ ] **Do** `docker compose ps`
      **Expect** `encrypt-web` is `Up` and eventually `(healthy)`; the port mapping reads `127.0.0.1:8085->8080/tcp` and **not** `0.0.0.0:8085`.

---

## 1. CLI: encrypt and decrypt a single file

- [ ] **Do**
      ```bash
      "$ENC" encrypt sample.bin
      ```
      Type a password twice when prompted.
      **Expect** the password is *not* echoed; output reports `Master Key saved to: sample.key`; `ls` shows a random `<16 chars>.enc` and `sample.key`, and `sample.bin` is **gone**.

- [ ] **Do** `ls -l sample.key`
      **Expect** permissions `-rw-------` (0600).

- [ ] **Do**
      ```bash
      "$ENC" decrypt <random>.enc sample.key
      ```
      **Expect** `Restored and Verified: sample.bin`, then `SUCCESS: Key file deleted securely.` The `.enc` and the `.key` are both gone.

- [ ] **Do** `sha256sum -c sample.sha`
      **Expect** `sample.bin: OK` — the roundtrip is byte-exact.

## 2. CLI: wrong password and mismatch

- [ ] **Do** Encrypt a throwaway file, then run decrypt and type a deliberately wrong password.
      **Expect** `Wrong password or corrupted key`; the `.enc` and the `.key` are **still there**; no plaintext appears.

- [ ] **Do** Run encrypt and type two different passwords at the two prompts.
      **Expect** `Passwords do not match`; the target file is untouched; no `.key` is written.

## 3. CLI: directory tree

```bash
mkdir -p tree/"sub dir"/deeper
echo one > tree/first.txt
echo two > tree/"sub dir"/second.txt
echo three > tree/"sub dir"/deeper/third.txt
ln -s /etc/hostname tree/link
```

- [ ] **Do** `"$ENC" encrypt tree`
      **Expect** a line `Skipping symlink: tree/link`; the directory is renamed to a random identifier; `tree.key` sits next to it; no original filename survives inside.

- [ ] **Do** `cat /etc/hostname`
      **Expect** unchanged content — the symlink was never followed or overwritten.

- [ ] **Do** `"$ENC" decrypt <random-dir> tree.key`
      **Expect** `Restored Dir:` lines; the tree returns with `tree/`, `sub dir/`, `deeper/` and the three files with their original names and contents; no `.dirname.enc` remains (`find tree -name '.dirname.enc'` prints nothing).

## 4. CLI: large file and progress

- [ ] **Do** `head -c 300000000 /dev/urandom > big.bin` then encrypt it.
      **Expect** a progress bar appears (files above 1 MiB), advances, and disappears on completion. Decrypt and verify the hash matches.

## 5. CLI with elevated privileges

The CLI is the component meant to run privileged; confirm it behaves when it does.

- [ ] **Do** Encrypt a file owned by another user with `sudo "$ENC" encrypt /path/to/file` (native binary, not the container).
      **Expect** success, and the resulting `.enc` and `.key` are owned by root with the key at 0600. Decrypt it back and verify the hash.

- [ ] **Do** Point the CLI at a directory containing a symlink to a sensitive file (for example `/etc/shadow`) and encrypt it as root.
      **Expect** `Skipping symlink:` and the target file completely untouched (`sudo sha256sum /etc/shadow` before and after).

---

## 6. Web UI: the drag & drop flow

Open `http://127.0.0.1:8085` in a browser.

- [ ] **Expect** the page renders with the drop zone, two password fields and the button; it follows the OS light/dark preference.

- [ ] **Do** Open the browser devtools **Network** tab and reload.
      **Expect** exactly four requests (`/`, `/app.css`, `/app.js`, `/api/config`), all same-origin. **No** request to any external host, CDN or font provider.

- [ ] **Do** Check the devtools **Console**.
      **Expect** no Content-Security-Policy violation, no script error.

- [ ] **Do** Drag `sample.bin` from the file manager onto the drop zone.
      **Expect** the zone highlights while dragging; on drop the file name and size appear.

- [ ] **Do** Drop a file *outside* the drop zone, on the page background.
      **Expect** nothing happens — the browser must **not** navigate away and open the file.

- [ ] **Do** Click the drop zone instead of dragging (and press Enter with it focused).
      **Expect** the native file picker opens; the chosen file is shown the same way.

## 7. Web UI: validation

- [ ] **Do** Submit with no file selected.
      **Expect** `Choose a file first.` in red; no request is sent.

- [ ] **Do** Select a file, type an 8-character password twice, submit.
      **Expect** `The password must be at least 12 characters.`; no request is sent.

- [ ] **Do** Type two different passwords of 12+ characters, submit.
      **Expect** `The two passwords do not match.`; no request is sent.

- [ ] **Do** Drop a file larger than the configured limit (`head -c 70000000 /dev/urandom > toobig.bin` with the default 64 MiB).
      **Expect** the size warning appears **immediately on drop**, naming the actual size and the limit, and the upload never starts. It must **not** produce a bare connection error: the server aborts an oversize body mid-stream, and browsers report that as a network failure rather than the 413.

## 8. Web UI: encrypt and download both files

- [ ] **Do** Select `sample.bin`, type the same 12+ character password twice, submit.
      **Expect** the progress bar advances during upload, then the label switches to `Encrypting…`; the button is disabled while it runs.

- [ ] **Expect** on success: the status reads `Encrypted. Your original file was not touched.`, and the result panel appears with the warning about needing both files.

- [ ] **Expect** the browser saves **two** files, `<random>.enc` and `<random>.key`, sharing the same random stem. If the browser blocked the second automatic download, the two buttons in the panel must download them on click.
      *This is the single most important check on the page: a user who leaves with only the `.enc` has lost the data permanently.*

- [ ] **Do** `sha256sum -c sample.sha` in the folder holding the original.
      **Expect** `sample.bin: OK` — the web path leaves the original on disk, untouched.

- [ ] **Do** Inspect the downloaded `.enc` with `strings <random>.enc | grep -i sample`.
      **Expect** no match: the original filename lives only inside the encrypted metadata.

## 9. Decrypting the browser artifacts with the CLI

The web service deliberately has no decrypt endpoint, so this is the path a real user must follow. **It has to work.**

- [ ] **Do** Move both downloads into one directory and run:
      ```bash
      cd ~/Downloads
      "$ENC" decrypt <random>.enc <random>.key
      ```
      Type the password used in the browser.
      **Expect** `Password correct. Starting decryption...`, then `Restored and Verified: sample.bin`, then `SUCCESS: Key file deleted securely.`

- [ ] **Do** Compare against the original: `sha256sum <restored file>` versus `sample.sha`.
      **Expect** identical digests.

- [ ] **Do** Repeat the browser encryption, then try to decrypt with the **wrong** password.
      **Expect** `Wrong password or corrupted key`; both files survive so the user can retry.

- [ ] **Do** Encrypt two different files through the browser, then try to decrypt the first `.enc` with the **second** `.key`.
      **Expect** failure at the metadata stage (`Decryption failed (Metadata)`), no output file, no temp file left behind (`ls -a` shows no `.*.tmp`).

- [ ] **Do** Truncate a browser-produced ciphertext (`truncate -s -32 <random>.enc`) and decrypt it.
      **Expect** a truncation or integrity error and **no** partially restored plaintext on disk.

- [ ] **Do** Upload a file whose name contains spaces, accents and an emoji, encrypt it through the browser, then decrypt with the CLI.
      **Expect** the exact original name is restored.

---

## 10. Security spot checks

- [ ] **Do** From a different origin, run this in the console of any other site (for example `https://example.com`):
      ```js
      fetch('http://127.0.0.1:8085/api/encrypt', {method: 'POST', body: new FormData()})
      ```
      **Expect** the request is refused with 403 (and/or blocked by the browser); the service must never process a POST driven by a foreign page.

- [ ] **Do** `docker run --rm --user 0:0 encrypt-web:0.6.0`
      **Expect** it exits immediately with `Refusing to run as root...`.

- [ ] **Do** `docker exec encrypt-web /bin/sh`
      **Expect** failure — the distroless image has no shell.

- [ ] **Do** `docker diff encrypt-web` after a few encryptions.
      **Expect** empty output: the service writes nothing to its filesystem.

- [ ] **Do** Set `ENCRYPT_WEB_TOKEN` in `docker-compose.yml`, `docker compose up -d`, then use the page.
      **Expect** the browser upload now fails with 401 (the bundled page does not send the header): confirm the variable is only meant for deployments fronted by a proxy that injects `X-Encrypt-Token`, and unset it again afterwards.

- [ ] **Do** Watch `docker compose logs -f encrypt-web` while encrypting a file named something recognisable.
      **Expect** no filename, no password and no key material in the logs.

- [ ] **Do** `docker stats encrypt-web` while uploading several large files at once.
      **Expect** memory stays well under the 512 MiB limit and the container is never OOM killed.

---

## 11. Recovery expectations

- [ ] **Do** Delete a `.key` file and attempt to decrypt.
      **Expect** `Target path or key file not found` — and understand that the data is now unrecoverable by design.

- [ ] **Do** Confirm the CHANGELOG and README describe what you just observed.
      **Expect** no surprises. If reality and documentation disagree, fix the documentation before release.
