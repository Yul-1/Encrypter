# Command reference

Everything you actually type, in one place. `$ENC` is the CLI binary: after
`./scripts/build-cli.sh` it lives at `./dist/encrypt`.

```bash
export ENC="$PWD/dist/encrypt"
```

---

## Build

| Goal | Command |
| --- | --- |
| CLI, with a local Rust toolchain | `cargo build --release` (binary at `target/release/encrypt`) |
| CLI, without a toolchain | `./scripts/build-cli.sh` (static binary at `dist/encrypt`) |
| Web service image | `docker compose build` |
| Web service, natively | `cargo build --release --no-default-features --features web` |

The CLI needs nothing at runtime: `scripts/build-cli.sh` only borrows a `rust`
container as a compiler, and the binary it produces is statically linked.

---

## CLI

### Encrypt

```bash
"$ENC" encrypt <path>
```

`<path>` is a file or a directory. You are prompted twice for the password that
protects the key file.

```bash
"$ENC" encrypt ./report.pdf          # -> <random>.enc + report.key
"$ENC" encrypt ./documents           # whole tree -> renamed dir + documents.key
sudo "$ENC" encrypt /srv/archive     # privileged targets
```

What happens: the file is replaced by `<random>.enc`, its real name is stored
encrypted inside the container, and **the plaintext is overwritten with random
data and deleted**. A directory is encrypted file by file, then renamed to a
random identifier. Symlinks are skipped, never followed.

### Decrypt

```bash
"$ENC" decrypt <path> <keyfile>
```

```bash
"$ENC" decrypt ./AbCd1234EfGh5678.enc ./report.key
"$ENC" decrypt ./Xy9Zq2Lm4Np7Rs1T ./documents.key      # a directory
```

Original names are restored from the encrypted metadata. On complete success
the key file is securely deleted; if anything failed, it is kept so you can
retry. Integrity is verified before the plaintext is put in place.

### Decrypt what the browser produced

The web page has no decrypt endpoint by design; the two downloads are restored
with the CLI, same command:

```bash
cd ~/Downloads
"$ENC" decrypt ./<random>.enc ./<random>.key
```

### Scripting the prompts

The password prompt reads from `/dev/tty`, so a terminal is required. To drive
it from a script, allocate a pty:

```bash
printf 'my long password\nmy long password\n' | script -qec "'$ENC' encrypt ./file" /dev/null
printf 'my long password\n'                   | script -qec "'$ENC' decrypt ./x.enc ./x.key" /dev/null
```

---

## Web service

Start it yourself when you need it; it never comes up on its own.

| Goal | Command |
| --- | --- |
| Start | `docker compose up -d` |
| Start after a code change | `docker compose up -d --build` |
| Open | `http://127.0.0.1:8085` |
| Status | `docker compose ps` |
| Follow the log | `docker compose logs -f encrypt-web` |
| Stop | `docker compose stop` |
| Stop and remove | `docker compose down` |

A request line looks like this, with no filename and no password in it:

```
POST /api/encrypt -> 200 in=3145992B 214ms
```

### Settings

Edit the `environment:` block in `docker-compose.yml`, then `docker compose up -d`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENCRYPT_WEB_BIND` | `127.0.0.1:8080` | Listen address inside the container |
| `ENCRYPT_WEB_MAX_UPLOAD_MB` | `64` | Upload ceiling, max 512 |
| `ENCRYPT_WEB_CONCURRENCY` | `2` | Simultaneous encryption workers, max 16 |
| `ENCRYPT_WEB_TOKEN` | unset | Requires a matching `X-Encrypt-Token` on POST |
| `ENCRYPT_WEB_ALLOW_ROOT` | unset | `1` bypasses the refusal to run as uid 0 |

To publish on a different host port, change the left-hand side of
`127.0.0.1:8085:8080` in `docker-compose.yml`. Keep the `127.0.0.1` prefix
unless you have put TLS and authentication in front of it.

### Calling the endpoint directly

```bash
curl -sS -D headers.txt -o out.enc \
    -F "password=your long password" \
    -F "file=@./report.pdf" \
    http://127.0.0.1:8085/api/encrypt

# tr strips the CR of the HTTP line terminator, which base64 would reject
grep -i '^x-encrypt-key:' headers.txt | tr -d '\r' | cut -d' ' -f2 | base64 -d > out.key
"$ENC" decrypt ./out.enc ./out.key
```

The restored file takes back its original name. If that name is already taken —
which it is here, since the web path left `report.pdf` where it was — a numeric
suffix is added instead of overwriting anything: `report_1.pdf`.

```bash
curl -sS http://127.0.0.1:8085/api/config     # upload limit and password minimum
curl -sS http://127.0.0.1:8085/healthz        # "ok"
```

---

## Tests

| Goal | Command |
| --- | --- |
| CLI suite | `./scripts/test-cli.sh` |
| CLI suite plus format compatibility | `ENCRYPT_REF_BIN=/path/to/old/encrypt ./scripts/test-cli.sh` |
| Web suite (service must be running) | `./scripts/test-web.sh` |
| Manual checklist | see `MANUAL-TESTS.md` |

Both suites print `N passed, M failed` and exit non-zero on any failure.

---

## Recovery

There is no back door. Losing either half makes the data unrecoverable:

- the `.key` file, and
- the password that protects it.

Keep the `.key` somewhere other than next to the `.enc`, and remember that a
successful decrypt deletes the key file — that pair is single-use by design.
