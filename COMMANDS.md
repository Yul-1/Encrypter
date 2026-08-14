# Command reference

Everything you actually type, in one place.

The project ships two separate things. The **CLI** is a plain binary you run
from a shell; it never runs in a container. The **web encrypter** is the only
containerized component, and it only ever starts because you started it.

---

## Get the CLI

### 1. Build the binary

Run one of these by hand; nothing builds automatically.

| Situation | Command | Result |
| --- | --- | --- |
| Rust installed | `cargo build --release` | `target/release/encrypt` |
| No Rust, Docker available | `./scripts/build-cli.sh` | `dist/encrypt` |

`scripts/build-cli.sh` picks the same two paths on its own: with a local
`cargo` it builds natively, without one it starts a throwaway `rust` container
purely as a compiler (`docker run --rm`, gone the moment the build ends) and
emits a statically linked musl binary. Either way it copies the result to
`dist/encrypt`, so that path is always the freshest build.

A cache volume named `encrypt-cargo-cache` survives between runs to keep later
builds fast; it is the only thing the script leaves behind.

The binary that comes out is self-contained. It does not need Docker, Rust, or
any shared library at runtime — and it is a Linux binary, so it runs under WSL
but not in PowerShell or CMD.

### 2. Put it on your PATH

Until you do this, `encrypt` is not a command: you have to spell out the full
path to the binary every time.

```bash
cp dist/encrypt ~/.local/bin/encrypt      # any directory on your PATH works
```

Check it took:

```bash
command -v encrypt      # -> /home/<you>/.local/bin/encrypt
encrypt                 # prints the usage lines
```

Every CLI example below assumes this step. If you would rather not install it,
the commands are identical with `./dist/encrypt` in place of `encrypt`.

Re-run the copy after every rebuild — `cp` takes a snapshot, so a fresh
`dist/encrypt` does not update the copy on your PATH by itself.

---

## Build the web service

| Goal | Command |
| --- | --- |
| Service image | `docker compose build` |
| Service, natively | `cargo build --release --no-default-features --features web` |

---

## CLI

### Where the files land

Both commands work from any directory, and the directory you happen to be in
never affects the outcome. Everything is written **next to the file you named**:
the `.enc` and the `.key` appear beside the original, and a decrypted file is
restored beside its `.enc`.

```bash
cd ~
encrypt encrypt /srv/data/report.pdf     # .enc and .key appear in /srv/data
```

The two arguments of `decrypt` are independent paths, so the `.enc` and the
`.key` do not have to sit in the same directory — keeping them apart is the
point.

### Encrypt

```bash
encrypt encrypt <path>
```

`<path>` is a file or a directory. You are prompted twice for the password that
protects the key file.

```bash
encrypt encrypt ./report.pdf          # -> <random>.enc + report.key
encrypt encrypt ./documents           # whole tree -> renamed dir + documents.key
sudo encrypt encrypt /srv/archive     # privileged targets
```

What happens: the file is replaced by `<random>.enc`, its real name is stored
encrypted inside the container, and **the plaintext is overwritten with random
data and deleted**. A directory is encrypted file by file, then renamed to a
random identifier. Symlinks are skipped, never followed.

### Decrypt

```bash
encrypt decrypt <path> <keyfile>
```

```bash
encrypt decrypt ./AbCd1234EfGh5678.enc ./report.key
encrypt decrypt ./Xy9Zq2Lm4Np7Rs1T ./documents.key      # a directory
encrypt decrypt /srv/data/x.enc ~/keys/x.key          # the two can live apart
```

Original names are restored from the encrypted metadata. On complete success
the key file is securely deleted; if anything failed, it is kept so you can
retry. Integrity is verified before the plaintext is put in place.

### Decrypt what the browser produced

The web page has no decrypt endpoint by design; the two downloads are restored
with the CLI, same command:

```bash
cd ~/Downloads
encrypt decrypt ./<random>.enc ./<random>.key
```

### Scripting the prompts

The password prompt reads from `/dev/tty`, so a terminal is required. To drive
it from a script, allocate a pty:

```bash
printf 'my long password\nmy long password\n' | script -qec "encrypt encrypt ./file" /dev/null
printf 'my long password\n'                   | script -qec "encrypt decrypt ./x.enc ./x.key" /dev/null
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
encrypt decrypt ./out.enc ./out.key
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
