#!/usr/bin/env bash
# CLI test suite. Drives the standalone binary directly: the CLI is not a
# containerized component, so nothing here needs Docker.
#
#   ./scripts/build-cli.sh
#   ./scripts/test-cli.sh [workdir]
#
# Point it elsewhere with ENCRYPT_BIN=/path/to/encrypt.
# Supplying a pre-refactor build enables the on-disk format compatibility check:
#   ENCRYPT_REF_BIN=/path/to/0.5.6/encrypt ./scripts/test-cli.sh

set -u

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ENCRYPT_BIN:-$PROJECT/dist/encrypt}"
WORK="${1:-$(mktemp -d)}"
REF_BIN="${ENCRYPT_REF_BIN:-}"
PASSWORD="correct horse battery staple"

PASSED=0
FAILED=0

pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "$1"; }

check() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

if [ ! -x "$BIN" ]; then
    printf 'No CLI binary at %s. Run ./scripts/build-cli.sh first.\n' "$BIN" >&2
    exit 1
fi

# `script -c` hands the command to an inner shell, so paths must survive quoting
shell_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

build_command() {
    local cmd
    cmd="$(shell_quote "$1")"
    shift
    for arg in "$@"; do
        cmd="$cmd $(shell_quote "$arg")"
    done
    printf '%s' "$cmd"
}

# rpassword reads from /dev/tty, so the binary needs a pty even when scripted
run_bin() {
    local binary="$1" input="$2"
    shift 2
    printf '%b' "$input" | script -qec "$(build_command "$binary" "$@")" /dev/null
}

cli() {
    local input="$1"
    shift
    run_bin "$BIN" "$input" "$@"
}

cli_ref() {
    local input="$1"
    shift
    run_bin "$REF_BIN" "$input" "$@"
}

encrypt_ok() { cli "$PASSWORD\n$PASSWORD\n" encrypt "$1" >/dev/null 2>&1; }
decrypt_ok() { cli "$PASSWORD\n" decrypt "$1" "$2" >/dev/null 2>&1; }

sha() { sha256sum "$1" | cut -d' ' -f1; }

# Directory encryption renames the target to a random identifier
only_subdir() { find "$1" -mindepth 1 -maxdepth 1 -type d | head -1; }
only_enc() { find "$1" -mindepth 1 -maxdepth 1 -name '*.enc' | head -1; }

new_case() {
    local dir="$WORK/$1"
    rm -rf "$dir"
    mkdir -p "$dir"
    printf '%s' "$dir"
}

printf 'binary:  %s\nworkdir: %s\n\n' "$BIN" "$WORK"
mkdir -p "$WORK"

# ---------------------------------------------------------------------------
printf 'Standalone binary\n'
# ---------------------------------------------------------------------------
if ldd "$BIN" 2>&1 | grep -qE 'not a dynamic executable|statically linked'; then
    pass "binary is statically linked, no runtime dependencies"
else
    # A glibc build from a local cargo is fine too, just note what it needs
    pass "binary is dynamically linked against the local system ($(ldd "$BIN" 2>/dev/null | wc -l) libs)"
fi

# Invoked with no arguments the CLI prints usage and exits 1, by design
if "$BIN" 2>&1 | grep -q 'Usage:'; then
    pass "binary runs without Docker"
else
    fail "binary runs without Docker"
fi

# ---------------------------------------------------------------------------
printf '\nRoundtrip of representative payloads\n'
# ---------------------------------------------------------------------------
make_payload() {
    case "$2" in
        empty)   : > "$1" ;;
        one)     printf 'x' > "$1" ;;
        chunk)   head -c 4194304 /dev/urandom > "$1" ;;
        chunk1)  head -c 4194305 /dev/urandom > "$1" ;;
        multi)   head -c 12582912 /dev/urandom > "$1" ;;
        text)    printf 'hello world\n' > "$1" ;;
    esac
}

for spec in "empty:empty.bin" "one:one.bin" "chunk:chunk-exact.bin" \
            "chunk1:chunk-plus-one.bin" "multi:multi-chunk.bin" \
            "text:a file with spaces & ünicode.txt"; do
    kind="${spec%%:*}"
    name="${spec#*:}"
    dir="$(new_case "rt-$kind")"
    make_payload "$dir/$name" "$kind"
    before="$(sha "$dir/$name")"

    if ! encrypt_ok "$dir/$name"; then
        fail "$name: encrypt"
        continue
    fi

    if [ -e "$dir/$name" ]; then
        fail "$name: plaintext still on disk after encrypt"
        continue
    fi

    enc="$(only_enc "$dir")"
    key="$(find "$dir" -maxdepth 1 -name '*.key' | head -1)"
    if [ -z "$enc" ] || [ -z "$key" ]; then
        fail "$name: missing ciphertext or key"
        continue
    fi

    if ! decrypt_ok "$enc" "$key"; then
        fail "$name: decrypt"
        continue
    fi

    if [ ! -e "$dir/$name" ]; then
        fail "$name: original name not restored"
    elif [ "$(sha "$dir/$name")" != "$before" ]; then
        fail "$name: content mismatch after roundtrip"
    elif [ -e "$key" ]; then
        fail "$name: key file not deleted after clean decrypt"
    else
        pass "$name: roundtrip, name restored, key consumed"
    fi
done

# ---------------------------------------------------------------------------
printf '\nDirectory tree, symlinks, name restoration\n'
# ---------------------------------------------------------------------------
dir="$(new_case tree)"
mkdir -p "$dir/tree/sub a/deeper"
printf 'one\n' > "$dir/tree/first.txt"
printf 'two\n' > "$dir/tree/sub a/second.txt"
printf 'three\n' > "$dir/tree/sub a/deeper/third.txt"
ln -s /etc/passwd "$dir/tree/danger.link"
sum_first="$(sha "$dir/tree/first.txt")"
sum_third="$(sha "$dir/tree/sub a/deeper/third.txt")"
sum_passwd="$(sha /etc/passwd)"

if encrypt_ok "$dir/tree"; then
    renamed="$(only_subdir "$dir")"
    if [ -z "$renamed" ]; then
        fail "tree: directory not renamed"
    else
        check "tree: original directory name gone" test ! -d "$dir/tree"
        check "tree: symlink left untouched" test -L "$renamed/danger.link"
        check "tree: no plaintext left" test ! -e "$renamed/first.txt"

        if [ "$(sha /etc/passwd)" = "$sum_passwd" ]; then
            pass "tree: symlink target never followed"
        else
            fail "tree: symlink target never followed"
        fi

        if decrypt_ok "$renamed" "$dir/tree.key"; then
            if [ "$(sha "$dir/tree/first.txt" 2>/dev/null)" = "$sum_first" ] &&
               [ "$(sha "$dir/tree/sub a/deeper/third.txt" 2>/dev/null)" = "$sum_third" ]; then
                pass "tree: full roundtrip with nested names restored"
            else
                fail "tree: content or structure mismatch"
            fi
            check "tree: dirname markers removed" test -z "$(find "$dir" -name '.dirname.enc')"
        else
            fail "tree: decrypt"
        fi
    fi
else
    fail "tree: encrypt"
fi

# ---------------------------------------------------------------------------
printf '\nFailure modes\n'
# ---------------------------------------------------------------------------
dir="$(new_case wrongpass)"
printf 'secret payload\n' > "$dir/secret.txt"
encrypt_ok "$dir/secret.txt"
enc="$(only_enc "$dir")"
out="$(cli "definitely not the password\n" decrypt "$enc" "$dir/secret.key" 2>&1)"
if printf '%s' "$out" | grep -qi 'wrong password\|corrupted key'; then
    pass "wrong password rejected"
else
    fail "wrong password rejected (got: $(printf '%s' "$out" | tr -d '\r' | tail -1))"
fi
check "wrong password: key file preserved" test -f "$dir/secret.key"
check "wrong password: no plaintext written" test ! -e "$dir/secret.txt"

dir="$(new_case truncated)"
printf 'payload that will be cut short\n' > "$dir/cut.txt"
encrypt_ok "$dir/cut.txt"
enc="$(only_enc "$dir")"
truncate -s -20 "$enc"
out="$(cli "$PASSWORD\n" decrypt "$enc" "$dir/cut.key" 2>&1)"
if printf '%s' "$out" | grep -qi 'truncated\|integrity\|decryption failed'; then
    pass "truncated ciphertext rejected"
else
    fail "truncated ciphertext rejected (got: $(printf '%s' "$out" | tr -d '\r' | tail -1))"
fi
check "truncated: no plaintext written" test ! -e "$dir/cut.txt"
check "truncated: no temp file left" test -z "$(find "$dir" -name '.*.tmp')"
check "truncated: key file preserved" test -f "$dir/cut.key"

dir="$(new_case bitflip)"
head -c 200000 /dev/urandom > "$dir/flip.bin"
encrypt_ok "$dir/flip.bin"
enc="$(only_enc "$dir")"
# Corrupt a byte inside the payload, past salt and metadata block
printf '\xff' | dd of="$enc" bs=1 seek=120 conv=notrunc status=none
out="$(cli "$PASSWORD\n" decrypt "$enc" "$dir/flip.key" 2>&1)"
if printf '%s' "$out" | grep -qi 'decryption failed\|integrity\|corrupt'; then
    pass "corrupted ciphertext rejected"
else
    fail "corrupted ciphertext rejected (got: $(printf '%s' "$out" | tr -d '\r' | tail -1))"
fi
check "bitflip: no plaintext written" test ! -e "$dir/flip.bin"
check "bitflip: no temp file left" test -z "$(find "$dir" -name '.*.tmp')"

dir="$(new_case mismatch)"
printf 'x\n' > "$dir/m.txt"
out="$(cli "onepassword123\nanotherpassword123\n" encrypt "$dir/m.txt" 2>&1)"
if printf '%s' "$out" | grep -qi 'do not match'; then
    pass "password confirmation mismatch aborts"
else
    fail "password confirmation mismatch aborts"
fi
check "mismatch: file untouched" test -f "$dir/m.txt"

dir="$(new_case keyperms)"
printf 'x\n' > "$dir/k.txt"
encrypt_ok "$dir/k.txt"
if [ "$(stat -c '%a' "$dir/k.key")" = "600" ]; then
    pass "key file created with 0600 permissions"
else
    fail "key file created with 0600 permissions (got $(stat -c '%a' "$dir/k.key"))"
fi

# ---------------------------------------------------------------------------
printf '\nOn-disk format compatibility with the pre-refactor binary\n'
# ---------------------------------------------------------------------------
if [ -n "$REF_BIN" ] && [ -x "$REF_BIN" ]; then
    dir="$(new_case compat)"
    head -c 5000000 /dev/urandom > "$dir/legacy.bin"
    before="$(sha "$dir/legacy.bin")"

    if cli_ref "$PASSWORD\n$PASSWORD\n" encrypt "$dir/legacy.bin" >/dev/null 2>&1; then
        enc="$(only_enc "$dir")"
        if decrypt_ok "$enc" "$dir/legacy.key"; then
            if [ "$(sha "$dir/legacy.bin")" = "$before" ]; then
                pass "0.5.6 ciphertext decrypts byte-identically with 0.6.0"
            else
                fail "0.5.6 ciphertext decrypts byte-identically with 0.6.0"
            fi
        else
            fail "0.6.0 could not decrypt a 0.5.6 container"
        fi
    else
        fail "reference binary failed to encrypt"
    fi

    dir="$(new_case compat-rev)"
    head -c 5000000 /dev/urandom > "$dir/current.bin"
    before="$(sha "$dir/current.bin")"
    if encrypt_ok "$dir/current.bin"; then
        enc="$(only_enc "$dir")"
        if cli_ref "$PASSWORD\n" decrypt "$enc" "$dir/current.key" >/dev/null 2>&1; then
            if [ "$(sha "$dir/current.bin")" = "$before" ]; then
                pass "0.6.0 ciphertext decrypts byte-identically with 0.5.6"
            else
                fail "0.6.0 ciphertext decrypts byte-identically with 0.5.6"
            fi
        else
            fail "0.5.6 could not decrypt a 0.6.0 container"
        fi
    else
        fail "0.6.0 failed to encrypt"
    fi
else
    printf '  skip reference binary not provided (set ENCRYPT_REF_BIN)\n'
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
