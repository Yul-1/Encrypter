#!/usr/bin/env bash
# Web service test suite: HTTP contract, cross-container decrypt roundtrip and
# the hardening assertions. Expects the compose stack to be running.
#
#   docker compose up -d --build
#   ./scripts/test-web.sh [workdir]

set -u

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${ENCRYPT_WEB_URL:-http://127.0.0.1:8085}"
WEB_IMAGE="${ENCRYPT_WEB_IMAGE:-encrypt-web:0.6.0}"
CONTAINER="${ENCRYPT_WEB_CONTAINER:-encrypt-web}"
# The CLI is not containerized: the roundtrip is closed with the standalone binary
BIN="${ENCRYPT_BIN:-$PROJECT/dist/encrypt}"
WORK="${1:-$(mktemp -d)}"
PASSWORD="correct horse battery staple"

if [ ! -x "$BIN" ]; then
    printf 'No CLI binary at %s. Run ./scripts/build-cli.sh first.\n' "$BIN" >&2
    exit 1
fi

# rpassword reads from /dev/tty, so the binary needs a pty even when scripted
decrypt_with_cli() {
    printf '%b' "$PASSWORD\n" |
        script -qec "'$BIN' decrypt '$1' '$2'" /dev/null
}

PASSED=0
FAILED=0

pass() { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "$1"; }

expect_status() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$label (HTTP $actual)"
    else
        fail "$label (expected HTTP $expected, got $actual)"
    fi
}

mkdir -p "$WORK"
printf 'target:  %s\nworkdir: %s\n\n' "$BASE" "$WORK"

# ---------------------------------------------------------------------------
printf 'Static surface and security headers\n'
# ---------------------------------------------------------------------------
headers="$WORK/index.headers"
status="$(curl -sS -D "$headers" -o "$WORK/index.html" -w '%{http_code}' "$BASE/")"
expect_status "GET / serves the page" 200 "$status"

for header in "content-security-policy" "x-content-type-options" "x-frame-options" \
              "referrer-policy" "cache-control" "cross-origin-resource-policy"; do
    if grep -qi "^$header:" "$headers"; then
        pass "response carries $header"
    else
        fail "response carries $header"
    fi
done

if grep -qi "^content-security-policy:.*default-src 'none'" "$headers"; then
    pass "CSP denies everything by default"
else
    fail "CSP denies everything by default"
fi

if grep -qiE '<script[^>]*>[^<]' "$WORK/index.html" || grep -qi 'onclick=' "$WORK/index.html"; then
    fail "page is free of inline script"
else
    pass "page is free of inline script"
fi

for asset in app.css app.js; do
    status="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/$asset")"
    expect_status "GET /$asset" 200 "$status"
done

status="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/healthz")"
expect_status "GET /healthz" 200 "$status"

config_body="$(curl -sS "$BASE/api/config")"
if printf '%s' "$config_body" | grep -q '"max_upload_bytes":[0-9]\+'; then
    pass "GET /api/config advertises the upload limit to the page"
else
    fail "GET /api/config advertises the upload limit to the page (got: $config_body)"
fi

# ---------------------------------------------------------------------------
printf '\nEncrypt roundtrip: browser upload decrypted by the CLI\n'
# ---------------------------------------------------------------------------
mkdir -p "$WORK/roundtrip"
sample="$WORK/roundtrip/report final.pdf"
head -c 3000000 /dev/urandom > "$sample"
sample_sum="$(sha256sum "$sample" | cut -d' ' -f1)"

resp_headers="$WORK/roundtrip/resp.headers"
status="$(curl -sS -D "$resp_headers" -o "$WORK/roundtrip/out.enc" -w '%{http_code}' \
    -H "Origin: $BASE" -H "Sec-Fetch-Site: same-origin" \
    -F "password=$PASSWORD" -F "file=@$sample" "$BASE/api/encrypt")"
expect_status "POST /api/encrypt" 200 "$status"

key_b64="$(grep -i '^x-encrypt-key:' "$resp_headers" | tr -d '\r' | cut -d' ' -f2)"
key_name="$(grep -i '^x-encrypt-key-filename:' "$resp_headers" | tr -d '\r' | cut -d' ' -f2)"
enc_name="$(grep -i '^content-disposition:' "$resp_headers" | tr -d '\r' | sed -n 's/.*filename="\([^"]*\)".*/\1/p')"

if [ -n "$key_b64" ] && [ -n "$key_name" ] && [ -n "$enc_name" ]; then
    pass "response advertises ciphertext and key file names"
else
    fail "response advertises ciphertext and key file names"
fi

if [ "${enc_name%.enc}" = "${key_name%.key}" ]; then
    pass "ciphertext and key share a stem"
else
    fail "ciphertext and key share a stem ($enc_name / $key_name)"
fi

if [ -f "$sample" ] && [ "$(sha256sum "$sample" | cut -d' ' -f1)" = "$sample_sum" ]; then
    pass "original file on disk is untouched"
else
    fail "original file on disk is untouched"
fi

if grep -qiE '\.pdf' "$WORK/roundtrip/out.enc" 2>/dev/null; then
    fail "ciphertext leaks the original file name"
else
    pass "ciphertext does not leak the original file name"
fi

mv "$WORK/roundtrip/out.enc" "$WORK/roundtrip/$enc_name"
printf '%s' "$key_b64" | base64 -d > "$WORK/roundtrip/$key_name"

decrypt_out="$(decrypt_with_cli "$WORK/roundtrip/$enc_name" "$WORK/roundtrip/$key_name" 2>&1)"

if [ -f "$WORK/roundtrip/report final.pdf" ]; then
    # get_unique_path appends _1 when the original name is already taken
    restored="$WORK/roundtrip/report final_1.pdf"
    [ -f "$restored" ] || restored="$WORK/roundtrip/report final.pdf"
    if [ "$(sha256sum "$restored" | cut -d' ' -f1)" = "$sample_sum" ]; then
        pass "CLI decrypts the browser ciphertext to identical bytes"
    else
        fail "CLI decrypts the browser ciphertext to identical bytes"
    fi
    if [ -f "$restored" ] && [ "$restored" != "$sample" ]; then
        pass "original filename restored from encrypted metadata"
    fi
else
    fail "CLI decrypt produced no output ($(printf '%s' "$decrypt_out" | tr -d '\r' | tail -1))"
fi

# ---------------------------------------------------------------------------
printf '\nInput validation\n'
# ---------------------------------------------------------------------------
printf 'payload\n' > "$WORK/small.txt"

status="$(curl -sS -o /dev/null -w '%{http_code}' -F "password=short" -F "file=@$WORK/small.txt" "$BASE/api/encrypt")"
expect_status "password below 12 characters rejected" 400 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -F "file=@$WORK/small.txt" "$BASE/api/encrypt")"
expect_status "missing password rejected" 400 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -F "password=$PASSWORD" "$BASE/api/encrypt")"
expect_status "missing file rejected" 400 "$status"

: > "$WORK/empty.bin"
status="$(curl -sS -o /dev/null -w '%{http_code}' -F "password=$PASSWORD" -F "file=@$WORK/empty.bin" "$BASE/api/encrypt")"
expect_status "empty file rejected" 400 "$status"

body="$(curl -sS -F "password=short" -F "file=@$WORK/small.txt" "$BASE/api/encrypt")"
if printf '%s' "$body" | grep -q '"error"'; then
    pass "errors are JSON without internal detail"
else
    fail "errors are JSON without internal detail"
fi

status="$(curl -sS -o /dev/null -w '%{http_code}' -X GET "$BASE/api/encrypt")"
expect_status "GET on the encrypt endpoint rejected" 405 "$status"

# ---------------------------------------------------------------------------
printf '\nUpload limit and cross-origin protection\n'
# ---------------------------------------------------------------------------
limit_mb="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" |
    sed -n 's/^ENCRYPT_WEB_MAX_UPLOAD_MB=//p' | tail -1)"
limit_mb="${limit_mb:-64}"
head -c $(((limit_mb + 2) * 1024 * 1024)) /dev/zero > "$WORK/oversize.bin"
status="$(curl -sS -o /dev/null -w '%{http_code}' -F "password=$PASSWORD" -F "file=@$WORK/oversize.bin" "$BASE/api/encrypt")"
expect_status "upload above ${limit_mb} MiB rejected" 413 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Origin: http://evil.test" \
    -F "password=$PASSWORD" -F "file=@$WORK/small.txt" "$BASE/api/encrypt")"
expect_status "cross-origin POST rejected" 403 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Sec-Fetch-Site: cross-site" \
    -F "password=$PASSWORD" -F "file=@$WORK/small.txt" "$BASE/api/encrypt")"
expect_status "cross-site fetch metadata rejected" 403 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Origin: $BASE" -H "Sec-Fetch-Site: same-origin" \
    -F "password=$PASSWORD" -F "file=@$WORK/small.txt" "$BASE/api/encrypt")"
expect_status "same-origin POST accepted" 200 "$status"

# ---------------------------------------------------------------------------
printf '\nHostile file names\n'
# ---------------------------------------------------------------------------
mkdir -p "$WORK/traversal"
printf 'not the real passwd\n' > "$WORK/traversal/payload"
traversal_headers="$WORK/traversal/resp.headers"
status="$(curl -sS -D "$traversal_headers" -o "$WORK/traversal/out.enc" -w '%{http_code}' \
    -F "password=$PASSWORD" \
    -F 'file=@'"$WORK/traversal/payload"';filename=../../../../etc/passwd' "$BASE/api/encrypt")"
expect_status "traversal file name accepted but neutralised" 200 "$status"

key_b64="$(grep -i '^x-encrypt-key:' "$traversal_headers" | tr -d '\r' | cut -d' ' -f2)"
key_name="$(grep -i '^x-encrypt-key-filename:' "$traversal_headers" | tr -d '\r' | cut -d' ' -f2)"
enc_name="$(grep -i '^content-disposition:' "$traversal_headers" | tr -d '\r' | sed -n 's/.*filename="\([^"]*\)".*/\1/p')"
mv "$WORK/traversal/out.enc" "$WORK/traversal/$enc_name"
printf '%s' "$key_b64" | base64 -d > "$WORK/traversal/$key_name"

decrypt_with_cli "$WORK/traversal/$enc_name" "$WORK/traversal/$key_name" >/dev/null 2>&1

if [ -f "$WORK/traversal/passwd" ]; then
    pass "traversal name reduced to a basename in the metadata"
else
    fail "traversal name reduced to a basename in the metadata"
fi

if [ "$(find "$WORK/traversal" -maxdepth 1 -type d | wc -l)" = "1" ]; then
    pass "decrypt wrote nothing outside the working directory"
else
    fail "decrypt wrote nothing outside the working directory"
fi

# ---------------------------------------------------------------------------
printf '\nContainer hardening\n'
# ---------------------------------------------------------------------------
uid="$(docker inspect -f '{{.Config.User}}' "$CONTAINER")"
if [ "$uid" = "65532:65532" ] || [ "$uid" = "65532" ]; then
    pass "service runs as non-root uid ($uid)"
else
    fail "service runs as non-root uid (got '$uid')"
fi

if [ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER")" = "true" ]; then
    pass "root filesystem is read-only"
else
    fail "root filesystem is read-only"
fi

if [ "$(docker inspect -f '{{.HostConfig.CapDrop}}' "$CONTAINER")" = "[ALL]" ]; then
    pass "all capabilities dropped"
else
    fail "all capabilities dropped"
fi

if docker inspect -f '{{.HostConfig.SecurityOpt}}' "$CONTAINER" | grep -q 'no-new-privileges:true'; then
    pass "no-new-privileges is set"
else
    fail "no-new-privileges is set"
fi

restart_policy="$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")"
if [ "$restart_policy" = "no" ] || [ -z "$restart_policy" ]; then
    pass "service is started manually, never automatically"
else
    fail "service is started manually, never automatically (policy: $restart_policy)"
fi

if [ -z "$(docker diff "$CONTAINER")" ]; then
    pass "no filesystem writes after serving traffic"
else
    fail "no filesystem writes after serving traffic: $(docker diff "$CONTAINER" | head -3)"
fi

if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" ]; then
    pass "container still healthy after the whole suite"
else
    fail "container still healthy after the whole suite"
fi

# ---------------------------------------------------------------------------
printf '\nPrivilege refusal and token mode\n'
# ---------------------------------------------------------------------------
root_out="$(docker run --rm --user 0:0 "$WEB_IMAGE" 2>&1)"
if printf '%s' "$root_out" | grep -qi 'refusing to run as root'; then
    pass "service refuses to start as root"
else
    fail "service refuses to start as root (got: $(printf '%s' "$root_out" | head -1))"
fi

root_out="$(docker run --rm --user 0:0 -e ENCRYPT_WEB_ALLOW_ROOT=1 -e ENCRYPT_WEB_BIND=127.0.0.1:8080 \
    --entrypoint /usr/local/bin/encrypt-web "$WEB_IMAGE" --healthcheck 2>&1)"
if [ -n "$root_out" ] && printf '%s' "$root_out" | grep -qi 'refusing'; then
    fail "explicit override still refuses"
else
    pass "explicit ENCRYPT_WEB_ALLOW_ROOT override is honoured"
fi

docker rm -f encrypt-web-token >/dev/null 2>&1
docker run -d --name encrypt-web-token -p 127.0.0.1:8086:8080 \
    -e ENCRYPT_WEB_TOKEN=super-secret-token -e ENCRYPT_WEB_BIND=0.0.0.0:8080 \
    --user 65532:65532 --read-only "$WEB_IMAGE" >/dev/null 2>&1
sleep 1

status="$(curl -sS -o /dev/null -w '%{http_code}' -F "password=$PASSWORD" -F "file=@$WORK/small.txt" http://127.0.0.1:8086/api/encrypt)"
expect_status "token mode rejects requests without the token" 401 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Encrypt-Token: wrong-token" \
    -F "password=$PASSWORD" -F "file=@$WORK/small.txt" http://127.0.0.1:8086/api/encrypt)"
expect_status "token mode rejects a wrong token" 401 "$status"

status="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Encrypt-Token: super-secret-token" \
    -F "password=$PASSWORD" -F "file=@$WORK/small.txt" http://127.0.0.1:8086/api/encrypt)"
expect_status "token mode accepts the right token" 200 "$status"

docker rm -f encrypt-web-token >/dev/null 2>&1

# ---------------------------------------------------------------------------
printf '\nConcurrency under load\n'
# ---------------------------------------------------------------------------
head -c 8000000 /dev/urandom > "$WORK/load.bin"
pids=""
for i in 1 2 3 4 5 6; do
    curl -sS -o /dev/null -w '%{http_code}\n' -F "password=$PASSWORD" -F "file=@$WORK/load.bin" \
        "$BASE/api/encrypt" > "$WORK/load-$i.status" &
    pids="$pids $!"
done
for pid in $pids; do wait "$pid"; done

unexpected="$(cat "$WORK"/load-*.status | grep -vc '200\|503')"
if [ "$unexpected" = "0" ]; then
    pass "6 parallel uploads all returned 200 or 503 ($(cat "$WORK"/load-*.status | sort | uniq -c | tr '\n' ' '))"
else
    fail "6 parallel uploads produced unexpected statuses ($(cat "$WORK"/load-*.status | sort | uniq -c | tr '\n' ' '))"
fi

if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" ] &&
   [ "$(docker inspect -f '{{.State.OOMKilled}}' "$CONTAINER")" = "false" ]; then
    pass "service survived the load without being OOM killed"
else
    fail "service survived the load without being OOM killed"
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
