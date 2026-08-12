//! Minimal drag & drop encryption service.
//!
//! Threat model: this binary is the network-facing half of a tool whose CLI
//! runs privileged and destroys plaintext. It therefore does strictly less:
//! it only encrypts, it never decrypts, it never writes to disk, and it is not
//! linked against the filesystem module at all (`fsops` is behind the `cli`
//! feature). The uploaded file is a browser-supplied copy, so the user's
//! original always stays where it is.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Multipart, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use encrypt::crypto::{self, SecureKey};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroize;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_CSS: &str = include_str!("../web/app.css");
const APP_JS: &str = include_str!("../web/app.js");

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_MAX_UPLOAD_MB: usize = 64;
const MAX_UPLOAD_MB_CAP: usize = 512;
const DEFAULT_CONCURRENCY: usize = 2;
/// Argon2id alone costs ~64 MiB per request, so the password is bounded too
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 512;
const MAX_FILENAME_LEN: usize = 200;
/// How long a request waits for a worker slot before being turned away
const QUEUE_WAIT: Duration = Duration::from_secs(30);
/// A worker slot is held while the body is read, so a stalled client cannot
/// occupy it indefinitely
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);

struct AppState {
    /// Bounds concurrent Argon2id + encryption work; the real memory guard
    workers: Arc<Semaphore>,
    token: Option<String>,
    max_upload_bytes: usize,
}

struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = format!("{{\"error\":\"{}\"}}", self.message);
        (
            self.status,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind: String = std::env::var("ENCRYPT_WEB_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| format!("Invalid ENCRYPT_WEB_BIND value: {}", bind))?;

    if std::env::args().any(|a| a == "--healthcheck") {
        return healthcheck(addr).await;
    }

    refuse_root()?;

    let max_upload_mb = env_usize("ENCRYPT_WEB_MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB)
        .clamp(1, MAX_UPLOAD_MB_CAP);
    let concurrency = env_usize("ENCRYPT_WEB_CONCURRENCY", DEFAULT_CONCURRENCY).clamp(1, 16);

    let token = match std::env::var("ENCRYPT_WEB_TOKEN") {
        Ok(t) if !t.is_empty() => Some(t),
        _ => None,
    };

    let state = Arc::new(AppState {
        workers: Arc::new(Semaphore::new(concurrency)),
        token,
        max_upload_bytes: max_upload_mb * 1024 * 1024,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/config", get(config))
        .route("/api/encrypt", post(encrypt_handler))
        .layer(DefaultBodyLimit::max(max_upload_mb * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), request_guard))
        .with_state(state.clone());

    let listener = TcpListener::bind(addr).await?;

    eprintln!(
        "encrypt-web listening on http://{} (uid {}, max upload {} MiB, workers {}, token auth {})",
        addr,
        current_uid(),
        max_upload_mb,
        concurrency,
        if state.token.is_some() { "on" } else { "off" }
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// The CLI half of this project is meant to run privileged; the listener is not.
fn refuse_root() -> Result<(), Box<dyn std::error::Error>> {
    if current_uid() == 0 && std::env::var("ENCRYPT_WEB_ALLOW_ROOT").as_deref() != Ok("1") {
        return Err("Refusing to run as root. Run as an unprivileged user, or set \
                    ENCRYPT_WEB_ALLOW_ROOT=1 if you fully understand the consequences."
            .into());
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // Safety: geteuid is always successful and takes no arguments
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    u32::MAX
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}

async fn healthcheck(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A bind on all interfaces is still reachable from inside the container
    let target = if addr.ip().is_unspecified() {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    };

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(target),
    )
    .await??;
    stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await?;
    if buf[..n].starts_with(b"HTTP/1.1 200") || buf[..n].starts_with(b"HTTP/1.0 200") {
        Ok(())
    } else {
        Err("healthcheck failed".into())
    }
}

/// Rejects cross-origin writes, stamps the security headers, and logs the
/// request line. Filenames and passwords live in the body and are never logged.
async fn request_guard(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let request_bytes = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let response = handle(state, req, next).await;

    eprintln!(
        "{} {} -> {} in={}B {}ms",
        method,
        path,
        response.status().as_u16(),
        request_bytes,
        started.elapsed().as_millis()
    );

    response
}

async fn handle(state: Arc<AppState>, req: Request, next: Next) -> Response {
    if req.method() == Method::POST {
        if let Err(e) = check_same_origin(req.headers()) {
            return e.into_response();
        }
        if let Some(expected) = state.token.as_deref() {
            let provided = req
                .headers()
                .get("x-encrypt-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                return ApiError::new(StatusCode::UNAUTHORIZED, "Invalid or missing token")
                    .into_response();
            }
        }
    }

    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    for (name, value) in security_headers() {
        headers.insert(name, value);
    }
    response
}

fn security_headers() -> Vec<(HeaderName, HeaderValue)> {
    let pairs: [(HeaderName, &str); 8] = [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("permissions-policy"),
            "geolocation=(), camera=(), microphone=(), interest-cohort=()",
        ),
    ];

    pairs
        .into_iter()
        .filter_map(|(name, value)| HeaderValue::from_str(value).ok().map(|v| (name, v)))
        .collect()
}

/// Blocks drive-by uploads from other pages: a cross-site POST never reaches the cipher.
fn check_same_origin(headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site != "same-origin" && site != "none" {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Cross-origin requests are not allowed",
            ));
        }
    }

    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let origin_host = origin
            .split("://")
            .nth(1)
            .map(|rest| rest.trim_end_matches('/'))
            .unwrap_or("");
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if origin_host.is_empty() || origin_host != host {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Cross-origin requests are not allowed",
            ));
        }
    }

    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

/// Lets the page reject oversized files before starting a doomed upload: the
/// body limit fires mid-stream, which browsers report as a bare network error.
async fn config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        format!(
            "{{\"max_upload_bytes\":{},\"min_password_length\":{}}}",
            state.max_upload_bytes, MIN_PASSWORD_LEN
        ),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn encrypt_handler(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    // The permit is taken before the body is buffered, so peak memory stays
    // bounded by concurrency * upload limit rather than by the client count
    let permit = tokio::time::timeout(QUEUE_WAIT, state.workers.clone().acquire_owned())
        .await
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Server busy, retry shortly"))?
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Server is shutting down"))?;

    let (password, filename, data) = tokio::time::timeout(UPLOAD_TIMEOUT, read_upload(multipart))
        .await
        .map_err(|_| ApiError::new(StatusCode::REQUEST_TIMEOUT, "Upload timed out"))??;

    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut password = password;
        let result = encrypt_in_memory(&password, &filename, &data);
        password.zeroize();
        result
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Encryption task failed"))?;

    let (ciphertext, protected_key) = outcome
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed"))?;

    // Ciphertext and key names share a stem so the two downloads stay paired
    let stem = crypto::random_name(16);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}.enc\"", stem))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed"))?,
    );
    headers.insert(
        HeaderName::from_static("x-encrypt-key"),
        HeaderValue::from_str(&BASE64.encode(&protected_key))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed"))?,
    );
    headers.insert(
        HeaderName::from_static("x-encrypt-key-filename"),
        HeaderValue::from_str(&format!("{}.key", stem))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed"))?,
    );

    Ok((headers, ciphertext).into_response())
}

async fn read_upload(mut multipart: Multipart) -> Result<(String, String, Bytes), ApiError> {
    let mut password: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut data: Option<Bytes> = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(e) => {
                let status = e.status();
                return Err(ApiError::new(
                    status,
                    if status == StatusCode::PAYLOAD_TOO_LARGE {
                        "File exceeds the configured upload limit"
                    } else {
                        "Malformed upload"
                    },
                ));
            }
        };

        let name = field.name().unwrap_or_default().to_string();
        let claimed_filename = field.file_name().map(|s| s.to_string());

        match name.as_str() {
            "password" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Malformed upload"))?;
                password = Some(text);
            }
            "file" => {
                let bytes = field.bytes().await.map_err(|e| {
                    let status = e.status();
                    ApiError::new(
                        status,
                        if status == StatusCode::PAYLOAD_TOO_LARGE {
                            "File exceeds the configured upload limit"
                        } else {
                            "Malformed upload"
                        },
                    )
                })?;
                filename = claimed_filename;
                data = Some(bytes);
            }
            _ => {
                // Unknown fields are drained, never interpreted
                let _ = field.bytes().await;
            }
        }
    }

    let password = password.ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Password is required"))?;
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Password must be at least 12 characters",
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Password is too long"));
    }

    let data = data.ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "File is required"))?;
    if data.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "File is empty"));
    }

    let filename = sanitize_filename(filename.as_deref().unwrap_or(""))
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid file name"))?;

    Ok((password, filename, data))
}

fn encrypt_in_memory(
    password: &str,
    filename: &str,
    data: &[u8],
) -> crypto::Result<(Vec<u8>, Vec<u8>)> {
    let master_key = SecureKey::generate();
    let protected_key = crypto::protect_key_with_password(&master_key, password)?;

    let mut ciphertext = Vec::with_capacity(data.len() + 4096);
    crypto::encrypt_stream(
        &mut &data[..],
        &mut ciphertext,
        &master_key,
        filename,
        &mut |_| {},
    )?;

    Ok((ciphertext, protected_key))
}

/// The name is only ever stored inside the encrypted metadata, never used as a
/// path, but it is still reduced to a harmless basename before it goes anywhere.
fn sanitize_filename(raw: &str) -> Option<String> {
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('.');

    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FILENAME_LEN)
        .collect();

    let cleaned = cleaned.trim().to_string();

    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return Some("upload.bin".to_string());
    }

    Some(cleaned)
}
