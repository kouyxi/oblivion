use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use tracing_subscriber;

mod engine;
mod http;
mod limiter;

use engine::{Verdict, WafEngine};
use http::Request;
use limiter::RateLimiter;

const LISTENER_ADDR: &str = "127.0.0.1:4000";
const UPSTREAM_ADDR: &str = "127.0.0.1:8000";
const MAX_HEADER_SIZE: usize = 8192;
const CLIENT_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

#[instrument(skip(client_stream, engine, limiter), fields(peer_addr, method, path))]
async fn handle_client(
    mut client_stream: TcpStream,
    engine: Arc<WafEngine>,
    limiter: Arc<RateLimiter>,
) {
    let peer_addr = match client_stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to get peer address: {}", e);
            return;
        }
    };

    tracing::Span::current().record("peer_addr", &tracing::field::display(peer_addr));

    if !limiter.check(peer_addr.ip()) {
        warn!("Rate limit exceeded");
        let _ = client_stream
            .write_all(
                b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\n\r\nRate Limit Exceeded",
            )
            .await;
        return;
    }

    let mut accumulator: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    let request_str: String;

    loop {
        let read_result = timeout(CLIENT_HEADER_TIMEOUT, client_stream.read(&mut buffer)).await;

        let n = match read_result {
            Err(_) => {
                warn!("Connection dropped: Client header timeout (Slowloris protection)");
                return; // Corta a conexão imediatamente
            }
            Ok(io_result) => match io_result {
                Ok(0) => return, // Cliente fechou conexão
                Ok(n) => n,
                Err(e) => {
                    debug!("Socket read error: {}", e);
                    return;
                }
            },
        };

        if accumulator.len() + n > MAX_HEADER_SIZE {
            warn!("DoS attempt: Header size exceeded limit");
            return;
        }
        accumulator.extend_from_slice(&buffer[..n]);

        if let Some(i) = accumulator.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_len = i + 4;
            request_str = String::from_utf8_lossy(&accumulator[..header_len]).to_string();
            break;
        }
    }

    match Request::parse(&request_str) {
        Ok(req) => {
            tracing::Span::current().record("method", &req.method);
            tracing::Span::current().record("path", &req.path);

            match engine.inspect(&req) {
                Verdict::Allow => {
                    info!("Proxying request");
                }
                Verdict::Block(reason) => {
                    warn!(reason = %reason, "Blocked malicious request"); // Log Amarelo/Vermelho
                    let error_msg = format!("HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: {}", reason);
                    let _ = client_stream.write_all(error_msg.as_bytes()).await;
                    return;
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Invalid HTTP Protocol");
            let _ = client_stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid HTTP Protocol")
                .await;
            return;
        }
    }

    let connect_result = timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(UPSTREAM_ADDR)).await;

    match connect_result {
        Err(_) => {
            error!(upstream = UPSTREAM_ADDR, "Upstream connection timeout");
            let _ = client_stream
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nUpstream Unresponsive")
                .await;
        }
        Ok(io_result) => match io_result {
            Ok(mut upstream_stream) => {
                if let Err(e) = upstream_stream.write_all(&accumulator).await {
                    error!(error = %e, "Failed to send headers to upstream");
                    return;
                }

                let (mut client_read, mut client_write) = client_stream.split();
                let (mut upstream_read, mut upstream_write) = upstream_stream.split();

                let mut client_limited = client_read.take(MAX_BODY_SIZE);

                let result = tokio::try_join!(
                    tokio::io::copy(&mut client_limited, &mut upstream_write),
                    tokio::io::copy(&mut upstream_read, &mut client_write)
                );
            }
            Err(e) => {
                error!(upstream = UPSTREAM_ADDR, error = %e, "Upstream is DOWN");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\nUpstream Unreachable")
                    .await;
            }
        },
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listener = TcpListener::bind(LISTENER_ADDR).await?;

    info!(
        "🛡️  OBLIVION PROXY running in {} -> Protecting {}",
        LISTENER_ADDR, UPSTREAM_ADDR
    );

    let engine = Arc::new(WafEngine::new());
    let limiter = Arc::new(RateLimiter::new(5.0, 10.0));

    loop {
        let (stream, _) = listener.accept().await?;
        let engine_clone = engine.clone();
        let limiter_clone = limiter.clone();

        tokio::spawn(async move {
            handle_client(stream, engine_clone, limiter_clone).await;
        });
    }
}
