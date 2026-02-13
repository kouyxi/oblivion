use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use tracing_subscriber;

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

mod engine;
mod http;
mod limiter;

use engine::{Verdict, WafEngine};
use http::Request;
use limiter::RateLimiter;

const LISTENER_ADDR: &str = "0.0.0.0:4433";
const UPSTREAM_ADDR: &str = "127.0.0.1:8000";
const MAX_HEADER_SIZE: usize = 8192;
const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024;

const CLIENT_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn load_tls_config() -> Arc<rustls::ServerConfig> {
    let cert_file =
        File::open("cert.pem").expect("❌ Erro: 'cert.pem' não encontrado. Gere com openssl.");
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    let key_file =
        File::open("key.pem").expect("❌ Erro: 'key.pem' não encontrado. Gere com openssl.");
    let mut key_reader = BufReader::new(key_file);
    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    let key = keys
        .first()
        .expect("❌ Erro: Nenhuma chave privada encontrada em 'key.pem'")
        .clone();

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("❌ Erro: Configuração TLS inválida");

    Arc::new(config)
}

#[instrument(skip(stream, engine), fields(peer_addr, method, path))]
async fn handle_client<S>(mut stream: S, peer_addr: SocketAddr, engine: Arc<WafEngine>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::Span::current().record("peer_addr", &tracing::field::display(peer_addr));

    let mut accumulator: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    let request_str: String;

    loop {
        let read_result = timeout(CLIENT_HEADER_TIMEOUT, stream.read(&mut buffer)).await;

        let n = match read_result {
            Err(_) => {
                warn!("Connection dropped: Client header timeout (Slowloris protection)");
                return;
            }
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Socket read error: {}", e);
                return;
            }
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
                    warn!(reason = %reason, "Blocked malicious request");
                    let msg = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\nBLOCK: {}",
                        7 + reason.len(),
                        reason
                    );
                    let _ = stream.write_all(msg.as_bytes()).await;
                    return;
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Invalid HTTP Protocol");
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid HTTP")
                .await;
            return;
        }
    }

    let connect_result = timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(UPSTREAM_ADDR)).await;

    match connect_result {
        Ok(Ok(mut upstream_stream)) => {
            if let Err(e) = upstream_stream.write_all(&accumulator).await {
                error!("Failed to send headers to upstream: {}", e);
                return;
            }

            let (mut client_read, mut client_write) = tokio::io::split(stream);
            let (mut upstream_read, mut upstream_write) = upstream_stream.split();

            let mut client_read_limited = client_read.take(MAX_BODY_SIZE);

            let result = tokio::try_join!(
                tokio::io::copy(&mut client_read_limited, &mut upstream_write),
                tokio::io::copy(&mut upstream_read, &mut client_write)
            );

            if let Err(e) = result {
                debug!("Tunnel closed: {}", e);
            }
        }
        Ok(Err(e)) => {
            error!(upstream = UPSTREAM_ADDR, error = %e, "Upstream connection failed");
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\nUpstream Error")
                .await;
        }
        Err(_) => {
            error!(upstream = UPSTREAM_ADDR, "Upstream connection timed out");
            let _ = stream
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nUpstream Timeout")
                .await;
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let tls_config = load_tls_config();
    let acceptor = TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind(LISTENER_ADDR).await?;
    info!(
        "🔐 OBLIVION WAF (HTTPS) rodando em {} -> Protegendo {}",
        LISTENER_ADDR, UPSTREAM_ADDR
    );

    let engine = Arc::new(WafEngine::new());

    let limiter = RateLimiter::new(5.0, 10.0);

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                debug!("Accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let engine = engine.clone();
        let limiter = limiter.clone();

        tokio::spawn(async move {
            if !limiter.check(peer_addr.ip()) {
                warn!("Rate limit exceeded for {}", peer_addr);
                return;
            }

            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    handle_client(tls_stream, peer_addr, engine).await;
                }
                Err(e) => {
                    debug!("TLS Handshake failed from {}: {}", peer_addr, e);
                }
            }
        });
    }
}
