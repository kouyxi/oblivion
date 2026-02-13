use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod engine;
mod http;

use engine::{Verdict, WafEngine};
use http::Request;

const LISTENER_ADDR: &str = "127.0.0.1:4000";
const UPSTREAM_ADDR: &str = "127.0.0.1:8000";
const MAX_HEADER_SIZE: usize = 8192;

async fn handle_client(mut client_stream: TcpStream, engine: Arc<WafEngine>) {
    let peer_addr = match client_stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let mut accumulator: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    let request_str: String;

    loop {
        let n = match client_stream.read(&mut buffer).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };

        if accumulator.len() + n > MAX_HEADER_SIZE {
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
        Ok(req) => match engine.inspect(&req) {
            Verdict::Allow => {
                println!("[PROXY] {} -> {} {}", peer_addr, req.method, req.path);
            }
            Verdict::Block(reason) => {
                println!("[BLOCK] {} - Reason: {}", peer_addr, reason);
                let error_msg = format!("HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: {}", reason);
                let _ = client_stream.write_all(error_msg.as_bytes()).await;
                return;
            }
        },
        Err(e) => {
            eprintln!("[ERROR] {} - Invalid HTTP: {}", peer_addr, e);
            let _ = client_stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid HTTP Protocol")
                .await;
            return;
        }
    }

    match TcpStream::connect(UPSTREAM_ADDR).await {
        Ok(mut upstream_stream) => {
            if let Err(_) = upstream_stream.write_all(&accumulator).await {
                return;
            }

            let (mut cr, mut cw) = client_stream.split();
            let (mut ur, mut uw) = upstream_stream.split();

            let _ = tokio::try_join!(
                tokio::io::copy(&mut cr, &mut uw),
                tokio::io::copy(&mut ur, &mut cw)
            );
        }
        Err(e) => {
            eprintln!("[ERROR] Upstream Down: {}", e);
            let _ = client_stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\nUpstream Unreachable")
                .await;
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(LISTENER_ADDR).await?;
    println!(
        "🛡️  OBLIVION PROXY running in {} -> Protecting {}",
        LISTENER_ADDR, UPSTREAM_ADDR
    );

    let engine = Arc::new(WafEngine::new());

    loop {
        let (stream, _) = listener.accept().await?;
        let engine_clone = engine.clone();

        tokio::spawn(async move {
            handle_client(stream, engine_clone).await;
        });
    }
}
