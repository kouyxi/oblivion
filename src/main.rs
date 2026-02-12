use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Traits para read/write assíncronos
use tokio::net::{TcpListener, TcpStream};

const SERVER_ADDR: &str = "127.0.0.1:4000";
const SCRATCH_BUFFER_SIZE: usize = 512;
const MAX_HEADER_SIZE: usize = 8192;

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
}

impl Request {
    fn parse(raw_request: &str) -> Result<Self, String> {
        let mut lines = raw_request.lines();

        let req_line = lines.next().ok_or("Empty request")?;
        let mut parts = req_line.split_whitespace();
        let method = parts.next().ok_or("Method")?.to_string();
        let path = parts.next().ok_or("Path")?.to_string();
        let version = parts.next().ok_or("Version")?.to_string();

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_string(), v.trim().to_string());
            }
        }

        let body = if let Some(idx) = raw_request.find("\r\n\r\n") {
            raw_request[idx + 4..].to_string()
        } else {
            String::new()
        };

        Ok(Request {
            method,
            path,
            version,
            headers,
            body,
        })
    }
}

async fn handle_client(mut stream: TcpStream) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let mut accumulator: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if accumulator.len() + n > MAX_HEADER_SIZE {
                    return;
                }

                accumulator.extend_from_slice(&buffer[..n]);

                if let Some(i) = accumulator.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_len = i + 4;
                    let request_str = String::from_utf8_lossy(&accumulator[..header_len]);

                    match Request::parse(&request_str) {
                        Ok(req) => {
                            println!(
                                "[DEBUG] Async Req from {}: {} {}",
                                peer_addr, req.method, req.path
                            );

                            if req.path.contains("DROP") || req.body.contains("DROP") {
                                println!("[BLOCK] {} - SQLi detected", peer_addr);
                                let _ = stream
                                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: SQLi")
                                    .await;
                                break;
                            }

                            if let Some(ua) = req.headers.get("User-Agent") {
                                if ua.contains("sqlmap") {
                                    let _ = stream
                                        .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: Bot")
                                        .await;
                                    break;
                                }
                            }

                            let response =
                                "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nAsync Oblivion!";
                            // write_all().await garante que tudo foi enviado sem bloquear
                            let _ = stream.write_all(response.as_bytes()).await;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
            Err(_) => break,
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(SERVER_ADDR).await?;

    println!("⚡ OBLIVION WAF (Async Engine) rodando em {}", SERVER_ADDR);

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            handle_client(stream).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    fn spawn_server() {
        thread::spawn(|| {
            let _ = main();
        });
        thread::sleep(Duration::from_millis(100));
    }

    #[test]
    fn test_fragmented_request() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            spawn_server();
        });

        let mut client = TcpStream::connect("127.0.0.1:4000").unwrap();

        client.write_all(b"GET / HTTP/1.1\r\nHost: loc").unwrap();
        thread::sleep(Duration::from_millis(50));
        client.write_all(b"alhost\r\n\r\n").unwrap();

        let mut buffer = [0u8; 512];
        let n = client.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(response.contains("200 OK"));
        assert!(response.contains("Hello Oblivion"));
    }
}
