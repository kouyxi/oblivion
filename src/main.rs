use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const SERVER_ADDR: &str = "127.0.0.1:4000";
const SCRATCH_BUFFER_SIZE: usize = 512;
const MAX_HEADER_SIZE: usize = 8192;
use std::collections::HashMap;

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

        let request_line = lines.next().ok_or("Empty request")?;
        let mut parts = request_line.split_whitespace();

        let method = parts.next().ok_or("Invalid Method")?.to_string();
        let path = parts.next().ok_or("Invalid Path")?.to_string();
        let version = parts.next().ok_or("Invalid Version")?.to_string();

        let mut headers = HashMap::new();
        let mut body_start_index = 0;

        for line in lines {
            if line.is_empty() {
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let body = if let Some(idx) = raw_request.find("\r\n\r\n") {
            // Pula os 4 bytes do delimitador e pega o resto
            raw_request[idx + 4..].to_string()
        } else {
            String::new() // Sem body
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

fn handle_client(mut stream: TcpStream) {
    let peer_addr = stream.peer_addr().unwrap();

    let mut accumulator: Vec<u8> = Vec::new();

    let mut buffer = [0u8; SCRATCH_BUFFER_SIZE];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("[INFO] {} - Connection closed by client.", peer_addr);
                break;
            }
            Ok(n) => {
                if accumulator.len() + n > MAX_HEADER_SIZE {
                    eprintln!("[WARN] {} - Potential DoS attack detected (Header overflow). Dropping connection.", peer_addr);
                    return;
                }

                accumulator.extend_from_slice(&buffer[..n]);

                let header_end_sequence = b"\r\n\r\n";

                if let Some(i) = accumulator
                    .windows(4)
                    .position(|window| window == header_end_sequence)
                {
                    let header_len = i + 4;
                    let request_bytes = &accumulator; // Pegamos TUDO (Headers + Body se tiver)
                    let request_str = String::from_utf8_lossy(request_bytes);

                    match Request::parse(&request_str) {
                        Ok(req) => {
                            println!("[DEBUG] Parsed Request: {:?}", req);

                            if req.path.contains("DROP") || req.body.contains("DROP") {
                                println!(
                                    "[BLOCK] {} - SQL Injection attempt in Path/Body",
                                    peer_addr
                                );
                                let _ = stream.write_all(
                                    b"HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: SQLi detected.",
                                );
                                break;
                            }

                            if req.path.ends_with(".env") || req.path.contains("/config") {
                                println!("[BLOCK] {} - Sensitive file access attempt", peer_addr);
                                let _ = stream.write_all(
                                    b"HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: Sensitive file.",
                                );
                                break;
                            }

                            if let Some(ua) = req.headers.get("User-Agent") {
                                if ua.contains("sqlmap") || ua.contains("nikto") {
                                    println!("[BLOCK] {} - Automated Scanner detected", peer_addr);
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 403 Forbidden\r\n\r\nBLOCK: Bot detected.",
                                    );
                                    break;
                                }
                            }

                            let response =
                                "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello Oblivion";
                            let _ = stream.write_all(response.as_bytes());
                            break;
                        }
                        Err(e) => {
                            eprintln!("[ERROR] Failed to parse HTTP: {}", e);
                            // Bad Request
                            let _ =
                                stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid HTTP");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[ERROR] {} - Socket read failure: {}", peer_addr, e);
                break;
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(SERVER_ADDR)?;

    println!("🛡️  OBLIVION WAF (Phase 02) running on {}", SERVER_ADDR);
    println!("[INFO] Waiting for connections...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("[ERROR] Connection failed: {}", e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

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
