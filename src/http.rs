use std::collections::HashMap;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Request {
    pub fn parse(raw_request: &str) -> Result<Self, String> {
        let mut lines = raw_request.lines();

        let req_line = lines.next().ok_or("Empty request")?;
        let mut parts = req_line.split_whitespace();
        let method = parts.next().ok_or("Method")?.to_string();
        let path = parts.next().ok_or("Path")?.to_string();
        let _version = parts.next().ok_or("Version")?;

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
            headers,
            body,
        })
    }
}
