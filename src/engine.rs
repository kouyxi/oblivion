use crate::http::Request;
use percent_encoding::percent_decode_str;

#[derive(Debug)]
pub enum Verdict {
    Allow,
    Block(String),
}

pub struct WafEngine {
    sqli_signatures: Vec<&'static str>,
    xss_signatures: Vec<&'static str>,
    traversal_signatures: Vec<&'static str>,
    allowed_methods: Vec<&'static str>,
}

impl WafEngine {
    pub fn new() -> Self {
        WafEngine {
            sqli_signatures: vec![
                "drop table",
                "or 1=1",
                "union select",
                "--",
                "sleep(",
                "pg_sleep",
                "waitfor delay",
                "select * from",
            ],
            xss_signatures: vec![
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "alert(",
                "document.cookie",
                "vbscript:",
            ],
            traversal_signatures: vec![
                "../",
                "..\\",
                "/etc/passwd",
                "c:\\windows",
                "%2e%2e%2f",
                ".env",
                "config.php",
            ],
            allowed_methods: vec!["GET", "POST", "HEAD"],
        }
    }

    pub fn inspect(&self, req: &Request) -> Verdict {
        if !self.allowed_methods.contains(&req.method.as_str()) {
            return Verdict::Block(format!("Method Not Allowed: {}", req.method));
        }

        if req.headers.contains_key("Content-Length")
            && req.headers.contains_key("Transfer-Encoding")
        {
            return Verdict::Block("Smuggling Attempt: CL and TE headers present".to_string());
        }

        if !req.headers.contains_key("Host") {
            return Verdict::Block("Protocol Anomaly: Missing Host Header".to_string());
        }

        let normalize = |input: &str| -> Result<String, String> {
            let mut decoded = input.to_string();
            let mut loop_count = 0;

            loop {
                if decoded.contains('\0') {
                    return Err("Null Byte Injection Detected".to_string());
                }

                let with_spaces = decoded.replace('+', " ");
                match percent_decode_str(&with_spaces).decode_utf8() {
                    Ok(d) => {
                        let new_val = d.to_string();
                        if new_val == decoded || loop_count > 5 {
                            break;
                        }
                        decoded = new_val;
                    }
                    Err(_) => break,
                }
                loop_count += 1;
            }
            Ok(decoded.to_lowercase())
        };

        let clean_path = match normalize(&req.path) {
            Ok(s) => s,
            Err(reason) => return Verdict::Block(reason),
        };

        let clean_body = match normalize(&req.body) {
            Ok(s) => s,
            Err(reason) => return Verdict::Block(reason),
        };

        if clean_path.contains('\r') || clean_path.contains('\n') {
            return Verdict::Block("CRLF Injection Detected".to_string());
        }

        let payload_check = format!("{} {}", clean_path, clean_body);

        for sig in &self.sqli_signatures {
            if payload_check.contains(sig) {
                return Verdict::Block(format!("SQL Injection: '{}'", sig));
            }
        }
        for sig in &self.xss_signatures {
            if payload_check.contains(sig) {
                return Verdict::Block(format!("XSS: '{}'", sig));
            }
        }
        for sig in &self.traversal_signatures {
            if payload_check.contains(sig) {
                return Verdict::Block(format!("Path Traversal: '{}'", sig));
            }
        }

        Verdict::Allow
    }
}
