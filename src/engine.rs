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
        }
    }

    pub fn inspect(&self, req: &Request) -> Verdict {
        if req.headers.contains_key("Content-Length")
            && req.headers.contains_key("Transfer-Encoding")
        {
            return Verdict::Block("Smuggling Attempt: CL and TE headers present".to_string());
        }

        if !req.headers.contains_key("Host") {
            return Verdict::Block("Protocol Anomaly: Missing Host Header".to_string());
        }

        let normalize = |input: &str| -> String {
            let mut decoded = input.to_string();
            let mut loop_count = 0;

            loop {
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
            decoded.to_lowercase()
        };

        let clean_path = normalize(&req.path);
        let clean_body = normalize(&req.body);

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
