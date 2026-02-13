use crate::http::Request;

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
                "DROP TABLE",
                "OR 1=1",
                "UNION SELECT",
                "--",
                "Sleep(",
                "pg_sleep",
                "WAITFOR DELAY",
            ],
            xss_signatures: vec![
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "alert(",
                "document.cookie",
            ],
            traversal_signatures: vec!["../", "..\\", "/etc/passwd", "C:\\Windows", "%2e%2e%2f"],
        }
    }

    pub fn inspect(&self, req: &Request) -> Verdict {
        if !req.headers.contains_key("Host") {
            return Verdict::Block("Protocol Anomaly: Missing Host Header".to_string());
        }

        if req.method == "TRACE" || req.method == "TRACK" {
            return Verdict::Block("Method Not Allowed: TRACE/TRACK".to_string());
        }

        let payload_check = format!("{} {}", req.path, req.body).to_lowercase();

        for sig in &self.sqli_signatures {
            if payload_check.contains(&sig.to_lowercase()) {
                return Verdict::Block(format!("SQL Injection Detected: Found '{}'", sig));
            }
        }

        for sig in &self.xss_signatures {
            if payload_check.contains(&sig.to_lowercase()) {
                return Verdict::Block(format!("XSS Detected: Found '{}'", sig));
            }
        }

        for sig in &self.traversal_signatures {
            if payload_check.contains(&sig.to_lowercase()) {
                return Verdict::Block(format!("Path Traversal Detected: Found '{}'", sig));
            }
        }

        Verdict::Allow
    }
}
