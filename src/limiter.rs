use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_update: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,

    rate: f64,
    capacity: f64,
}

impl RateLimiter {
    pub fn new(rate: f64, capacity: f64) -> Self {
        RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            rate,
            capacity,
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap();

        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last_update: Instant::now(),
        });

        let now = Instant::now();
        let duration = now.duration_since(bucket.last_update).as_secs_f64();

        let new_tokens = duration * self.rate;

        if new_tokens > 0.0 {
            bucket.tokens = (bucket.tokens + new_tokens).min(self.capacity);
            bucket.last_update = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_logic() {
        let limiter = RateLimiter::new(1.0, 3.0);
        let ip = "127.0.0.1".parse().unwrap();

        assert_eq!(limiter.check(ip), true, "Req 1 deve passar");
        assert_eq!(limiter.check(ip), true, "Req 2 deve passar");
        assert_eq!(limiter.check(ip), true, "Req 3 deve passar");

        assert_eq!(
            limiter.check(ip),
            false,
            "Req 4 deve ser bloqueada (butcketvazio)"
        );

        thread::sleep(Duration::from_millis(1500));

        assert_eq!(limiter.check(ip), true, "Req 5 deve passar após espera");
        assert_eq!(
            limiter.check(ip),
            false,
            "Req 6 deve bloquear (só tinha 1.5 tokens)"
        );
    }
}
