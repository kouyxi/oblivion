use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SHARD_COUNT: usize = 16;

struct Bucket {
    tokens: f64,
    last_update: Instant,
}

pub struct RateLimiter {
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
    rate: f64,
    capacity: f64,
}

impl RateLimiter {
    pub fn new(rate: f64, capacity: f64) -> Arc<Self> {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(HashMap::new()));
        }

        let limiter = Arc::new(RateLimiter {
            shards,
            rate,
            capacity,
        });

        let limiter_clone = limiter.clone();
        tokio::spawn(async move {
            loop {
                // Roda a cada 60 segundos
                tokio::time::sleep(Duration::from_secs(60)).await;
                limiter_clone.cleanup();
            }
        });

        limiter
    }

    fn get_shard_index(&self, ip: IpAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % SHARD_COUNT
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let shard_idx = self.get_shard_index(ip);
        let mut shard = self.shards[shard_idx].lock().unwrap();

        let bucket = shard.entry(ip).or_insert(Bucket {
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

    fn cleanup(&self) {
        let threshold = Duration::from_secs(600); // 10 minutos
        let now = Instant::now();
        let mut removed_count = 0;

        for shard in &self.shards {
            let mut map = shard.lock().unwrap();

            let len_before = map.len();
            map.retain(|_, bucket| now.duration_since(bucket.last_update) < threshold);
            removed_count += len_before - map.len();
        }

        if removed_count > 0 {
            println!(
                "[GC] Rate Limiter cleanup: removed {} inactive IPs",
                removed_count
            );
        }
    }
}
