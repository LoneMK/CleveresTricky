use rand_distr::{LogNormal, Distribution};
use std::time::Duration;
use std::thread;
use log::debug;

pub struct TeeLatencySimulator {
    dist: LogNormal<f64>,
}

impl TeeLatencySimulator {
    pub fn new() -> Self {
        // Log-normal distribution parameters matching realistic TEE/StrongBox latency
        // Mean ~ 150ms, with a tail up to 300ms
        // These parameters can be tuned. Normal log-normal params:
        // mu = 4.9, sigma = 0.3 (roughly means around 134ms)
        let dist = LogNormal::new(4.9, 0.3).unwrap();
        Self { dist }
    }

    pub fn emulate_crypto_latency(&self) {
        let mut rng = rand::thread_rng();
        let delay_ms = self.dist.sample(&mut rng);
        
        // Cap the delay to avoid watchdog timeouts (e.g., max 500ms)
        // and ensure a minimum latency of 80ms.
        let delay_ms = delay_ms.clamp(80.0, 500.0) as u64;
        
        debug!("TeeLatencySimulator: Injecting {} ms delay to emulate TEE crypto", delay_ms);
        thread::sleep(Duration::from_millis(delay_ms));
    }
}
