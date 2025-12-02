//! Latency Benchmark for FastNet
//!
//! Measures round-trip time (RTT) latency for encrypted packet transmission.
//!
//! # Running
//!
//! ```bash
//! cargo run --example benchmark --release --features dev-certs
//! ```
//!
//! # Metrics
//!
//! - **Avg**: Average RTT across all packets
//! - **P99**: 99th percentile RTT (99% of packets are faster than this)
//! - **P99.9**: 99.9th percentile RTT
//! - **Max**: Maximum RTT observed

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example benchmark --release --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::net::SocketAddr;
        use std::time::{Duration, Instant};
        use tokio::sync::mpsc;
        use fastnet::{SecureSocket, SecureEvent};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;

        const NUM_PACKETS: usize = 10_000;
        const WARMUP_PACKETS: usize = 100;
        const PACKET_SIZE: usize = 64;

        println!("╔═══════════════════════════════════════╗");
        println!("║       FastNet Latency Benchmark       ║");
        println!("╠═══════════════════════════════════════╣");
        println!("║  Packets: {:>6}                      ║", NUM_PACKETS);
        println!("║  Size:    {:>6} bytes                ║", PACKET_SIZE);
        println!("╚═══════════════════════════════════════╝");
        println!();

        // Generate certificate
        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:17777".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:17778".parse().unwrap();

        // Channel to signal server ready
        let (tx, mut rx) = mpsc::channel::<()>(1);

        // Start server
        let server_handle = tokio::spawn(async move {
            let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key)
                .await
                .expect("Failed to bind server");

            tx.send(()).await.unwrap();

            let total = NUM_PACKETS + WARMUP_PACKETS;
            let mut count = 0usize;
            loop {
                for event in server.poll().await.unwrap() {
                    match event {
                        SecureEvent::Data(peer, ch, data) => {
                            server.send(peer, ch, data).await.unwrap();
                            count += 1;
                            if count >= total {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        // Wait for server
        rx.recv().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client = SecureSocket::connect(tcp_addr).await?;
        
        // Get peer ID
        let mut peer_id = 0u16;
        for event in client.poll().await? {
            if let SecureEvent::Connected(id) = event {
                peer_id = id;
                break;
            }
        }

        if peer_id == 0 {
            eprintln!("Failed to connect");
            return Ok(());
        }

        println!("Connected! Starting benchmark...\n");

        let payload = vec![0u8; PACKET_SIZE];
        let mut latencies = Vec::with_capacity(NUM_PACKETS);

        // Warmup
        for _ in 0..WARMUP_PACKETS {
            client.send(peer_id, 0, payload.clone()).await?;
            'warmup: loop {
                for event in client.poll().await? {
                    if let SecureEvent::Data(_, _, _) = event {
                        break 'warmup;
                    }
                }
            }
        }

        // Benchmark
        for i in 0..NUM_PACKETS {
            let start = Instant::now();
            client.send(peer_id, 0, payload.clone()).await?;
            
            'recv: loop {
                for event in client.poll().await? {
                    if let SecureEvent::Data(_, _, _) = event {
                        let elapsed = start.elapsed();
                        latencies.push(elapsed);
                        break 'recv;
                    }
                }
            }

            if (i + 1) % 2000 == 0 {
                println!("  Progress: {}/{}", i + 1, NUM_PACKETS);
            }
        }

        server_handle.abort();

        // Calculate statistics
        latencies.sort();
        
        let sum: Duration = latencies.iter().sum();
        let avg = sum / latencies.len() as u32;
        let min = latencies[0];
        let max = latencies[latencies.len() - 1];
        let median = latencies[latencies.len() / 2];
        let p99 = latencies[(latencies.len() as f64 * 0.99) as usize];
        let p999 = latencies[(latencies.len() as f64 * 0.999) as usize];

        println!();
        println!("┌─────────────────────────────────────────┐");
        println!("│         Results (RTT with encryption)   │");
        println!("├─────────────────────────────────────────┤");
        println!("│  Min:      {:>10.3} µs               │", min.as_nanos() as f64 / 1000.0);
        println!("│  Avg:      {:>10.3} µs               │", avg.as_nanos() as f64 / 1000.0);
        println!("│  Median:   {:>10.3} µs               │", median.as_nanos() as f64 / 1000.0);
        println!("│  P99:      {:>10.3} µs               │", p99.as_nanos() as f64 / 1000.0);
        println!("│  P99.9:    {:>10.3} µs               │", p999.as_nanos() as f64 / 1000.0);
        println!("│  Max:      {:>10.3} µs               │", max.as_nanos() as f64 / 1000.0);
        println!("└─────────────────────────────────────────┘");

        Ok(())
    }
}
