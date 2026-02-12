//! Real-time Telemetry/Data Stream Server Template
//!
//! An encrypted server that receives real-time data streams from multiple sources.
//! Ideal for IoT sensors, monitoring dashboards, stock tickers, or any high-frequency data.
//!
//! # Protocol
//! - Channel 0 (ReliableOrdered): Control messages, subscriptions, alerts
//! - Channel 1 (Unreliable): High-frequency sensor/telemetry data (drop-tolerant)
//! - Channel 2 (Reliable): Important events, logs
//!
//! # Data Format
//! Simple binary: [type:1][timestamp:8][payload:N]
//!
//! # Running
//!
//! ```bash
//! cargo run --example telemetry_server --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example telemetry_server --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use std::time::{SystemTime, UNIX_EPOCH};
        use fastnet::{SecureSocket, SecureEvent};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;

        // --- Telemetry data types ---
        const TYPE_HEARTBEAT: u8 = 0x01;
        const TYPE_SENSOR: u8 = 0x02;
        const TYPE_ALERT: u8 = 0x03;
        const TYPE_LOG: u8 = 0x04;
        const TYPE_SUBSCRIBE: u8 = 0x10;

        fn now_ms() -> u64 {
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
        }

        fn parse_telemetry(data: &[u8]) -> Option<(u8, u64, &[u8])> {
            if data.len() < 9 { return None; }
            let msg_type = data[0];
            let timestamp = u64::from_le_bytes(data[1..9].try_into().ok()?);
            let payload = &data[9..];
            Some((msg_type, timestamp, payload))
        }

        fn build_telemetry(msg_type: u8, payload: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(9 + payload.len());
            buf.push(msg_type);
            buf.extend_from_slice(&now_ms().to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        }

        println!("╔═══════════════════════════════════════╗");
        println!("║    FastNet Telemetry Stream Server    ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;

        println!("Telemetry server listening:");
        println!("  UDP: {}  |  TCP: {}", udp_addr, tcp_addr);
        println!("Channels: 0=Control, 1=Sensors(unreliable), 2=Events(reliable)");
        println!();

        // Track sources and their last data
        let mut sources: HashMap<u16, String> = HashMap::new();
        let mut packet_count: HashMap<u16, u64> = HashMap::new();

        // Track subscribers (peers that want to receive data from sources)
        let mut subscribers: Vec<u16> = Vec::new();

        loop {
            let events = server.poll().await?;
            let mut forwards: Vec<(u16, u8, Vec<u8>)> = Vec::new();

            for event in &events {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        println!("[+] Source/subscriber {} connected", peer_id);
                        sources.insert(*peer_id, format!("source_{}", peer_id));
                        packet_count.insert(*peer_id, 0);
                    }
                    SecureEvent::Data(peer_id, channel, data) => {
                        *packet_count.entry(*peer_id).or_insert(0) += 1;

                        if let Some((msg_type, timestamp, payload)) = parse_telemetry(data) {
                            let source = sources.get(peer_id).cloned()
                                .unwrap_or_else(|| format!("unknown_{}", peer_id));
                            let count = packet_count.get(peer_id).unwrap_or(&0);

                            match msg_type {
                                TYPE_HEARTBEAT => {
                                    println!("[♥] {} heartbeat (#{}, ch={})", source, count, channel);
                                }
                                TYPE_SENSOR => {
                                    // Parse sensor reading: [sensor_id:2][value:4]
                                    if payload.len() >= 6 {
                                        let sensor_id = u16::from_le_bytes([payload[0], payload[1]]);
                                        let value = f32::from_le_bytes(payload[2..6].try_into().unwrap());
                                        println!("[📊] {} sensor {} = {:.2} (ts={}, ch={})",
                                                 source, sensor_id, value, timestamp, channel);
                                    }
                                    // Forward to all subscribers
                                    for &sub_id in &subscribers {
                                        if sub_id != *peer_id {
                                            forwards.push((sub_id, 1, data.clone()));
                                        }
                                    }
                                }
                                TYPE_ALERT => {
                                    let alert_text = String::from_utf8_lossy(payload);
                                    println!("[⚠️] ALERT from {}: {}", source, alert_text);
                                    // Forward alerts on reliable channel to all subscribers
                                    for &sub_id in &subscribers {
                                        if sub_id != *peer_id {
                                            forwards.push((sub_id, 2, data.clone()));
                                        }
                                    }
                                }
                                TYPE_LOG => {
                                    let log_text = String::from_utf8_lossy(payload);
                                    println!("[📝] {} log: {}", source, log_text);
                                }
                                TYPE_SUBSCRIBE => {
                                    println!("[*] Peer {} subscribed to data stream", peer_id);
                                    if !subscribers.contains(peer_id) {
                                        subscribers.push(*peer_id);
                                    }
                                    let ack = build_telemetry(TYPE_SUBSCRIBE, b"OK");
                                    forwards.push((*peer_id, 0, ack));
                                }
                                _ => {
                                    println!("[?] {} unknown type 0x{:02x} ({} bytes)",
                                             source, msg_type, payload.len());
                                }
                            }
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        let name = sources.remove(peer_id).unwrap_or_default();
                        let count = packet_count.remove(peer_id).unwrap_or(0);
                        subscribers.retain(|&id| id != *peer_id);
                        println!("[-] {} disconnected (received {} packets)", name, count);
                    }
                }
            }

            for (peer_id, channel, data) in forwards {
                let _ = server.send(peer_id, channel, data).await;
            }
        }
    }
}
