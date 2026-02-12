//! Real-time Telemetry/Data Stream Client Template
//!
//! Simulates a sensor source sending high-frequency data to the telemetry server.
//! Can also act as a subscriber to receive data from other sources.
//!
//! # Running
//!
//! First, start the server:
//! ```bash
//! cargo run --example telemetry_server --features dev-certs
//! ```
//!
//! Then run one or more clients:
//! ```bash
//! cargo run --example telemetry_client --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example telemetry_client --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        use fastnet::{SecureSocket, SecureEvent};

        const TYPE_HEARTBEAT: u8 = 0x01;
        const TYPE_SENSOR: u8 = 0x02;
        const TYPE_ALERT: u8 = 0x03;
        const TYPE_SUBSCRIBE: u8 = 0x10;

        fn now_ms() -> u64 {
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
        }

        fn build_telemetry(msg_type: u8, payload: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(9 + payload.len());
            buf.push(msg_type);
            buf.extend_from_slice(&now_ms().to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        }

        fn build_sensor_reading(sensor_id: u16, value: f32) -> Vec<u8> {
            let mut payload = Vec::with_capacity(6);
            payload.extend_from_slice(&sensor_id.to_le_bytes());
            payload.extend_from_slice(&value.to_le_bytes());
            build_telemetry(TYPE_SENSOR, &payload)
        }

        println!("╔═══════════════════════════════════════╗");
        println!("║    FastNet Telemetry Stream Client    ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let server_addr = "127.0.0.1:9002".parse().unwrap();
        println!("Connecting to {}...", server_addr);

        let mut client = SecureSocket::connect(server_addr).await?;

        let peer_id = 'wait: loop {
            for event in client.poll().await? {
                if let SecureEvent::Connected(id) = event {
                    break 'wait id;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        println!("Connected as peer {}\n", peer_id);

        // Subscribe to receive data from other sources
        let sub_msg = build_telemetry(TYPE_SUBSCRIBE, b"");
        client.send(peer_id, 0, sub_msg).await?;

        // Simulate sending sensor data at 10 Hz
        let mut tick: u64 = 0;
        let mut last_heartbeat = std::time::Instant::now();

        loop {
            // Send sensor readings on unreliable channel (channel 1) - high frequency
            let temperature = 20.0 + (tick as f32 * 0.1).sin() * 5.0;
            let humidity = 60.0 + (tick as f32 * 0.05).cos() * 15.0;

            let temp_data = build_sensor_reading(1, temperature);
            client.send(peer_id, 1, temp_data).await?;

            let humidity_data = build_sensor_reading(2, humidity);
            client.send(peer_id, 1, humidity_data).await?;

            // Send heartbeat every 5 seconds on reliable channel
            if last_heartbeat.elapsed() > Duration::from_secs(5) {
                let hb = build_telemetry(TYPE_HEARTBEAT, b"");
                client.send(peer_id, 0, hb).await?;
                last_heartbeat = std::time::Instant::now();
            }

            // Simulate alert on threshold
            if temperature > 24.0 && tick % 50 == 0 {
                let alert = build_telemetry(TYPE_ALERT, b"Temperature above threshold!");
                client.send(peer_id, 2, alert).await?;
                println!("[!] Sent temperature alert");
            }

            // Poll for incoming data (from other sources via server)
            for event in client.poll().await? {
                match event {
                    SecureEvent::Data(_, channel, data) => {
                        if data.len() >= 9 {
                            let msg_type = data[0];
                            match msg_type {
                                TYPE_SENSOR if data.len() >= 15 => {
                                    let sensor_id = u16::from_le_bytes([data[9], data[10]]);
                                    let value = f32::from_le_bytes(data[11..15].try_into().unwrap());
                                    println!("  [recv] sensor {} = {:.2} (ch={})", sensor_id, value, channel);
                                }
                                TYPE_ALERT => {
                                    let text = String::from_utf8_lossy(&data[9..]);
                                    println!("  [recv] ALERT: {}", text);
                                }
                                _ => {}
                            }
                        }
                    }
                    SecureEvent::Disconnected(_) => {
                        println!("Server disconnected.");
                        return Ok(());
                    }
                    _ => {}
                }
            }

            tick += 1;
            if tick % 10 == 0 {
                println!("[tick {}] temp={:.1}C humidity={:.1}%", tick, temperature, humidity);
            }

            // 10 Hz update rate
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
