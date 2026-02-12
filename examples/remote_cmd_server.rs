//! Remote Command Server Template
//!
//! An encrypted remote command execution server using FastNet.
//! Clients can send commands and receive their output in real-time.
//!
//! # Protocol
//! - Client sends: `CMD:<command>` or `PING`
//! - Server responds: `OUT:<output>`, `ERR:<error>`, `OK`, `PONG`
//!
//! # Security Note
//! This is a template. In production, add authentication and command whitelisting.
//!
//! # Running
//!
//! ```bash
//! cargo run --example remote_cmd_server --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example remote_cmd_server --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use fastnet::{SecureSocket, SecureEvent};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;

        println!("╔═══════════════════════════════════════╗");
        println!("║     FastNet Remote Command Server     ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:8877".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:8878".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;

        println!("Remote command server listening:");
        println!("  UDP: {}  |  TCP: {}", udp_addr, tcp_addr);
        println!();

        // Track authenticated sessions (template: all peers are trusted)
        let mut sessions: HashMap<u16, String> = HashMap::new();

        loop {
            let events = server.poll().await?;
            let mut responses: Vec<(u16, Vec<u8>)> = Vec::new();

            for event in &events {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        println!("[+] Peer {} connected", peer_id);
                        sessions.insert(*peer_id, format!("session_{}", peer_id));
                        responses.push((*peer_id, b"OK:Connected. Send CMD:<command> to execute.".to_vec()));
                    }
                    SecureEvent::Data(peer_id, _channel, data) => {
                        let request = String::from_utf8_lossy(data);
                        println!("[<] Peer {}: {}", peer_id, request);

                        if request == "PING" {
                            responses.push((*peer_id, b"PONG".to_vec()));
                        } else if let Some(cmd) = request.strip_prefix("CMD:") {
                            let cmd = cmd.trim();
                            println!("[*] Executing for peer {}: {}", peer_id, cmd);

                            // Execute command (template: using basic shell)
                            // WARNING: In production, sanitize and whitelist commands!
                            match std::process::Command::new("sh")
                                .arg("-c")
                                .arg(cmd)
                                .output()
                            {
                                Ok(output) => {
                                    let stdout = String::from_utf8_lossy(&output.stdout);
                                    let stderr = String::from_utf8_lossy(&output.stderr);

                                    if !stdout.is_empty() {
                                        let msg = format!("OUT:{}", stdout.trim_end());
                                        responses.push((*peer_id, msg.into_bytes()));
                                    }
                                    if !stderr.is_empty() {
                                        let msg = format!("ERR:{}", stderr.trim_end());
                                        responses.push((*peer_id, msg.into_bytes()));
                                    }
                                    if stdout.is_empty() && stderr.is_empty() {
                                        responses.push((*peer_id, format!("OK:exit {}", output.status.code().unwrap_or(-1)).into_bytes()));
                                    }
                                }
                                Err(e) => {
                                    let msg = format!("ERR:Failed to execute: {}", e);
                                    responses.push((*peer_id, msg.into_bytes()));
                                }
                            }
                        } else if let Some(key_value) = request.strip_prefix("SET:") {
                            // Simple key-value store example
                            if let Some((key, value)) = key_value.split_once('=') {
                                println!("[*] Peer {} SET {}={}", peer_id, key.trim(), value.trim());
                                let msg = format!("OK:SET {}={}", key.trim(), value.trim());
                                responses.push((*peer_id, msg.into_bytes()));
                            }
                        } else {
                            responses.push((*peer_id, b"ERR:Unknown command. Use CMD:<command>, SET:key=value, or PING".to_vec()));
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        println!("[-] Peer {} disconnected", peer_id);
                        sessions.remove(peer_id);
                    }
                }
            }

            for (peer_id, data) in responses {
                let _ = server.send(peer_id, 0, data).await;
            }
        }
    }
}
