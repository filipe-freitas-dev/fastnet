//! Chat Server Template
//!
//! A real-time encrypted chat server using FastNet.
//! Supports multiple clients, message broadcasting, and simple commands.
//!
//! # Features
//! - Encrypted messaging between all connected clients
//! - Broadcast messages to all peers
//! - Simple protocol: prefix-based message types (MSG, CMD, SYS)
//! - Graceful disconnect handling
//!
//! # Running
//!
//! ```bash
//! cargo run --example chat_server --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("This example requires the 'dev-certs' feature.");
        eprintln!("Run with: cargo run --example chat_server --features dev-certs");
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
        println!("║       FastNet Chat Server             ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        // Generate self-signed certificate for development
        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:7778".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;

        println!("Chat server listening:");
        println!("  UDP (data):      {}", udp_addr);
        println!("  TCP (handshake): {}", tcp_addr);
        println!();

        // Track peer nicknames
        let mut nicknames: HashMap<u16, String> = HashMap::new();

        loop {
            let events = server.poll().await?;

            // Collect messages to broadcast (avoid borrow conflict with server.send)
            let mut broadcasts: Vec<(u16, Vec<u8>)> = Vec::new();

            for event in &events {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        let name = format!("User{}", peer_id);
                        println!("[+] {} joined (peer {})", name, peer_id);
                        nicknames.insert(*peer_id, name.clone());

                        // Notify the new user
                        let welcome = format!("SYS:Welcome, {}! Use /nick <name> to change your name.", name);
                        broadcasts.push((*peer_id, welcome.into_bytes()));

                        // Broadcast join to others
                        let join_msg = format!("SYS:{} joined the chat", name);
                        for &other_id in nicknames.keys() {
                            if other_id != *peer_id {
                                broadcasts.push((other_id, join_msg.as_bytes().to_vec()));
                            }
                        }
                    }
                    SecureEvent::Data(peer_id, _channel, data) => {
                        let text = String::from_utf8_lossy(data);
                        let sender = nicknames.get(peer_id).cloned()
                            .unwrap_or_else(|| format!("Peer{}", peer_id));

                        // Handle commands
                        if text.starts_with("/nick ") {
                            let new_name = text[6..].trim().to_string();
                            let old_name = sender.clone();
                            nicknames.insert(*peer_id, new_name.clone());
                            println!("[*] {} renamed to {}", old_name, new_name);

                            let rename_msg = format!("SYS:{} is now known as {}", old_name, new_name);
                            for &id in nicknames.keys() {
                                broadcasts.push((id, rename_msg.as_bytes().to_vec()));
                            }
                        } else if text.starts_with("/list") {
                            let user_list: Vec<String> = nicknames.values().cloned().collect();
                            let list_msg = format!("SYS:Online ({}): {}", user_list.len(), user_list.join(", "));
                            broadcasts.push((*peer_id, list_msg.into_bytes()));
                        } else {
                            // Broadcast message to all peers
                            println!("[{}] {}", sender, text);
                            let msg = format!("MSG:{}:{}", sender, text);
                            for &id in nicknames.keys() {
                                if id != *peer_id {
                                    broadcasts.push((id, msg.as_bytes().to_vec()));
                                }
                            }
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        let name = nicknames.remove(peer_id)
                            .unwrap_or_else(|| format!("Peer{}", peer_id));
                        println!("[-] {} left (peer {})", name, peer_id);

                        let leave_msg = format!("SYS:{} left the chat", name);
                        for &id in nicknames.keys() {
                            broadcasts.push((id, leave_msg.as_bytes().to_vec()));
                        }
                    }
                }
            }

            // Send all collected broadcasts
            for (peer_id, data) in broadcasts {
                // Channel 0 = ReliableOrdered (guaranteed delivery, in order)
                let _ = server.send(peer_id, 0, data).await;
            }
        }
    }
}
