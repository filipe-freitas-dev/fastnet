//! Remote Command Server Template
//!
//! An encrypted remote command server using FastNet.
//! The server sends commands to connected clients, which execute them
//! and return the output.
//!
//! # Protocol
//! - Server sends: `CMD:<command>`, `PING`
//! - Client responds: `OUT:<output>`, `ERR:<error>`, `PONG`
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
        use std::collections::HashSet;
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
        println!("Waiting for clients...");
        println!();

        let mut peers: HashSet<u16> = HashSet::new();

        // Spawn a blocking thread for stdin reading
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);
        tokio::task::spawn_blocking(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) => { if tx.blocking_send(l).is_err() { break; } }
                    Err(_) => break,
                }
            }
        });

        println!("Usage:");
        println!("  CMD:<command>    Send a shell command to all clients");
        println!("  PING             Check client latency");
        println!("  /list            List connected clients");
        println!("  /quit            Shut down server");
        println!();

        loop {
            tokio::select! {
                biased;

                result = server.poll() => {
                    for event in result? {
                        match event {
                            SecureEvent::Connected(peer_id) => {
                                println!("[+] Client {} connected ({} total)", peer_id, peers.len() + 1);
                                peers.insert(peer_id);
                            }
                            SecureEvent::Data(peer_id, _channel, data) => {
                                let text = String::from_utf8_lossy(&data);
                                if let Some(out) = text.strip_prefix("OUT:") {
                                    println!("[client {}] {}", peer_id, out);
                                } else if let Some(err) = text.strip_prefix("ERR:") {
                                    eprintln!("[client {} ERROR] {}", peer_id, err);
                                } else if text == "PONG" {
                                    println!("[client {}] PONG!", peer_id);
                                } else {
                                    println!("[client {}] {}", peer_id, text);
                                }
                            }
                            SecureEvent::Disconnected(peer_id) => {
                                peers.remove(&peer_id);
                                println!("[-] Client {} disconnected ({} remaining)", peer_id, peers.len());
                            }
                        }
                    }
                }

                input = rx.recv() => {
                    match input {
                        Some(input) => {
                            let input = input.trim().to_string();
                            if input.is_empty() { continue; }

                            if input == "/quit" {
                                println!("Shutting down...");
                                let peer_list: Vec<u16> = peers.iter().copied().collect();
                                for peer_id in peer_list {
                                    let _ = server.disconnect(peer_id).await;
                                }
                                return Ok(());
                            }

                            if input == "/list" {
                                if peers.is_empty() {
                                    println!("  No clients connected.");
                                } else {
                                    println!("  Connected clients: {:?}", peers);
                                }
                                continue;
                            }

                            if peers.is_empty() {
                                println!("  [!] No clients connected.");
                                continue;
                            }

                            // Send command to all connected clients
                            let peer_list: Vec<u16> = peers.iter().copied().collect();
                            println!("[>] Sending to {} client(s): {}", peer_list.len(), input);
                            for peer_id in peer_list {
                                let _ = server.send(peer_id, 0, input.as_bytes().to_vec()).await;
                            }
                        }
                        None => {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
