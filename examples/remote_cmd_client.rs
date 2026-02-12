//! Remote Command Client Template
//!
//! An encrypted client that sends commands to the remote command server
//! and displays the results.
//!
//! # Running
//!
//! First, start the server:
//! ```bash
//! cargo run --example remote_cmd_server --features dev-certs
//! ```
//!
//! Then run this client:
//! ```bash
//! cargo run --example remote_cmd_client --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example remote_cmd_client --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::time::Duration;
        use fastnet::{SecureSocket, SecureEvent};

        println!("╔═══════════════════════════════════════╗");
        println!("║     FastNet Remote Command Client     ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let server_addr = "127.0.0.1:8878".parse().unwrap();
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

        // Read the welcome message
        tokio::time::sleep(Duration::from_millis(50)).await;
        for event in client.poll().await? {
            if let SecureEvent::Data(_, _, data) = event {
                println!("  {}", String::from_utf8_lossy(&data));
            }
        }

        println!();
        println!("Usage:");
        println!("  CMD:<command>    Execute a shell command");
        println!("  SET:key=value    Set a key-value pair");
        println!("  PING             Check server latency");
        println!("  /quit            Disconnect");
        println!();

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

        loop {
            tokio::select! {
                biased;

                result = client.poll() => {
                    for event in result? {
                        match event {
                            SecureEvent::Data(_, _, data) => {
                                let text = String::from_utf8_lossy(&data);
                                if let Some(out) = text.strip_prefix("OUT:") {
                                    println!("{}", out);
                                } else if let Some(err) = text.strip_prefix("ERR:") {
                                    eprintln!("[ERROR] {}", err);
                                } else if text == "PONG" {
                                    println!("  PONG!");
                                } else if let Some(ok) = text.strip_prefix("OK:") {
                                    println!("  [OK] {}", ok);
                                } else {
                                    println!("  {}", text);
                                }
                            }
                            SecureEvent::Disconnected(_) => {
                                println!("\nDisconnected from server.");
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                }

                input = rx.recv() => {
                    match input {
                        Some(input) => {
                            let input = input.trim().to_string();
                            if input.is_empty() { continue; }

                            if input == "/quit" {
                                client.disconnect(peer_id).await?;
                                println!("Disconnected.");
                                return Ok(());
                            }

                            let start = std::time::Instant::now();
                            client.send(peer_id, 0, input.into_bytes()).await?;

                            // Wait for response
                            let timeout = Duration::from_secs(10);
                            let mut got_response = false;
                            while start.elapsed() < timeout {
                                for event in client.poll().await? {
                                    match event {
                                        SecureEvent::Data(_, _, data) => {
                                            let text = String::from_utf8_lossy(&data);
                                            if let Some(out) = text.strip_prefix("OUT:") {
                                                println!("{}", out);
                                            } else if let Some(err) = text.strip_prefix("ERR:") {
                                                eprintln!("[ERROR] {}", err);
                                            } else if text == "PONG" {
                                                println!("  PONG! ({:?})", start.elapsed());
                                            } else if let Some(ok) = text.strip_prefix("OK:") {
                                                println!("  [OK] {}", ok);
                                            } else {
                                                println!("  {}", text);
                                            }
                                            got_response = true;
                                        }
                                        SecureEvent::Disconnected(_) => {
                                            println!("\nServer disconnected.");
                                            return Ok(());
                                        }
                                        _ => {}
                                    }
                                }
                                if got_response { break; }
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            if !got_response {
                                eprintln!("  [TIMEOUT] No response after {:?}", timeout);
                            }
                        }
                        None => {
                            client.disconnect(peer_id).await?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
