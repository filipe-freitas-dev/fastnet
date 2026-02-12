//! Chat Client Template
//!
//! A real-time encrypted chat client using FastNet.
//! Connects to the chat server and allows sending/receiving messages.
//!
//! # Running
//!
//! First, start the server:
//! ```bash
//! cargo run --example chat_server --features dev-certs
//! ```
//!
//! Then run this client:
//! ```bash
//! cargo run --example chat_client --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("This example requires the 'dev-certs' feature.");
        eprintln!("Run with: cargo run --example chat_client --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::time::Duration;
        use fastnet::{SecureSocket, SecureEvent};
        use tokio::io::{self, AsyncBufReadExt, BufReader};

        println!("╔═══════════════════════════════════════╗");
        println!("║       FastNet Chat Client             ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let server_addr = "127.0.0.1:7778".parse().unwrap();
        println!("Connecting to {}...", server_addr);

        let mut client = SecureSocket::connect(server_addr).await?;
        println!("Connected!\n");

        // Wait for Connected event
        let peer_id = 'wait: loop {
            for event in client.poll().await? {
                if let SecureEvent::Connected(id) = event {
                    break 'wait id;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        println!("Commands: /nick <name>, /list, /quit");
        println!("Type a message and press Enter to send.\n");

        let stdin = BufReader::new(io::stdin());
        let mut lines = stdin.lines();

        loop {
            tokio::select! {
                biased;

                // Check for incoming messages (non-blocking, with short timeout)
                result = client.poll() => {
                    for event in result? {
                        match event {
                            SecureEvent::Data(_, _, data) => {
                                let text = String::from_utf8_lossy(&data);
                                // Parse protocol: MSG:sender:text or SYS:text
                                if let Some(msg) = text.strip_prefix("MSG:") {
                                    if let Some((sender, content)) = msg.split_once(':') {
                                        println!("  [{}] {}", sender, content);
                                    }
                                } else if let Some(sys) = text.strip_prefix("SYS:") {
                                    println!("  * {}", sys);
                                } else {
                                    println!("  > {}", text);
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

                // Read user input
                line = lines.next_line() => {
                    match line {
                        Ok(Some(input)) => {
                            let input = input.trim().to_string();
                            if input.is_empty() { continue; }

                            if input == "/quit" {
                                println!("Disconnecting...");
                                client.disconnect(peer_id).await?;
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                println!("Bye!");
                                return Ok(());
                            }

                            client.send(peer_id, 0, input.into_bytes()).await?;
                        }
                        Ok(None) => {
                            // EOF
                            client.disconnect(peer_id).await?;
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Input error: {}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}
