//! Remote Command Client Template
//!
//! An encrypted client that receives commands from the server,
//! executes them locally, and returns the output.
//!
//! # Protocol
//! - Server sends: `CMD:<command>`, `PING`
//! - Client responds: `OUT:<output>`, `ERR:<error>`, `PONG`
//!
//! # Security Note
//! This is a template. In production, add command whitelisting and validation.
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

        println!("Connected! Waiting for commands from server...");
        println!("(The server will send commands for this client to execute)");
        println!();

        loop {
            for event in client.poll().await? {
                let mut responses: Vec<Vec<u8>> = Vec::new();

                match event {
                    SecureEvent::Data(_, _channel, data) => {
                        let request = String::from_utf8_lossy(&data);
                        println!("[server] {}", request);

                        if request == "PING" {
                            responses.push(b"PONG".to_vec());
                        } else if let Some(cmd) = request.strip_prefix("CMD:") {
                            let cmd = cmd.trim();
                            println!("[exec] {}", cmd);

                            // Execute command locally
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
                                        println!("{}", stdout.trim_end());
                                        responses.push(msg.into_bytes());
                                    }
                                    if !stderr.is_empty() {
                                        let msg = format!("ERR:{}", stderr.trim_end());
                                        eprintln!("[stderr] {}", stderr.trim_end());
                                        responses.push(msg.into_bytes());
                                    }
                                    if stdout.is_empty() && stderr.is_empty() {
                                        let msg = format!("OUT:exit {}", output.status.code().unwrap_or(-1));
                                        responses.push(msg.into_bytes());
                                    }
                                }
                                Err(e) => {
                                    let msg = format!("ERR:Failed to execute: {}", e);
                                    eprintln!("[error] {}", e);
                                    responses.push(msg.into_bytes());
                                }
                            }
                        } else {
                            println!("[?] Unknown: {}", request);
                            responses.push(format!("ERR:Unknown command: {}", request).into_bytes());
                        }

                        for resp in responses {
                            let _ = client.send(peer_id, 0, resp).await;
                        }
                    }
                    SecureEvent::Disconnected(_) => {
                        println!("\nServer disconnected.");
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
}
