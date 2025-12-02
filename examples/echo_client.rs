//! Echo Client Example
//!
//! A simple client that connects to the echo server, sends messages,
//! and displays the echoed responses.
//!
//! # Running
//!
//! First, start the server:
//! ```bash
//! cargo run --example echo_server --features dev-certs
//! ```
//!
//! Then run this client:
//! ```bash
//! cargo run --example echo_client --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("This example requires the 'dev-certs' feature.");
        eprintln!("Run with: cargo run --example echo_client --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::time::Duration;
        use fastnet::{SecureSocket, SecureEvent};

        println!("╔═══════════════════════════════════════╗");
        println!("║       FastNet Echo Client             ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        // Connect to server
        let server_addr = "127.0.0.1:7778".parse().unwrap();
        println!("Connecting to {}...", server_addr);
        
        let mut client = SecureSocket::connect(server_addr).await?;
        println!("TLS handshake complete!");
        println!();

        // Wait for Connected event and get peer_id
        let peer_id = loop {
            for event in client.poll().await? {
                if let SecureEvent::Connected(id) = event {
                    println!("[+] Connected as peer {}", id);
                    break id;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };

        // Send some test messages
        let messages = [
            "Hello, FastNet!",
            "Testing 1, 2, 3...",
            "Low latency networking!",
            "Encrypted and fast!",
        ];

        for (i, msg) in messages.iter().enumerate() {
            println!();
            println!("[>] Sending: \"{}\"", msg);
            
            client.send(peer_id, 0, msg.as_bytes().to_vec()).await?;

            // Wait for echo
            let start = std::time::Instant::now();
            'recv: loop {
                for event in client.poll().await? {
                    if let SecureEvent::Data(_, _, data) = event {
                        let elapsed = start.elapsed();
                        let response = String::from_utf8_lossy(&data);
                        println!("[<] Received: \"{}\" (RTT: {:?})", response, elapsed);
                        break 'recv;
                    }
                }
            }

            // Small delay between messages
            if i < messages.len() - 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        println!();
        println!("All messages echoed successfully!");
        println!();

        Ok(())
    }
}
