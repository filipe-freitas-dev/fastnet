//! Test client that connects, sends one message, then waits forever (simulating a freeze/crash)

use std::time::Duration;
use fastnet::{SecureSocket, SecureEvent};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("╔═══════════════════════════════════════╗");
    println!("║   Test Crash Client (No Disconnect)   ║");
    println!("╚═══════════════════════════════════════╝");
    println!();

    // Connect to server
    let server_addr = "127.0.0.1:7778".parse().unwrap();
    println!("Connecting to {}...", server_addr);

    let mut client = SecureSocket::connect(server_addr).await?;
    println!("TLS handshake complete!");
    println!();

    // Wait for Connected event and get peer_id
    let peer_id = 'wait_connect: loop {
        for event in client.poll().await? {
            if let SecureEvent::Connected(id) = event {
                println!("[+] Connected as peer {}", id);
                break 'wait_connect id;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    // Send ONE message
    println!("[>] Sending: \"Test message\"");
    client.send(peer_id, 0, b"Test message".to_vec()).await?;

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

    println!();
    println!("✋ Now client will wait forever without disconnect (simulating freeze)");
    println!("   Server should detect timeout after 30 seconds...");
    println!();

    // Wait forever without calling disconnect() - simulating a crash/freeze
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
