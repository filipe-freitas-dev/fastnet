//! Hybrid Client Example
//!
//! Demonstrates the TCP fallback feature. The client automatically
//! tries UDP first, then falls back to TCP if UDP is blocked.
//!
//! # Usage
//!
//! First, start the echo server:
//! ```bash
//! cargo run --example echo_server --features dev-certs
//! ```
//!
//! Then run the hybrid client:
//! ```bash
//! cargo run --example hybrid_client
//! ```

use std::io;

use fastnet::tcp::{HybridSocket, HybridEvent, TransportMode};

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("╔════════════════════════════════════════╗");
    println!("║     FastNet Hybrid Client              ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    
    let server_addr = "127.0.0.1:7778";
    println!("Connecting to: {}", server_addr);
    println!("(Attempting UDP first, TCP fallback if needed)");
    println!();
    
    let mut socket = HybridSocket::connect(server_addr).await?;
    
    // Show transport mode
    match socket.transport_mode() {
        TransportMode::Udp => {
            println!("✅ Connected via UDP (optimal latency)");
        }
        TransportMode::Tcp => {
            println!("⚠️  Connected via TCP (fallback mode)");
            println!("   UDP may be blocked by firewall");
        }
    }
    
    println!("Session ID: {}", socket.session_id());
    println!();
    
    // Send some test messages
    for i in 1..=5 {
        let message = format!("Test message #{}", i);
        println!("📤 Sending: {}", message);
        socket.send(0, message.into_bytes()).await?;
        
        // Poll for response
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        for event in socket.poll().await? {
            match event {
                HybridEvent::Data(_, channel, data) => {
                    let response = String::from_utf8_lossy(&data);
                    println!("📨 Received [ch{}]: {}", channel, response);
                }
                HybridEvent::Disconnected(_) => {
                    println!("❌ Disconnected from server");
                    return Ok(());
                }
                HybridEvent::TransportChanged(mode) => {
                    println!("🔄 Transport changed to: {:?}", mode);
                }
                _ => {}
            }
        }
    }
    
    println!();
    println!("✅ Test completed successfully!");
    
    Ok(())
}
