//! Signaling Server Example
//!
//! A simple signaling server for P2P peer discovery and NAT traversal.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example signaling_server
//! ```
//!
//! The server listens on port 9000 by default.

use std::env;
use std::io;

use fastnet::p2p::SignalingServer;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr = args.get(1).map(|s| s.as_str()).unwrap_or("0.0.0.0:9000");
    
    println!("╔════════════════════════════════════════╗");
    println!("║     FastNet Signaling Server           ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    println!("Starting signaling server on: {}", addr);
    
    let server = SignalingServer::bind(addr).await?;
    
    println!("Server running!");
    println!();
    println!("Peers can connect using:");
    println!("  cargo run --example p2p_peer -- <room_name> {}", addr);
    println!();
    
    server.run().await
}
