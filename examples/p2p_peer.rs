//! P2P Peer Example
//!
//! Demonstrates peer-to-peer networking with NAT traversal.
//!
//! # Usage
//!
//! First, run the signaling server:
//! ```bash
//! cargo run --example signaling_server
//! ```
//!
//! Then run multiple peers:
//! ```bash
//! cargo run --example p2p_peer -- room1
//! cargo run --example p2p_peer -- room1  # In another terminal
//! ```
//!
//! Peers in the same room will discover each other and establish
//! direct connections when possible.

use std::env;
use std::io::{self, Write};

use fastnet::p2p::{P2PSocket, P2PEvent, ConnectionMode};

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let room_id = args.get(1).map(|s| s.as_str()).unwrap_or("default-room");
    let signaling_addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:9000");
    
    println!("╔════════════════════════════════════════╗");
    println!("║         FastNet P2P Example            ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    
    // Connect to signaling server
    println!("Connecting to signaling server: {}", signaling_addr);
    let mut socket = P2PSocket::connect(signaling_addr).await?;
    println!("Connected! Local ID: {}", socket.local_id());
    
    // Join room
    println!("Joining room: {}", room_id);
    socket.join_room(room_id).await?;
    println!("Joined room successfully!");
    println!();
    println!("Waiting for other peers...");
    println!("(Other peers should run: cargo run --example p2p_peer -- {})", room_id);
    println!();
    
    let mut message_count = 0u32;
    
    loop {
        // Poll for events
        for event in socket.poll().await? {
            match event {
                P2PEvent::PeerJoined(peer_id) => {
                    println!("📥 Peer {} discovered (attempting connection...)", peer_id);
                }
                
                P2PEvent::PeerConnected(peer_id) => {
                    println!("✅ Direct connection established with peer {}", peer_id);
                    
                    // Send greeting
                    let greeting = format!("Hello from peer {}!", socket.local_id());
                    socket.send(peer_id, greeting.into_bytes()).await?;
                }
                
                P2PEvent::PeerRelayed(peer_id) => {
                    println!("🔄 Using relay for peer {} (NAT traversal failed)", peer_id);
                    
                    // Can still communicate via relay
                    let msg = format!("Hello via relay from peer {}!", socket.local_id());
                    socket.send(peer_id, msg.into_bytes()).await?;
                }
                
                P2PEvent::Data(peer_id, data) => {
                    let message = String::from_utf8_lossy(&data);
                    let mode = match socket.peer_mode(peer_id) {
                        Some(ConnectionMode::Direct) => "direct",
                        Some(ConnectionMode::Relayed) => "relayed",
                        _ => "unknown",
                    };
                    println!("📨 [{}] Peer {}: {}", mode, peer_id, message);
                    
                    // Echo back with counter
                    message_count += 1;
                    let response = format!("Message #{} received!", message_count);
                    socket.send(peer_id, response.into_bytes()).await?;
                }
                
                P2PEvent::PeerLeft(peer_id) => {
                    println!("👋 Peer {} left", peer_id);
                }
                
                P2PEvent::Error(peer_id, error) => {
                    println!("❌ Error with peer {}: {:?}", peer_id, error);
                }
            }
        }
        
        // Print stats periodically
        let peer_count = socket.peer_count();
        if peer_count > 0 {
            print!("\r📊 Connected peers: {} | Messages: {}     ", peer_count, message_count);
            io::stdout().flush()?;
        }
        
        // Small delay to prevent busy loop
        tokio::time::sleep(tokio::time::Duration::from_millis(16)).await;
    }
}
