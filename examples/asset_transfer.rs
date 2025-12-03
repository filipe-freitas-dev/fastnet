//! Asset Transfer Example
//!
//! Demonstrates large file transfers with chunking and verification.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example asset_transfer
//! ```
//!
//! This example creates a test file, transfers it using the asset
//! distribution system, and verifies integrity.

use std::io::{self, Write};
use std::fs::File;

use fastnet::assets::{AssetServer, AssetClient, AssetConfig, AssetEvent};
use uuid::Uuid;

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("╔════════════════════════════════════════╗");
    println!("║    FastNet Asset Transfer Example      ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    
    // Create test file
    let test_file = "/tmp/fastnet_test_asset.bin";
    let output_file = "/tmp/fastnet_received_asset.bin";
    
    println!("1. Creating test file...");
    create_test_file(test_file, 256 * 1024)?; // 256 KB
    println!("   Created: {} (256 KB)", test_file);
    println!();
    
    // Server: Register asset
    println!("2. Registering asset on server...");
    let mut server = AssetServer::new(AssetConfig::default());
    let info = server.register("test-asset", test_file).await?;
    println!("   Name: {}", info.name);
    println!("   Size: {} bytes", info.size);
    println!("   Chunks: {}", info.chunk_count);
    println!("   Hash: {:?}...", &info.hash[..8]);
    println!();
    
    // Client: Request download
    println!("3. Client requesting asset...");
    let mut client = AssetClient::new();
    
    // Simulate request/response
    let peer_id = Uuid::new_v4();
    let (transfer_id, asset_info) = server.handle_request(peer_id, "test-asset")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Asset not found"))?;
    
    println!("   Transfer ID: {}", transfer_id);
    client.start_download(transfer_id, asset_info.clone(), output_file)?;
    println!();
    
    // Transfer chunks
    println!("4. Transferring chunks...");
    let mut chunks_sent = 0;
    
    while let Some(chunk) = server.get_next_chunk(transfer_id)? {
        chunks_sent += 1;
        
        // Simulate network transfer
        let complete = client.receive_chunk(chunk)?;
        
        // Print progress
        if let Some(progress) = client.get_progress(transfer_id) {
            print!("\r   Progress: {:.1}% ({}/{} chunks)", 
                progress * 100.0, chunks_sent, asset_info.chunk_count);
            io::stdout().flush()?;
        }
        
        if complete {
            println!();
            break;
        }
    }
    
    // Process events
    println!();
    println!("5. Processing events...");
    for event in client.poll_events() {
        match event {
            AssetEvent::Progress { received, total, .. } => {
                println!("   Progress: {} / {} bytes", received, total);
            }
            AssetEvent::Completed { path, .. } => {
                println!("   ✅ Transfer complete: {:?}", path);
            }
            AssetEvent::Failed { error, .. } => {
                println!("   ❌ Transfer failed: {}", error);
            }
            _ => {}
        }
    }
    
    // Verify files match
    println!();
    println!("6. Verifying integrity...");
    let original = std::fs::read(test_file)?;
    let received = std::fs::read(output_file)?;
    
    if original == received {
        println!("   ✅ Files match! Transfer verified.");
    } else {
        println!("   ❌ Files don't match! Transfer failed.");
    }
    
    // Cleanup
    println!();
    println!("7. Cleanup...");
    std::fs::remove_file(test_file)?;
    std::fs::remove_file(output_file)?;
    println!("   Temporary files removed.");
    
    println!();
    println!("╔════════════════════════════════════════╗");
    println!("║         Test Complete!                 ║");
    println!("╚════════════════════════════════════════╝");
    
    Ok(())
}

fn create_test_file(path: &str, size: usize) -> io::Result<()> {
    let mut file = File::create(path)?;
    
    // Create reproducible pattern
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        data.push((i % 256) as u8);
    }
    
    file.write_all(&data)?;
    Ok(())
}
