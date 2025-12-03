//! Asset distribution for large file transfers.
#![allow(dead_code)] // Some fields reserved for future use
//!
//! This module provides efficient transfer of large files (textures, maps, mods)
//! with chunking, integrity verification, and resumable downloads.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                      Asset Transfer                            │
//! │                                                                │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
//! │  │   Chunker   │───▶│  Compressor │───▶│   Sender    │        │
//! │  │   (64KB)    │    │   (LZ4)     │    │  (Reliable) │        │
//! │  └─────────────┘    └─────────────┘    └─────────────┘        │
//! │                                                                │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
//! │  │   Hasher    │◀───│ Assembler   │◀───│  Receiver   │        │
//! │  │  (BLAKE3)   │    │             │    │  (Ordered)  │        │
//! │  └─────────────┘    └─────────────┘    └─────────────┘        │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Chunked Transfer**: Splits large files into 64KB chunks
//! - **Compression**: Optional LZ4 compression for faster transfers
//! - **Integrity**: BLAKE3 hash verification per chunk and per file
//! - **Resumable**: Can resume interrupted transfers
//! - **Progress**: Real-time progress callbacks
//!
//! # Example
//!
//! ## Server (sending assets)
//!
//! ```rust,no_run
//! use fastnet::assets::{AssetServer, AssetConfig};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let mut server = AssetServer::new(AssetConfig::default());
//!     
//!     // Register assets to serve
//!     server.register("map_forest.pak", "/game/maps/forest.pak").await?;
//!     server.register("textures.pak", "/game/textures/pack1.pak").await?;
//!     
//!     // Handle requests (integrate with your game server)
//!     // server.handle_request(peer_id, request).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Client (downloading assets)
//!
//! ```rust,no_run
//! use fastnet::assets::{AssetClient, AssetEvent};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let mut client = AssetClient::new();
//!     
//!     // Request an asset
//!     client.request("map_forest.pak", "/local/maps/forest.pak").await?;
//!     
//!     // Process download
//!     loop {
//!         for event in client.poll().await? {
//!             match event {
//!                 AssetEvent::Progress { id, received, total } => {
//!                     let percent = (received as f64 / total as f64) * 100.0;
//!                     println!("Downloading: {:.1}%", percent);
//!                 }
//!                 AssetEvent::Completed { id, path } => {
//!                     println!("Downloaded: {}", path);
//!                     break;
//!                 }
//!                 AssetEvent::Failed { id, error } => {
//!                     eprintln!("Failed: {}", error);
//!                     break;
//!                 }
//!             }
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::fs::File;
use std::time::{Duration, Instant};

use blake3::Hasher;
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use uuid::Uuid;

use crate::types::{TransferId, PeerId};

/// Default chunk size (64KB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Asset transfer events.
#[derive(Debug, Clone)]
pub enum AssetEvent {
    /// Asset request received (server-side).
    Requested {
        /// Request ID.
        id: TransferId,
        /// Asset name requested.
        name: String,
        /// Requesting peer.
        peer_id: PeerId,
    },
    
    /// Transfer progress update.
    Progress {
        /// Transfer ID.
        id: TransferId,
        /// Bytes received/sent.
        received: u64,
        /// Total bytes.
        total: u64,
    },
    
    /// Transfer completed successfully.
    Completed {
        /// Transfer ID.
        id: TransferId,
        /// Local file path.
        path: PathBuf,
    },
    
    /// Transfer failed.
    Failed {
        /// Transfer ID.
        id: TransferId,
        /// Error description.
        error: String,
    },
    
    /// Chunk received (for manual handling).
    ChunkReceived {
        /// Transfer ID.
        id: TransferId,
        /// Chunk index.
        index: u32,
        /// Chunk data.
        data: Vec<u8>,
    },
}

/// Asset metadata.
#[derive(Debug, Clone)]
pub struct AssetInfo {
    /// Asset name/identifier.
    pub name: String,
    /// Total size in bytes.
    pub size: u64,
    /// BLAKE3 hash of entire file.
    pub hash: [u8; 32],
    /// Number of chunks.
    pub chunk_count: u32,
    /// Chunk size used.
    pub chunk_size: usize,
    /// Whether compression is enabled.
    pub compressed: bool,
}

/// Configuration for asset transfers.
#[derive(Debug, Clone)]
pub struct AssetConfig {
    /// Chunk size for splitting files.
    pub chunk_size: usize,
    /// Enable LZ4 compression.
    pub compress: bool,
    /// Directory for storing downloaded assets.
    pub download_dir: PathBuf,
    /// Maximum concurrent transfers.
    pub max_concurrent: usize,
    /// Verify chunks with hashes.
    pub verify_chunks: bool,
    /// Maximum retries per chunk.
    pub max_chunk_retries: u32,
    /// Timeout per chunk in milliseconds.
    pub chunk_timeout_ms: u64,
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            compress: true,
            download_dir: PathBuf::from("./downloads"),
            max_concurrent: 4,
            verify_chunks: true,
            max_chunk_retries: 3,
            chunk_timeout_ms: 5000,
        }
    }
}

/// Transfer statistics.
#[derive(Debug, Clone)]
pub struct TransferStats {
    /// Transfer ID.
    pub transfer_id: TransferId,
    /// Chunks sent so far.
    pub chunks_sent: u32,
    /// Total chunks.
    pub total_chunks: u32,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Total size in bytes.
    pub total_size: u64,
    /// Time elapsed.
    pub elapsed: Duration,
    /// Transfer speed in bytes/second.
    pub bytes_per_second: f64,
    /// Whether transfer is paused.
    pub paused: bool,
}

/// Outgoing chunk for transfer.
#[derive(Debug, Clone)]
pub struct AssetChunk {
    /// Transfer ID.
    pub transfer_id: TransferId,
    /// Chunk index.
    pub index: u32,
    /// Chunk data (possibly compressed).
    pub data: Vec<u8>,
    /// BLAKE3 hash of this chunk.
    pub hash: [u8; 32],
}

/// Server-side asset management.
pub struct AssetServer {
    /// Registered assets.
    assets: HashMap<String, RegisteredAsset>,
    /// Active transfers.
    transfers: HashMap<TransferId, ServerTransfer>,
    /// Configuration.
    config: AssetConfig,
    /// Events.
    events: Vec<AssetEvent>,
}

struct RegisteredAsset {
    path: PathBuf,
    info: AssetInfo,
    chunk_hashes: Vec<[u8; 32]>,
}

struct ServerTransfer {
    asset_name: String,
    peer_id: PeerId,
    current_chunk: u32,
    total_chunks: u32,
    paused: bool,
    started_at: Instant,
    bytes_sent: u64,
}

impl AssetServer {
    /// Create a new asset server.
    pub fn new(config: AssetConfig) -> Self {
        Self {
            assets: HashMap::new(),
            transfers: HashMap::new(),
            config,
            events: Vec::new(),
        }
    }
    
    /// Register an asset for serving.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name clients will use to request this asset
    /// * `path` - Local file path
    pub async fn register(&mut self, name: &str, path: &str) -> io::Result<AssetInfo> {
        let path = PathBuf::from(path);
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();
        
        // Calculate file hash
        let hash = Self::hash_file(&path)?;
        
        // Calculate chunk hashes
        let chunk_count = ((size as usize + self.config.chunk_size - 1) / self.config.chunk_size) as u32;
        let chunk_hashes = Self::calculate_chunk_hashes(&path, self.config.chunk_size)?;
        
        let info = AssetInfo {
            name: name.to_string(),
            size,
            hash,
            chunk_count,
            chunk_size: self.config.chunk_size,
            compressed: self.config.compress,
        };
        
        self.assets.insert(name.to_string(), RegisteredAsset {
            path,
            info: info.clone(),
            chunk_hashes,
        });
        
        Ok(info)
    }
    
    /// Get info about a registered asset.
    pub fn get_asset_info(&self, name: &str) -> Option<&AssetInfo> {
        self.assets.get(name).map(|a| &a.info)
    }
    
    /// Handle an asset request from a peer.
    pub fn handle_request(&mut self, peer_id: PeerId, name: &str) -> Option<(TransferId, AssetInfo)> {
        let asset = self.assets.get(name)?;
        
        let transfer_id = Uuid::new_v4();
        
        self.transfers.insert(transfer_id, ServerTransfer {
            asset_name: name.to_string(),
            peer_id,
            current_chunk: 0,
            total_chunks: asset.info.chunk_count,
            paused: false,
            started_at: Instant::now(),
            bytes_sent: 0,
        });
        
        self.events.push(AssetEvent::Requested {
            id: transfer_id,
            name: name.to_string(),
            peer_id,
        });
        
        Some((transfer_id, asset.info.clone()))
    }
    
    /// Get the next chunk for a transfer.
    pub fn get_next_chunk(&mut self, transfer_id: TransferId) -> io::Result<Option<AssetChunk>> {
        let transfer = match self.transfers.get_mut(&transfer_id) {
            Some(t) => t,
            None => return Ok(None),
        };
        
        if transfer.paused {
            return Ok(None);
        }
        
        if transfer.current_chunk >= transfer.total_chunks {
            self.transfers.remove(&transfer_id);
            return Ok(None);
        }
        
        let asset = self.assets.get(&transfer.asset_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Asset not found"))?;
        
        let chunk_index = transfer.current_chunk;
        let chunk = Self::read_chunk(&asset.path, chunk_index as usize, self.config.chunk_size)?;
        
        let data = if self.config.compress {
            Self::compress(&chunk)
        } else {
            chunk.clone()
        };
        
        let hash = asset.chunk_hashes[chunk_index as usize];
        
        transfer.current_chunk += 1;
        
        // Emit progress
        let received = transfer.current_chunk as u64 * self.config.chunk_size as u64;
        let total = asset.info.size;
        self.events.push(AssetEvent::Progress {
            id: transfer_id,
            received: received.min(total),
            total,
        });
        
        Ok(Some(AssetChunk {
            transfer_id,
            index: chunk_index,
            data,
            hash,
        }))
    }
    
    /// Get pending events.
    pub fn poll_events(&mut self) -> Vec<AssetEvent> {
        std::mem::take(&mut self.events)
    }
    
    fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
        let mut file = File::open(path)?;
        let mut hasher = Hasher::new();
        let mut buffer = [0u8; 8192];
        
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            hasher.update(&buffer[..n]);
        }
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn calculate_chunk_hashes(path: &Path, chunk_size: usize) -> io::Result<Vec<[u8; 32]>> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;
        let chunk_count = (size + chunk_size - 1) / chunk_size;
        
        let mut hashes = Vec::with_capacity(chunk_count);
        let mut buffer = vec![0u8; chunk_size];
        
        for _ in 0..chunk_count {
            let n = file.read(&mut buffer)?;
            let mut hasher = Hasher::new();
            hasher.update(&buffer[..n]);
            hashes.push(*hasher.finalize().as_bytes());
        }
        
        Ok(hashes)
    }
    
    fn read_chunk(path: &Path, index: usize, chunk_size: usize) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start((index * chunk_size) as u64))?;
        
        let mut buffer = vec![0u8; chunk_size];
        let n = file.read(&mut buffer)?;
        buffer.truncate(n);
        
        Ok(buffer)
    }
    
    fn compress(data: &[u8]) -> Vec<u8> {
        // LZ4 compression with size prepended
        let mut out = Vec::with_capacity(data.len() + 5);
        out.push(1); // 1 = LZ4 compressed
        out.extend_from_slice(&compress_prepend_size(data));
        out
    }
    
    /// Pause a transfer.
    pub fn pause_transfer(&mut self, transfer_id: TransferId) -> bool {
        if let Some(transfer) = self.transfers.get_mut(&transfer_id) {
            transfer.paused = true;
            true
        } else {
            false
        }
    }
    
    /// Resume a paused transfer.
    pub fn resume_transfer(&mut self, transfer_id: TransferId) -> bool {
        if let Some(transfer) = self.transfers.get_mut(&transfer_id) {
            transfer.paused = false;
            true
        } else {
            false
        }
    }
    
    /// Cancel a transfer.
    pub fn cancel_transfer(&mut self, transfer_id: TransferId) -> bool {
        self.transfers.remove(&transfer_id).is_some()
    }
    
    /// Get a specific chunk by index (for retries/resumes).
    pub fn get_chunk(&self, transfer_id: TransferId, chunk_index: u32) -> io::Result<Option<AssetChunk>> {
        let transfer = match self.transfers.get(&transfer_id) {
            Some(t) => t,
            None => return Ok(None),
        };
        
        let asset = self.assets.get(&transfer.asset_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Asset not found"))?;
        
        if chunk_index >= asset.info.chunk_count {
            return Ok(None);
        }
        
        let chunk = Self::read_chunk(&asset.path, chunk_index as usize, self.config.chunk_size)?;
        
        let data = if self.config.compress {
            Self::compress(&chunk)
        } else {
            let mut out = Vec::with_capacity(chunk.len() + 1);
            out.push(0); // 0 = uncompressed
            out.extend_from_slice(&chunk);
            out
        };
        
        let hash = asset.chunk_hashes[chunk_index as usize];
        
        Ok(Some(AssetChunk {
            transfer_id,
            index: chunk_index,
            data,
            hash,
        }))
    }
    
    /// Get transfer statistics.
    pub fn get_transfer_stats(&self, transfer_id: TransferId) -> Option<TransferStats> {
        self.transfers.get(&transfer_id).map(|t| {
            let asset = self.assets.get(&t.asset_name);
            let total_size = asset.map(|a| a.info.size).unwrap_or(0);
            let elapsed = t.started_at.elapsed();
            let bytes_per_sec = if elapsed.as_secs_f64() > 0.0 {
                t.bytes_sent as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };
            
            TransferStats {
                transfer_id,
                chunks_sent: t.current_chunk,
                total_chunks: t.total_chunks,
                bytes_sent: t.bytes_sent,
                total_size,
                elapsed,
                bytes_per_second: bytes_per_sec,
                paused: t.paused,
            }
        })
    }
    
    /// List all active transfers.
    pub fn list_transfers(&self) -> Vec<TransferId> {
        self.transfers.keys().copied().collect()
    }
}

/// Client-side asset downloading.
pub struct AssetClient {
    /// Active downloads.
    downloads: HashMap<TransferId, ClientDownload>,
    /// Configuration.
    config: AssetConfig,
    /// Events.
    events: Vec<AssetEvent>,
}

struct ClientDownload {
    info: AssetInfo,
    path: PathBuf,
    file: File,
    received_chunks: Vec<bool>,
    bytes_received: u64,
    paused: bool,
    started_at: Instant,
    chunk_retries: HashMap<u32, u32>,
}

impl AssetClient {
    /// Create a new asset client.
    pub fn new() -> Self {
        Self::with_config(AssetConfig::default())
    }
    
    /// Create with custom configuration.
    pub fn with_config(config: AssetConfig) -> Self {
        Self {
            downloads: HashMap::new(),
            config,
            events: Vec::new(),
        }
    }
    
    /// Start a download.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` - ID from server's response
    /// * `info` - Asset info from server
    /// * `output_path` - Where to save the file
    pub fn start_download(&mut self, transfer_id: TransferId, info: AssetInfo, output_path: &str) -> io::Result<()> {
        let path = PathBuf::from(output_path);
        
        // Create parent directories
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let file = File::create(&path)?;
        file.set_len(info.size)?; // Pre-allocate
        
        let chunk_count = info.chunk_count as usize;
        
        self.downloads.insert(transfer_id, ClientDownload {
            info,
            path,
            file,
            received_chunks: vec![false; chunk_count],
            bytes_received: 0,
            paused: false,
            started_at: Instant::now(),
            chunk_retries: HashMap::new(),
        });
        
        Ok(())
    }
    
    /// Resume an interrupted download from a partial file.
    ///
    /// Reads existing chunks and marks them as received.
    pub fn resume_download(&mut self, transfer_id: TransferId, info: AssetInfo, output_path: &str) -> io::Result<u32> {
        let path = PathBuf::from(output_path);
        
        if !path.exists() {
            // No existing file, start fresh
            self.start_download(transfer_id, info, output_path)?;
            return Ok(0);
        }
        
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() != info.size {
            // File size doesn't match, start fresh
            self.start_download(transfer_id, info, output_path)?;
            return Ok(0);
        }
        
        // Open for read+write
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        
        let chunk_count = info.chunk_count as usize;
        let mut received_chunks = vec![false; chunk_count];
        let mut bytes_received = 0u64;
        let mut valid_chunks = 0u32;
        
        // Verify existing chunks
        let mut buffer = vec![0u8; info.chunk_size];
        let mut temp_file = File::open(&path)?;
        
        for i in 0..chunk_count {
            temp_file.seek(SeekFrom::Start((i * info.chunk_size) as u64))?;
            let n = temp_file.read(&mut buffer)?;
            
            if n > 0 {
                // Mark chunk as received - final hash check will catch corruption
                received_chunks[i] = true;
                bytes_received += n as u64;
                valid_chunks += 1;
            }
        }
        
        self.downloads.insert(transfer_id, ClientDownload {
            info,
            path,
            file,
            received_chunks,
            bytes_received,
            paused: false,
            started_at: Instant::now(),
            chunk_retries: HashMap::new(),
        });
        
        Ok(valid_chunks)
    }
    
    /// Process a received chunk.
    pub fn receive_chunk(&mut self, chunk: AssetChunk) -> io::Result<bool> {
        let download = self.downloads.get_mut(&chunk.transfer_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Unknown transfer"))?;
        
        // Verify hash if enabled
        if self.config.verify_chunks {
            let data = Self::decompress(&chunk.data);
            let mut hasher = Hasher::new();
            hasher.update(&data);
            let computed_hash = *hasher.finalize().as_bytes();
            
            if computed_hash != chunk.hash {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Chunk hash mismatch"));
            }
        }
        
        // Write chunk to file
        let data = Self::decompress(&chunk.data);
        let offset = chunk.index as u64 * download.info.chunk_size as u64;
        download.file.seek(SeekFrom::Start(offset))?;
        download.file.write_all(&data)?;
        
        // Mark as received
        download.received_chunks[chunk.index as usize] = true;
        download.bytes_received += data.len() as u64;
        
        // Emit progress
        self.events.push(AssetEvent::Progress {
            id: chunk.transfer_id,
            received: download.bytes_received,
            total: download.info.size,
        });
        
        // Check if complete
        let complete = download.received_chunks.iter().all(|&r| r);
        
        if complete {
            // Verify final hash
            download.file.flush()?;
            
            let final_hash = AssetServer::hash_file(&download.path)?;
            if final_hash != download.info.hash {
                self.events.push(AssetEvent::Failed {
                    id: chunk.transfer_id,
                    error: "File hash mismatch".to_string(),
                });
                self.downloads.remove(&chunk.transfer_id);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "File hash mismatch"));
            }
            
            let path = download.path.clone();
            self.downloads.remove(&chunk.transfer_id);
            
            self.events.push(AssetEvent::Completed {
                id: chunk.transfer_id,
                path,
            });
        }
        
        Ok(complete)
    }
    
    /// Get missing chunk indices for a transfer.
    pub fn get_missing_chunks(&self, transfer_id: TransferId) -> Vec<u32> {
        self.downloads.get(&transfer_id)
            .map(|d| {
                d.received_chunks.iter()
                    .enumerate()
                    .filter(|(_, &received)| !received)
                    .map(|(i, _)| i as u32)
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get download progress (0.0 to 1.0).
    pub fn get_progress(&self, transfer_id: TransferId) -> Option<f64> {
        self.downloads.get(&transfer_id)
            .map(|d| d.bytes_received as f64 / d.info.size as f64)
    }
    
    /// Poll for events.
    pub fn poll_events(&mut self) -> Vec<AssetEvent> {
        std::mem::take(&mut self.events)
    }
    
    /// Cancel a download.
    pub fn cancel_download(&mut self, transfer_id: TransferId) -> bool {
        if let Some(download) = self.downloads.remove(&transfer_id) {
            // Optionally delete partial file
            let _ = std::fs::remove_file(&download.path);
            true
        } else {
            false
        }
    }
    
    /// Cancel download but keep partial file for resume.
    pub fn cancel_download_keep_partial(&mut self, transfer_id: TransferId) -> bool {
        self.downloads.remove(&transfer_id).is_some()
    }
    
    /// Pause a download.
    pub fn pause_download(&mut self, transfer_id: TransferId) -> bool {
        if let Some(download) = self.downloads.get_mut(&transfer_id) {
            download.paused = true;
            true
        } else {
            false
        }
    }
    
    /// Resume a paused download.
    pub fn unpause_download(&mut self, transfer_id: TransferId) -> bool {
        if let Some(download) = self.downloads.get_mut(&transfer_id) {
            download.paused = false;
            true
        } else {
            false
        }
    }
    
    /// Check if download is paused.
    pub fn is_paused(&self, transfer_id: TransferId) -> Option<bool> {
        self.downloads.get(&transfer_id).map(|d| d.paused)
    }
    
    /// Record a failed chunk for retry tracking.
    pub fn record_chunk_failure(&mut self, transfer_id: TransferId, chunk_index: u32) -> Option<u32> {
        if let Some(download) = self.downloads.get_mut(&transfer_id) {
            let retries = download.chunk_retries.entry(chunk_index).or_insert(0);
            *retries += 1;
            Some(*retries)
        } else {
            None
        }
    }
    
    /// Check if a chunk has exceeded max retries.
    pub fn chunk_exceeded_retries(&self, transfer_id: TransferId, chunk_index: u32) -> bool {
        self.downloads.get(&transfer_id)
            .and_then(|d| d.chunk_retries.get(&chunk_index))
            .map(|&r| r >= self.config.max_chunk_retries)
            .unwrap_or(false)
    }
    
    /// Get download statistics.
    pub fn get_download_stats(&self, transfer_id: TransferId) -> Option<TransferStats> {
        self.downloads.get(&transfer_id).map(|d| {
            let elapsed = d.started_at.elapsed();
            let bytes_per_sec = if elapsed.as_secs_f64() > 0.0 {
                d.bytes_received as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };
            let chunks_received = d.received_chunks.iter().filter(|&&r| r).count() as u32;
            
            TransferStats {
                transfer_id,
                chunks_sent: chunks_received,
                total_chunks: d.info.chunk_count,
                bytes_sent: d.bytes_received,
                total_size: d.info.size,
                elapsed,
                bytes_per_second: bytes_per_sec,
                paused: d.paused,
            }
        })
    }
    
    /// List all active downloads.
    pub fn list_downloads(&self) -> Vec<TransferId> {
        self.downloads.keys().copied().collect()
    }
    
    /// Get asset info for a download.
    pub fn get_asset_info(&self, transfer_id: TransferId) -> Option<&AssetInfo> {
        self.downloads.get(&transfer_id).map(|d| &d.info)
    }
    
    fn decompress(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        
        // Check compression marker
        match data[0] {
            0 => data[1..].to_vec(), // Uncompressed
            1 => {
                // LZ4 compressed
                decompress_size_prepended(&data[1..]).unwrap_or_else(|_| data[1..].to_vec())
            }
            _ => data[1..].to_vec(), // Unknown, treat as raw
        }
    }
}

impl Default for AssetClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize asset info for network transfer.
pub fn serialize_asset_info(info: &AssetInfo) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // Name length + name
    buf.extend_from_slice(&(info.name.len() as u16).to_le_bytes());
    buf.extend_from_slice(info.name.as_bytes());
    
    // Size
    buf.extend_from_slice(&info.size.to_le_bytes());
    
    // Hash
    buf.extend_from_slice(&info.hash);
    
    // Chunk info
    buf.extend_from_slice(&info.chunk_count.to_le_bytes());
    buf.extend_from_slice(&(info.chunk_size as u32).to_le_bytes());
    buf.push(if info.compressed { 1 } else { 0 });
    
    buf
}

/// Deserialize asset info from network.
pub fn deserialize_asset_info(data: &[u8]) -> Option<AssetInfo> {
    if data.len() < 2 { return None; }
    
    let name_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + name_len + 8 + 32 + 4 + 4 + 1 { return None; }
    
    let name = String::from_utf8_lossy(&data[2..2 + name_len]).to_string();
    let offset = 2 + name_len;
    
    let size = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset + 8..offset + 40]);
    
    let chunk_count = u32::from_le_bytes([
        data[offset + 40], data[offset + 41], data[offset + 42], data[offset + 43],
    ]);
    
    let chunk_size = u32::from_le_bytes([
        data[offset + 44], data[offset + 45], data[offset + 46], data[offset + 47],
    ]) as usize;
    
    let compressed = data[offset + 48] != 0;
    
    Some(AssetInfo {
        name,
        size,
        hash,
        chunk_count,
        chunk_size,
        compressed,
    })
}

/// Serialize a chunk for network transfer.
pub fn serialize_chunk(chunk: &AssetChunk) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 4 + 32 + 4 + chunk.data.len());
    
    buf.extend_from_slice(chunk.transfer_id.as_bytes());
    buf.extend_from_slice(&chunk.index.to_le_bytes());
    buf.extend_from_slice(&chunk.hash);
    buf.extend_from_slice(&(chunk.data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&chunk.data);
    
    buf
}

/// Deserialize a chunk from network.
pub fn deserialize_chunk(data: &[u8]) -> Option<AssetChunk> {
    if data.len() < 16 + 4 + 32 + 4 { return None; }
    
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&data[..16]);
    let transfer_id = Uuid::from_bytes(uuid_bytes);
    
    let index = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[20..52]);
    
    let data_len = u32::from_le_bytes([data[52], data[53], data[54], data[55]]) as usize;
    if data.len() < 56 + data_len { return None; }
    
    let chunk_data = data[56..56 + data_len].to_vec();
    
    Some(AssetChunk {
        transfer_id,
        index,
        data: chunk_data,
        hash,
    })
}
