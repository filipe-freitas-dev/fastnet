//! Socket tuning and OS-level optimizations for low-latency networking.
//!
//! This module provides configuration for reducing jitter and improving
//! latency in real-time networking applications.

#![allow(dead_code)] // Public API - some items for future use
//!
//! # Linux Tuning Options
//!
//! - **SO_RCVBUF/SO_SNDBUF**: Larger buffers reduce packet drops
//! - **SO_BUSY_POLL**: CPU polling for reduced latency (requires root)
//! - **IP_TOS/SO_PRIORITY**: QoS marking for network prioritization
//! - **SO_REUSEADDR/SO_REUSEPORT**: Allow address reuse

use std::io;
use std::os::unix::io::AsRawFd;
use tokio::net::UdpSocket;

/// Socket tuning configuration for low-latency networking.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// Receive buffer size in bytes (SO_RCVBUF).
    /// Larger values reduce packet drops under load.
    /// Default: 4MB
    pub recv_buffer_size: usize,
    
    /// Send buffer size in bytes (SO_SNDBUF).
    /// Larger values allow more in-flight packets.
    /// Default: 4MB
    pub send_buffer_size: usize,
    
    /// Busy poll timeout in microseconds (SO_BUSY_POLL).
    /// Set to 0 to disable. Requires CAP_NET_ADMIN.
    /// Trades CPU for lower latency.
    /// Default: 50µs
    pub busy_poll_us: u32,
    
    /// IP Type of Service / DSCP value (IP_TOS).
    /// Common values:
    /// - 0x00: Best effort
    /// - 0x10: Low delay (DSCP CS1)
    /// - 0xB8: Expedited forwarding (DSCP EF, 46 << 2)
    /// Default: 0xB8 (EF - Expedited Forwarding for real-time)
    pub ip_tos: u8,
    
    /// Socket priority (SO_PRIORITY).
    /// Higher values = higher priority (0-6).
    /// Default: 6 (highest)
    pub priority: u32,
    
    /// Enable SO_REUSEADDR.
    /// Default: true
    pub reuse_addr: bool,
    
    /// Enable SO_REUSEPORT (Linux 3.9+).
    /// Allows multiple sockets on same port for load balancing.
    /// Default: false
    pub reuse_port: bool,
    
    /// Disable Nagle's algorithm for TCP (TCP_NODELAY).
    /// Already disabled by default in most cases.
    /// Default: true
    pub tcp_nodelay: bool,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            recv_buffer_size: 4 * 1024 * 1024, // 4MB
            send_buffer_size: 4 * 1024 * 1024, // 4MB
            busy_poll_us: 50,
            ip_tos: 0xB8, // DSCP EF (Expedited Forwarding)
            priority: 6,
            reuse_addr: true,
            reuse_port: false,
            tcp_nodelay: true,
        }
    }
}

impl SocketConfig {
    /// Configuration optimized for minimal latency.
    /// Uses aggressive CPU polling.
    pub fn low_latency() -> Self {
        Self {
            recv_buffer_size: 8 * 1024 * 1024,
            send_buffer_size: 8 * 1024 * 1024,
            busy_poll_us: 100, // More aggressive polling
            ip_tos: 0xB8,
            priority: 6,
            reuse_addr: true,
            reuse_port: false,
            tcp_nodelay: true,
        }
    }
    
    /// Configuration optimized for high throughput.
    /// Larger buffers, less CPU polling.
    pub fn high_throughput() -> Self {
        Self {
            recv_buffer_size: 16 * 1024 * 1024,
            send_buffer_size: 16 * 1024 * 1024,
            busy_poll_us: 0, // Disabled
            ip_tos: 0x00,
            priority: 4,
            reuse_addr: true,
            reuse_port: true,
            tcp_nodelay: true,
        }
    }
    
    /// Apply configuration to a UDP socket.
    #[cfg(target_os = "linux")]
    pub fn apply_udp(&self, socket: &UdpSocket) -> io::Result<()> {
        use std::mem;
        
        let fd = socket.as_raw_fd();
        
        unsafe {
            // SO_RCVBUF
            let val = self.recv_buffer_size as libc::c_int;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &val as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0 {
                // Non-fatal: may need root for large buffers
                eprintln!("Warning: Failed to set SO_RCVBUF (may need root for large buffers)");
            }
            
            // SO_SNDBUF
            let val = self.send_buffer_size as libc::c_int;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &val as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0 {
                eprintln!("Warning: Failed to set SO_SNDBUF");
            }
            
            // SO_BUSY_POLL (requires CAP_NET_ADMIN)
            if self.busy_poll_us > 0 {
                let val = self.busy_poll_us as libc::c_int;
                if libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BUSY_POLL,
                    &val as *const _ as *const libc::c_void,
                    mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) != 0 {
                    // Non-fatal: requires root/CAP_NET_ADMIN
                }
            }
            
            // IP_TOS
            let val = self.ip_tos as libc::c_int;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &val as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0 {
                eprintln!("Warning: Failed to set IP_TOS");
            }
            
            // SO_PRIORITY
            let val = self.priority as libc::c_int;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                &val as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0 {
                // Non-fatal: may need root
            }
        }
        
        Ok(())
    }
    
    /// Apply configuration (no-op on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn apply_udp(&self, _socket: &UdpSocket) -> io::Result<()> {
        Ok(())
    }
}

/// Batch sending/receiving for reduced syscall overhead.
/// Uses sendmmsg/recvmmsg on Linux for multiple packets per syscall.
#[cfg(target_os = "linux")]
pub mod batch {
    use std::io;
    use std::net::SocketAddr;
    use std::os::unix::io::AsRawFd;
    use tokio::net::UdpSocket;
    
    /// Maximum packets per batch operation.
    pub const MAX_BATCH_SIZE: usize = 64;
    
    /// Batch of outgoing packets.
    pub struct SendBatch {
        /// Packet data buffers.
        pub packets: [([u8; super::super::packet::MAX_PACKET_SIZE], usize); MAX_BATCH_SIZE],
        /// Destination addresses.
        pub addrs: [Option<SocketAddr>; MAX_BATCH_SIZE],
        /// Number of packets in batch.
        pub count: usize,
    }
    
    impl SendBatch {
        /// Create a new empty batch.
        pub fn new() -> Self {
            Self {
                packets: [([0u8; super::super::packet::MAX_PACKET_SIZE], 0); MAX_BATCH_SIZE],
                addrs: [None; MAX_BATCH_SIZE],
                count: 0,
            }
        }
        
        /// Add a packet to the batch.
        #[inline]
        pub fn push(&mut self, data: &[u8], addr: SocketAddr) -> bool {
            if self.count >= MAX_BATCH_SIZE {
                return false;
            }
            let len = data.len().min(super::super::packet::MAX_PACKET_SIZE);
            self.packets[self.count].0[..len].copy_from_slice(&data[..len]);
            self.packets[self.count].1 = len;
            self.addrs[self.count] = Some(addr);
            self.count += 1;
            true
        }
        
        /// Clear the batch.
        #[inline]
        pub fn clear(&mut self) {
            self.count = 0;
        }
        
        /// Check if batch is full.
        #[inline]
        pub fn is_full(&self) -> bool {
            self.count >= MAX_BATCH_SIZE
        }
        
        /// Check if batch is empty.
        #[inline]
        pub fn is_empty(&self) -> bool {
            self.count == 0
        }
    }
    
    impl Default for SendBatch {
        fn default() -> Self {
            Self::new()
        }
    }
    
    /// Batch of received packets.
    pub struct RecvBatch {
        /// Packet data buffers.
        pub packets: [([u8; super::super::packet::MAX_PACKET_SIZE], usize); MAX_BATCH_SIZE],
        /// Source addresses.
        pub addrs: [Option<SocketAddr>; MAX_BATCH_SIZE],
        /// Number of packets received.
        pub count: usize,
    }
    
    impl RecvBatch {
        /// Create a new empty batch.
        pub fn new() -> Self {
            Self {
                packets: [([0u8; super::super::packet::MAX_PACKET_SIZE], 0); MAX_BATCH_SIZE],
                addrs: [None; MAX_BATCH_SIZE],
                count: 0,
            }
        }
        
        /// Clear the batch.
        #[inline]
        pub fn clear(&mut self) {
            self.count = 0;
        }
        
        /// Iterate over received packets.
        #[inline]
        pub fn iter(&self) -> impl Iterator<Item = (&[u8], SocketAddr)> {
            (0..self.count).filter_map(move |i| {
                let (buf, len) = &self.packets[i];
                self.addrs[i].map(|addr| (&buf[..*len], addr))
            })
        }
    }
    
    impl Default for RecvBatch {
        fn default() -> Self {
            Self::new()
        }
    }
    
    /// Send multiple packets in a single syscall using sendmmsg.
    /// Returns number of packets sent.
    pub fn sendmmsg(socket: &UdpSocket, batch: &SendBatch) -> io::Result<usize> {
        if batch.count == 0 {
            return Ok(0);
        }
        
        let fd = socket.as_raw_fd();
        
        // Build iovec and mmsghdr arrays
        let mut iovecs: [libc::iovec; MAX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; MAX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
        let mut sockaddrs: [libc::sockaddr_in; MAX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
        
        for i in 0..batch.count {
            let (buf, len) = &batch.packets[i];
            if let Some(addr) = batch.addrs[i] {
                // Set up iovec
                iovecs[i].iov_base = buf.as_ptr() as *mut libc::c_void;
                iovecs[i].iov_len = *len;
                
                // Set up sockaddr
                if let SocketAddr::V4(v4) = addr {
                    sockaddrs[i].sin_family = libc::AF_INET as u16;
                    sockaddrs[i].sin_port = v4.port().to_be();
                    sockaddrs[i].sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                }
                
                // Set up msghdr
                msgs[i].msg_hdr.msg_name = &mut sockaddrs[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }
        }
        
        let sent = unsafe {
            libc::sendmmsg(fd, msgs.as_mut_ptr(), batch.count as libc::c_uint, 0)
        };
        
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }
    
    /// Receive multiple packets in a single syscall using recvmmsg.
    /// Returns number of packets received.
    pub fn recvmmsg(socket: &UdpSocket, batch: &mut RecvBatch, timeout_us: u64) -> io::Result<usize> {
        let fd = socket.as_raw_fd();
        
        // Build iovec and mmsghdr arrays
        let mut iovecs: [libc::iovec; MAX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; MAX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
        let mut sockaddrs: [libc::sockaddr_in; MAX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
        
        for i in 0..MAX_BATCH_SIZE {
            iovecs[i].iov_base = batch.packets[i].0.as_mut_ptr() as *mut libc::c_void;
            iovecs[i].iov_len = super::super::packet::MAX_PACKET_SIZE;
            
            msgs[i].msg_hdr.msg_name = &mut sockaddrs[i] as *mut _ as *mut libc::c_void;
            msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        
        let timeout = libc::timespec {
            tv_sec: (timeout_us / 1_000_000) as i64,
            tv_nsec: ((timeout_us % 1_000_000) * 1000) as i64,
        };
        
        let received = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                MAX_BATCH_SIZE as libc::c_uint,
                libc::MSG_DONTWAIT,
                &timeout as *const libc::timespec as *mut libc::timespec,
            )
        };
        
        if received < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                batch.count = 0;
                return Ok(0);
            }
            return Err(err);
        }
        
        batch.count = received as usize;
        
        // Extract lengths and addresses
        for i in 0..batch.count {
            batch.packets[i].1 = msgs[i].msg_len as usize;
            
            let sa = &sockaddrs[i];
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            batch.addrs[i] = Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
        }
        
        Ok(batch.count)
    }
}

/// Placeholder for non-Linux systems.
#[cfg(not(target_os = "linux"))]
pub mod batch {
    use std::io;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    
    pub const MAX_BATCH_SIZE: usize = 64;
    
    pub struct SendBatch {
        pub count: usize,
    }
    
    impl SendBatch {
        pub fn new() -> Self { Self { count: 0 } }
        pub fn push(&mut self, _data: &[u8], _addr: SocketAddr) -> bool { false }
        pub fn clear(&mut self) { self.count = 0; }
        pub fn is_full(&self) -> bool { true }
        pub fn is_empty(&self) -> bool { true }
    }
    
    impl Default for SendBatch {
        fn default() -> Self { Self::new() }
    }
    
    pub struct RecvBatch {
        pub count: usize,
    }
    
    impl RecvBatch {
        pub fn new() -> Self { Self { count: 0 } }
        pub fn clear(&mut self) { self.count = 0; }
        pub fn iter(&self) -> impl Iterator<Item = (&[u8], SocketAddr)> {
            std::iter::empty()
        }
    }
    
    impl Default for RecvBatch {
        fn default() -> Self { Self::new() }
    }
    
    pub fn sendmmsg(_socket: &UdpSocket, _batch: &SendBatch) -> io::Result<usize> {
        Ok(0)
    }
    
    pub fn recvmmsg(_socket: &UdpSocket, _batch: &mut RecvBatch, _timeout_us: u64) -> io::Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = SocketConfig::default();
        assert_eq!(config.recv_buffer_size, 4 * 1024 * 1024);
        assert_eq!(config.ip_tos, 0xB8);
    }
    
    #[test]
    fn test_low_latency_config() {
        let config = SocketConfig::low_latency();
        assert_eq!(config.busy_poll_us, 100);
    }
}
