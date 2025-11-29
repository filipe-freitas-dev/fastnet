//! # FastNet FFI - C/C++ Foreign Function Interface
//!
//! This module provides C-compatible bindings for using FastNet in game engines
//! like Unreal Engine, Unity, or any C/C++ application.
//!
//! ## Thread Safety
//!
//! All FFI functions are **NOT thread-safe**. Each client/server handle must be
//! used from a single thread at a time. For multi-threaded usage, protect access
//! with mutexes on the C/C++ side.
//!
//! ## Memory Management
//!
//! - Handles returned by `fastnet_client_connect` and `fastnet_server_create` must be
//!   freed with their corresponding destroy functions.
//! - Data pointers in events are valid only until the next `poll` call.

use std::ffi::{c_char, CStr};
use std::net::SocketAddr;
use std::ptr;
use std::slice;

use tokio::runtime::Runtime;

use crate::net::fast::{SecureSocket, SecureEvent};

/// Event types that can be received from the network.
#[repr(C)]
pub enum FastNetEventType {
    /// No event available
    None = 0,
    /// A peer has connected
    Connected = 1,
    /// Data received from a peer
    Data = 2,
    /// A peer has disconnected
    Disconnected = 3,
    /// An error occurred
    Error = 4,
}

/// Network event structure.
///
/// # Safety
///
/// The `data` pointer is only valid until the next call to `fastnet_*_poll()`.
/// Copy the data if you need to keep it longer.
#[repr(C)]
pub struct FastNetEvent {
    /// Type of the event
    pub event_type: FastNetEventType,
    /// ID of the peer this event relates to
    pub peer_id: u16,
    /// Channel the data was received on (for Data events)
    pub channel: u8,
    /// Pointer to received data (valid until next poll)
    pub data: *mut u8,
    /// Length of received data in bytes
    pub data_len: u32,
    /// Error code (for Error events)
    pub error_code: i32,
}

impl Default for FastNetEvent {
    fn default() -> Self {
        Self {
            event_type: FastNetEventType::None,
            peer_id: 0,
            channel: 0,
            data: ptr::null_mut(),
            data_len: 0,
            error_code: 0,
        }
    }
}

/// Opaque client handle
pub struct FastNetClient {
    runtime: Runtime,
    socket: Option<SecureSocket>,
    last_data: Option<Vec<u8>>,
    server_peer_id: u16,
}

/// Opaque server handle
pub struct FastNetServer {
    runtime: Runtime,
    socket: Option<SecureSocket>,
    last_data: Option<Vec<u8>>,
}

// =============================================================================
// Client API
// =============================================================================

/// Connects to a FastNet server.
///
/// # Parameters
/// - `host`: Server address (e.g., "127.0.0.1")
/// - `port`: Server TLS port (e.g., 7778)
///
/// # Returns
/// - Handle to the client, or NULL on error
///
/// # Note
/// The TLS handshake takes ~40-50ms on first connection.
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_client_connect(
    host: *const c_char,
    port: u16,
) -> *mut FastNetClient {
    if host.is_null() {
        return ptr::null_mut();
    }

    let host_str = unsafe {
        match CStr::from_ptr(host).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let addr: SocketAddr = match format!("{}:{}", host_str, port).parse() {
        Ok(a) => a,
        Err(_) => return ptr::null_mut(),
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let socket = runtime.block_on(async {
        SecureSocket::connect(addr).await.ok()
    });

    if socket.is_none() {
        return ptr::null_mut();
    }

    let client = Box::new(FastNetClient {
        runtime,
        socket,
        last_data: None,
        server_peer_id: 0,
    });

    Box::into_raw(client)
}

/// Disconnects from the server and frees resources.
///
/// # Safety
/// The handle becomes invalid after this call.
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_client_disconnect(client: *mut FastNetClient) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

/// Sends data to the server.
///
/// # Parameters
/// - `client`: Client handle
/// - `channel`: Channel ID (0-255)
/// - `data`: Pointer to data buffer
/// - `data_len`: Length of data in bytes
///
/// # Returns
/// - `0` on success
/// - `-1` if parameters are invalid
/// - `-2` if send failed
/// - `-3` if not connected
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_client_send(
    client: *mut FastNetClient,
    channel: u8,
    data: *const u8,
    data_len: u32,
) -> i32 {
    if client.is_null() || data.is_null() {
        return -1;
    }

    let client = unsafe { &mut *client };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };

    if let Some(ref mut socket) = client.socket {
        let peer_id = client.server_peer_id;
        let result = client.runtime.block_on(async {
            socket.send(peer_id, channel, data_slice.to_vec()).await
        });

        match result {
            Ok(_) => 0,
            Err(_) => -2,
        }
    } else {
        -3
    }
}

/// Polls for network events.
///
/// # Parameters
/// - `client`: Client handle
/// - `event`: Pointer to event structure to fill
///
/// # Returns
/// - `true` if an event was received
/// - `false` if no events pending
///
/// # Note
/// Call in a loop until it returns `false`.
/// The `event.data` pointer is only valid until the next poll.
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_client_poll(
    client: *mut FastNetClient,
    event: *mut FastNetEvent,
) -> bool {
    if client.is_null() || event.is_null() {
        return false;
    }

    let client = unsafe { &mut *client };
    let event = unsafe { &mut *event };

    *event = FastNetEvent::default();
    client.last_data = None;

    if let Some(ref mut socket) = client.socket {
        let events = client.runtime.block_on(async {
            socket.poll().await.unwrap_or_default()
        });

        if let Some(e) = events.into_iter().next() {
            match e {
                SecureEvent::Connected(peer_id) => {
                    event.event_type = FastNetEventType::Connected;
                    event.peer_id = peer_id;
                    client.server_peer_id = peer_id;
                    return true;
                }
                SecureEvent::Data(peer_id, channel, data) => {
                    event.event_type = FastNetEventType::Data;
                    event.peer_id = peer_id;
                    event.channel = channel;
                    event.data_len = data.len() as u32;

                    client.last_data = Some(data);
                    if let Some(ref d) = client.last_data {
                        event.data = d.as_ptr() as *mut u8;
                    }
                    return true;
                }
                SecureEvent::Disconnected(peer_id) => {
                    event.event_type = FastNetEventType::Disconnected;
                    event.peer_id = peer_id;
                    return true;
                }
            }
        }
    }

    false
}

/// Returns the estimated RTT in microseconds.
///
/// # Parameters
/// - `client`: Client handle
///
/// # Returns
/// RTT in microseconds, or 0 if unavailable
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_client_rtt_us(client: *mut FastNetClient) -> u64 {
    if client.is_null() {
        return 0;
    }

    let client = unsafe { &*client };

    if let Some(ref socket) = client.socket {
        socket.peer_rtt(0).map(|d| d.as_micros() as u64).unwrap_or(0)
    } else {
        0
    }
}

// =============================================================================
// Server API
// =============================================================================

/// Creates a FastNet server.
///
/// # Parameters
/// - `udp_port`: UDP port for game data (e.g., 7777)
/// - `tcp_port`: TCP port for TLS handshake (e.g., 7778)
/// - `cert_path`: Path to PEM certificate file
/// - `key_path`: Path to PEM private key file
///
/// # Returns
/// Handle to the server, or NULL on error
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_server_create(
    udp_port: u16,
    tcp_port: u16,
    cert_path: *const c_char,
    key_path: *const c_char,
) -> *mut FastNetServer {
    if cert_path.is_null() || key_path.is_null() {
        return ptr::null_mut();
    }

    let cert_str = unsafe {
        match CStr::from_ptr(cert_path).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let key_str = unsafe {
        match CStr::from_ptr(key_path).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let socket = runtime.block_on(async {
        use std::fs::File;
        use std::io::BufReader;
        use rustls_pemfile::{certs, private_key};

        let cert_file = File::open(cert_str).ok()?;
        let key_file = File::open(key_str).ok()?;

        let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
            .filter_map(|r| r.ok())
            .collect();
        let key = private_key(&mut BufReader::new(key_file)).ok()??;

        let udp_addr: SocketAddr = format!("0.0.0.0:{}", udp_port).parse().ok()?;
        let tcp_addr: SocketAddr = format!("0.0.0.0:{}", tcp_port).parse().ok()?;

        SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await.ok()
    });

    if socket.is_none() {
        return ptr::null_mut();
    }

    let server = Box::new(FastNetServer {
        runtime,
        socket,
        last_data: None,
    });

    Box::into_raw(server)
}

/// Destroys the server and frees resources.
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_server_destroy(server: *mut FastNetServer) {
    if !server.is_null() {
        unsafe {
            drop(Box::from_raw(server));
        }
    }
}

/// Sends data to a specific peer.
///
/// # Parameters
/// - `server`: Server handle
/// - `peer_id`: Target peer ID
/// - `channel`: Channel ID
/// - `data`: Pointer to data buffer
/// - `data_len`: Length of data in bytes
///
/// # Returns
/// - `0` on success
/// - Negative value on error
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_server_send(
    server: *mut FastNetServer,
    peer_id: u16,
    channel: u8,
    data: *const u8,
    data_len: u32,
) -> i32 {
    if server.is_null() || data.is_null() {
        return -1;
    }

    let server = unsafe { &mut *server };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };

    if let Some(ref mut socket) = server.socket {
        let result = server.runtime.block_on(async {
            socket.send(peer_id, channel, data_slice.to_vec()).await
        });

        match result {
            Ok(_) => 0,
            Err(_) => -2,
        }
    } else {
        -3
    }
}

/// Polls for network events on the server.
///
/// # Parameters
/// - `server`: Server handle
/// - `event`: Pointer to event structure to fill
///
/// # Returns
/// - `true` if an event was received
/// - `false` if no events pending
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_server_poll(
    server: *mut FastNetServer,
    event: *mut FastNetEvent,
) -> bool {
    if server.is_null() || event.is_null() {
        return false;
    }

    let server = unsafe { &mut *server };
    let event = unsafe { &mut *event };

    *event = FastNetEvent::default();
    server.last_data = None;

    if let Some(ref mut socket) = server.socket {
        let events = server.runtime.block_on(async {
            socket.poll().await.unwrap_or_default()
        });

        if let Some(e) = events.into_iter().next() {
            match e {
                SecureEvent::Connected(peer_id) => {
                    event.event_type = FastNetEventType::Connected;
                    event.peer_id = peer_id;
                    return true;
                }
                SecureEvent::Data(peer_id, channel, data) => {
                    event.event_type = FastNetEventType::Data;
                    event.peer_id = peer_id;
                    event.channel = channel;
                    event.data_len = data.len() as u32;

                    server.last_data = Some(data);
                    if let Some(ref d) = server.last_data {
                        event.data = d.as_ptr() as *mut u8;
                    }
                    return true;
                }
                SecureEvent::Disconnected(peer_id) => {
                    event.event_type = FastNetEventType::Disconnected;
                    event.peer_id = peer_id;
                    return true;
                }
            }
        }
    }

    false
}

/// Returns the number of connected peers.
#[unsafe(no_mangle)]
pub extern "C" fn fastnet_server_peer_count(server: *mut FastNetServer) -> u32 {
    if server.is_null() {
        return 0;
    }

    let server = unsafe { &*server };

    if let Some(ref socket) = server.socket {
        socket.peer_count() as u32
    } else {
        0
    }
}
