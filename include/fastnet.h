/**
 * ╔═╗╔═╗╔═╗╔╦╗╔╗╔╔═╗╔╦╗
 * ╠╣ ╠═╣╚═╗ ║ ║║║║╣  ║   Ultra-low latency encrypted networking
 * ╚  ╩ ╩╚═╝ ╩ ╝╚╝╚═╝ ╩   for real-time games
 *
 *
 * FastNet Network Library - C/C++ API
 * 
 * High-performance networking with built-in encryption:
 * - TLS 1.3 handshake for secure key exchange
 * - ChaCha20-Poly1305 AEAD for packet encryption
 * - ~15µs average RTT on localhost
 * - Zero-copy packet processing
 *
 * Compatible with: Unreal Engine, Unity, Godot, and any C/C++ application.
 *
 * Example (Client):
 * ```c
 *   FastNetClient* client = fastnet_client_connect("127.0.0.1", 7778);
 *   
 *   uint8_t data[] = {1, 2, 3, 4};
 *   fastnet_client_send(client, 0, data, sizeof(data));
 *   
 *   FastNetEvent event;
 *   while (fastnet_client_poll(client, &event)) {
 *       if (event.type == FASTNET_EVENT_DATA) {
 *           // Process event.data, event.data_len
 *       }
 *   }
 *   
 *   fastnet_client_disconnect(client);
 * ```
 */

#ifndef FASTNET_H
#define FASTNET_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Types
// =============================================================================

/**
 * Network event type
 */
typedef enum FastNetEventType {
    FASTNET_EVENT_NONE = 0,        ///< No event
    FASTNET_EVENT_CONNECTED = 1,   ///< Peer connected
    FASTNET_EVENT_DATA = 2,        ///< Data received
    FASTNET_EVENT_DISCONNECTED = 3,///< Peer disconnected
    FASTNET_EVENT_ERROR = 4        ///< Error occurred
} FastNetEventType;

/**
 * Network event structure
 * 
 * @warning The 'data' pointer is only valid until the next poll() call.
 *          Copy the data if you need to keep it.
 */
typedef struct FastNetEvent {
    FastNetEventType type;     ///< Event type
    uint16_t peer_id;       ///< Peer ID this event relates to
    uint8_t channel;        ///< Channel (for DATA events)
    uint8_t* data;          ///< Pointer to data (valid until next poll)
    uint32_t data_len;      ///< Data length in bytes
    int32_t error_code;     ///< Error code (for ERROR events)
} FastNetEvent;

/**
 * Channel types for different reliability modes
 */
typedef enum FastNetChannel {
    FASTNET_CHANNEL_RELIABLE_ORDERED = 0,   ///< Commands, chat (guaranteed order)
    FASTNET_CHANNEL_UNRELIABLE = 1,         ///< Position updates (fast, no guarantee)
    FASTNET_CHANNEL_RELIABLE = 2,           ///< Important events (guaranteed delivery)
    FASTNET_CHANNEL_UNRELIABLE_SEQUENCED = 3 ///< Input, voice (latest only)
} FastNetChannel;

/// Opaque client handle
typedef void* FastNetClient;

/// Opaque server handle  
typedef void* FastNetServer;

// =============================================================================
// Client API
// =============================================================================

/**
 * Connects to a FastNet server.
 * 
 * This establishes a TLS 1.3 connection and exchanges encryption keys.
 * The handshake typically takes 40-50ms.
 * 
 * @param host Server IP address (e.g., "127.0.0.1" or "game.example.com")
 * @param port Server TLS port (e.g., 7778)
 * @return Client handle on success, NULL on failure
 * 
 * @note The connection is fully encrypted after this call returns.
 */
FastNetClient fastnet_client_connect(const char* host, uint16_t port);

/**
 * Disconnects from the server and releases all resources.
 * 
 * @param client Client handle (safe to pass NULL)
 * 
 * @warning The handle becomes invalid after this call.
 */
void fastnet_client_disconnect(FastNetClient client);

/**
 * Sends encrypted data to the server.
 * 
 * @param client  Client handle
 * @param channel Channel ID (0-255, see FastNetChannel for predefined types)
 * @param data    Pointer to data buffer
 * @param data_len Size of data in bytes
 * @return 0 on success, negative on error:
 *         -1 = invalid parameters
 *         -2 = send failed
 *         -3 = not connected
 * 
 * @note Data is encrypted with ChaCha20-Poly1305 before sending.
 */
int32_t fastnet_client_send(
    FastNetClient client,
    uint8_t channel,
    const uint8_t* data,
    uint32_t data_len
);

/**
 * Polls for network events.
 * 
 * Call this regularly (e.g., every frame) to process incoming data.
 * 
 * @param client Client handle
 * @param event  Pointer to event structure to fill
 * @return true if an event was received, false otherwise
 * 
 * @note Call in a loop until it returns false.
 * @warning event->data is only valid until the next poll() call.
 * 
 * Example:
 * ```c
 * FastNetEvent event;
 * while (fastnet_client_poll(client, &event)) {
 *     switch (event.type) {
 *         case FASTNET_EVENT_CONNECTED:
 *             printf("Connected as peer %d\n", event.peer_id);
 *             break;
 *         case FASTNET_EVENT_DATA:
 *             process_packet(event.data, event.data_len);
 *             break;
 *         case FASTNET_EVENT_DISCONNECTED:
 *             printf("Disconnected\n");
 *             break;
 *     }
 * }
 * ```
 */
bool fastnet_client_poll(FastNetClient client, FastNetEvent* event);

/**
 * Returns the estimated round-trip time in microseconds.
 * 
 * @param client Client handle
 * @return RTT in microseconds, or 0 if not available
 */
uint64_t fastnet_client_rtt_us(FastNetClient client);

// =============================================================================
// Server API
// =============================================================================

/**
 * Creates a FastNet server.
 * 
 * @param udp_port  UDP port for encrypted game data (e.g., 7777)
 * @param tcp_port  TCP port for TLS handshake (e.g., 7778)
 * @param cert_path Path to PEM certificate file
 * @param key_path  Path to PEM private key file
 * @return Server handle on success, NULL on failure
 * 
 * @note Generate certificates with:
 *       openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
 */
FastNetServer fastnet_server_create(
    uint16_t udp_port,
    uint16_t tcp_port,
    const char* cert_path,
    const char* key_path
);

/**
 * Destroys the server and releases all resources.
 * 
 * @param server Server handle (safe to pass NULL)
 */
void fastnet_server_destroy(FastNetServer server);

/**
 * Sends encrypted data to a specific peer.
 * 
 * @param server   Server handle
 * @param peer_id  Target peer ID (from CONNECTED event)
 * @param channel  Channel ID
 * @param data     Pointer to data buffer
 * @param data_len Size of data in bytes
 * @return 0 on success, negative on error
 */
int32_t fastnet_server_send(
    FastNetServer server,
    uint16_t peer_id,
    uint8_t channel,
    const uint8_t* data,
    uint32_t data_len
);

/**
 * Polls for network events on the server.
 * 
 * @param server Server handle
 * @param event  Pointer to event structure to fill
 * @return true if an event was received, false otherwise
 */
bool fastnet_server_poll(FastNetServer server, FastNetEvent* event);

/**
 * Returns the number of connected peers.
 * 
 * @param server Server handle
 * @return Number of connected peers
 */
uint32_t fastnet_server_peer_count(FastNetServer server);

// =============================================================================
// Delta Compression API (v0.2)
// =============================================================================

/// Opaque delta encoder handle
typedef void* FastNetDeltaEncoder;

/// Opaque delta decoder handle
typedef void* FastNetDeltaDecoder;

/**
 * Creates a delta encoder for compressing game state updates.
 * 
 * Delta compression sends only what changed between frames,
 * typically achieving 80-95% bandwidth reduction.
 * 
 * @return Encoder handle, or NULL on error
 * 
 * Example:
 * ```c
 * FastNetDeltaEncoder* encoder = fastnet_delta_encoder_create();
 * 
 * uint8_t old_state[512] = {...};
 * uint8_t new_state[512] = {...};  // mostly same, few bytes changed
 * uint8_t delta[512];
 * uint32_t delta_len;
 * 
 * if (fastnet_delta_encode(encoder, old_state, 512, new_state, 512, 
 *                          delta, sizeof(delta), &delta_len) == 0) {
 *     // delta_len is typically much smaller than 512!
 *     fastnet_client_send(client, 0, delta, delta_len);
 * }
 * ```
 */
FastNetDeltaEncoder fastnet_delta_encoder_create(void);

/**
 * Destroys a delta encoder.
 * @param encoder Encoder handle (safe to pass NULL)
 */
void fastnet_delta_encoder_destroy(FastNetDeltaEncoder encoder);

/**
 * Encodes delta between old and new state.
 * 
 * @param encoder         Encoder handle
 * @param old_state       Previous state data
 * @param old_len         Length of old state
 * @param new_state       New state data  
 * @param new_len         Length of new state
 * @param output          Buffer to write delta to
 * @param output_capacity Size of output buffer
 * @param output_len      Receives actual output length
 * @return 0 on success, -1 invalid params, -2 buffer too small, -3 encode failed
 */
int32_t fastnet_delta_encode(
    FastNetDeltaEncoder encoder,
    const uint8_t* old_state,
    uint32_t old_len,
    const uint8_t* new_state,
    uint32_t new_len,
    uint8_t* output,
    uint32_t output_capacity,
    uint32_t* output_len
);

/**
 * Creates a delta decoder for decompressing game state updates.
 * @return Decoder handle, or NULL on error
 */
FastNetDeltaDecoder fastnet_delta_decoder_create(void);

/**
 * Destroys a delta decoder.
 * @param decoder Decoder handle (safe to pass NULL)
 */
void fastnet_delta_decoder_destroy(FastNetDeltaDecoder decoder);

/**
 * Applies delta to state buffer in-place.
 * 
 * @param decoder   Decoder handle
 * @param delta     Delta data received from encoder
 * @param delta_len Length of delta
 * @param state     State buffer to modify in-place
 * @param state_len Length of state buffer
 * @return 0 on success, -1 invalid params, -3 decode failed
 */
int32_t fastnet_delta_apply(
    FastNetDeltaDecoder decoder,
    const uint8_t* delta,
    uint32_t delta_len,
    uint8_t* state,
    uint32_t state_len
);

#ifdef __cplusplus
}
#endif

#endif // FASTNET_H
