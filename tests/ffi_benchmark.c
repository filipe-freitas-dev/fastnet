/**
 * FastNet FFI Benchmark - Delta Compression Performance
 * 
 * Compile:
 *   gcc -O3 -o ffi_benchmark tests/ffi_benchmark.c -L target/release -lfastnet -I include
 * 
 * Run:
 *   LD_LIBRARY_PATH=target/release ./ffi_benchmark
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "../include/fastnet.h"

#define ITERATIONS 100000
#define STATE_SIZE 512

// Get time in nanoseconds
static inline uint64_t get_nanos() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main() {
    printf("╔═══════════════════════════════════════╗\n");
    printf("║   FastNet FFI Delta Benchmark         ║\n");
    printf("╠═══════════════════════════════════════╣\n");
    printf("║  Iterations: %d                   ║\n", ITERATIONS);
    printf("║  State Size: %d bytes                 ║\n", STATE_SIZE);
    printf("╚═══════════════════════════════════════╝\n\n");

    // Create encoder and decoder
    FastNetDeltaEncoder encoder = fastnet_delta_encoder_create();
    FastNetDeltaDecoder decoder = fastnet_delta_decoder_create();

    if (!encoder || !decoder) {
        printf("ERROR: Failed to create encoder/decoder\n");
        return 1;
    }

    // Prepare test data
    uint8_t old_state[STATE_SIZE];
    uint8_t new_state[STATE_SIZE];
    uint8_t delta[1024];
    uint8_t reconstructed[STATE_SIZE];
    uint32_t delta_len;

    // Initialize states
    for (int i = 0; i < STATE_SIZE; i++) {
        old_state[i] = (uint8_t)(i % 256);
        new_state[i] = (uint8_t)(i % 256);
    }

    // Simulate typical game update: 3 small changes
    new_state[0] = 100;    // position x
    new_state[4] = 150;    // position y
    new_state[8] = 75;     // position z

    uint64_t encode_times[ITERATIONS];
    uint64_t decode_times[ITERATIONS];
    int encode_failures = 0;
    int decode_failures = 0;
    uint64_t total_delta_size = 0;

    printf("Running benchmark...\n");

    // Benchmark encode
    for (int i = 0; i < ITERATIONS; i++) {
        // Vary the change slightly each iteration
        new_state[0] = (uint8_t)(100 + (i % 50));

        uint64_t start = get_nanos();
        int result = fastnet_delta_encode(encoder, old_state, STATE_SIZE, 
                                          new_state, STATE_SIZE,
                                          delta, sizeof(delta), &delta_len);
        uint64_t end = get_nanos();

        if (result == 0) {
            encode_times[i - encode_failures] = end - start;
            total_delta_size += delta_len;
        } else {
            encode_failures++;
        }

        if (i % 20000 == 0 && i > 0) {
            printf("  Progress: %d/%d\n", i, ITERATIONS);
        }
    }

    // Benchmark decode
    // First encode a valid delta
    new_state[0] = 100;
    fastnet_delta_encode(encoder, old_state, STATE_SIZE, new_state, STATE_SIZE,
                         delta, sizeof(delta), &delta_len);

    for (int i = 0; i < ITERATIONS; i++) {
        memcpy(reconstructed, old_state, STATE_SIZE);

        uint64_t start = get_nanos();
        int result = fastnet_delta_apply(decoder, delta, delta_len, 
                                         reconstructed, STATE_SIZE);
        uint64_t end = get_nanos();

        if (result == 0) {
            decode_times[i - decode_failures] = end - start;
        } else {
            decode_failures++;
        }
    }

    // Calculate statistics
    int valid_encodes = ITERATIONS - encode_failures;
    int valid_decodes = ITERATIONS - decode_failures;

    // Sort for percentiles
    for (int i = 0; i < valid_encodes - 1; i++) {
        for (int j = i + 1; j < valid_encodes; j++) {
            if (encode_times[i] > encode_times[j]) {
                uint64_t tmp = encode_times[i];
                encode_times[i] = encode_times[j];
                encode_times[j] = tmp;
            }
        }
    }

    for (int i = 0; i < valid_decodes - 1; i++) {
        for (int j = i + 1; j < valid_decodes; j++) {
            if (decode_times[i] > decode_times[j]) {
                uint64_t tmp = decode_times[i];
                decode_times[i] = decode_times[j];
                decode_times[j] = tmp;
            }
        }
    }

    uint64_t encode_sum = 0;
    for (int i = 0; i < valid_encodes; i++) encode_sum += encode_times[i];

    uint64_t decode_sum = 0;
    for (int i = 0; i < valid_decodes; i++) decode_sum += decode_times[i];

    printf("\n┌─────────────────────────────────────────┐\n");
    printf("│            Encode Results               │\n");
    printf("├─────────────────────────────────────────┤\n");
    printf("│  Min:      %8.3f ns                  │\n", (double)encode_times[0]);
    printf("│  Avg:      %8.3f ns                  │\n", (double)encode_sum / valid_encodes);
    printf("│  Median:   %8.3f ns                  │\n", (double)encode_times[valid_encodes/2]);
    printf("│  P99:      %8.3f ns                  │\n", (double)encode_times[(int)(valid_encodes * 0.99)]);
    printf("│  Max:      %8.3f ns                  │\n", (double)encode_times[valid_encodes-1]);
    printf("│  Failures: %d                            │\n", encode_failures);
    printf("└─────────────────────────────────────────┘\n");

    printf("\n┌─────────────────────────────────────────┐\n");
    printf("│            Decode Results               │\n");
    printf("├─────────────────────────────────────────┤\n");
    printf("│  Min:      %8.3f ns                  │\n", (double)decode_times[0]);
    printf("│  Avg:      %8.3f ns                  │\n", (double)decode_sum / valid_decodes);
    printf("│  Median:   %8.3f ns                  │\n", (double)decode_times[valid_decodes/2]);
    printf("│  P99:      %8.3f ns                  │\n", (double)decode_times[(int)(valid_decodes * 0.99)]);
    printf("│  Max:      %8.3f ns                  │\n", (double)decode_times[valid_decodes-1]);
    printf("│  Failures: %d                            │\n", decode_failures);
    printf("└─────────────────────────────────────────┘\n");

    printf("\n┌─────────────────────────────────────────┐\n");
    printf("│            Compression Stats            │\n");
    printf("├─────────────────────────────────────────┤\n");
    printf("│  Original:    %d bytes                  │\n", STATE_SIZE);
    printf("│  Avg Delta:   %.1f bytes                 │\n", (double)total_delta_size / valid_encodes);
    printf("│  Compression: %.1f%%                     │\n", 
           (1.0 - (double)total_delta_size / valid_encodes / STATE_SIZE) * 100.0);
    printf("└─────────────────────────────────────────┘\n");

    // Throughput
    double encode_avg_ns = (double)encode_sum / valid_encodes;
    double decode_avg_ns = (double)decode_sum / valid_decodes;
    double encode_ops_per_sec = 1000000000.0 / encode_avg_ns;
    double decode_ops_per_sec = 1000000000.0 / decode_avg_ns;

    printf("\n┌─────────────────────────────────────────┐\n");
    printf("│            Throughput                   │\n");
    printf("├─────────────────────────────────────────┤\n");
    printf("│  Encode: %.0f ops/sec               │\n", encode_ops_per_sec);
    printf("│  Decode: %.0f ops/sec               │\n", decode_ops_per_sec);
    printf("└─────────────────────────────────────────┘\n");

    // Cleanup
    fastnet_delta_encoder_destroy(encoder);
    fastnet_delta_decoder_destroy(decoder);

    return 0;
}
