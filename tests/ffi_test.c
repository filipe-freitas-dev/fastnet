/**
 * FastNet FFI Test - Delta Compression
 * 
 * Compile with:
 *   gcc -o ffi_test tests/ffi_test.c -L target/release -lfastnet -Wl,-rpath,target/release
 * 
 * Run with:
 *   ./ffi_test
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/fastnet.h"

int main() {
    printf("FastNet FFI Test - Delta Compression\n");
    printf("=====================================\n\n");

    // Create encoder and decoder
    FastNetDeltaEncoder encoder = fastnet_delta_encoder_create();
    FastNetDeltaDecoder decoder = fastnet_delta_decoder_create();

    if (!encoder || !decoder) {
        printf("ERROR: Failed to create encoder/decoder\n");
        return 1;
    }
    printf("✓ Created encoder and decoder\n");

    // Test 1: Simple delta - only position changed
    printf("\n--- Test 1: Position Update ---\n");
    {
        // Game state: x, y, z, health, ammo (each 4 bytes = 20 bytes total)
        uint8_t old_state[20] = {
            100, 0, 0, 0,   // x = 100
            200, 0, 0, 0,   // y = 200
            50, 0, 0, 0,    // z = 50
            100, 0, 0, 0,   // health = 100
            30, 0, 0, 0     // ammo = 30
        };

        uint8_t new_state[20] = {
            101, 0, 0, 0,   // x = 101 (moved!)
            200, 0, 0, 0,   // y = 200
            50, 0, 0, 0,    // z = 50
            100, 0, 0, 0,   // health = 100
            30, 0, 0, 0     // ammo = 30
        };

        uint8_t delta[64];
        uint32_t delta_len = 0;

        int result = fastnet_delta_encode(encoder, old_state, 20, new_state, 20,
                                          delta, sizeof(delta), &delta_len);

        if (result == 0) {
            printf("  Original size: 20 bytes\n");
            printf("  Delta size:    %u bytes\n", delta_len);
            printf("  Compression:   %.1f%%\n", (1.0 - (float)delta_len / 20.0) * 100.0);
        } else {
            printf("  ERROR: Encode failed with code %d\n", result);
        }
    }

    // Test 2: Multiple changes (delta > original = expected to fail)
    printf("\n--- Test 2: Many Changes (delta > state) ---\n");
    {
        uint8_t old_state[20] = {
            100, 0, 0, 0,
            200, 0, 0, 0,
            50, 0, 0, 0,
            100, 0, 0, 0,
            30, 0, 0, 0
        };

        uint8_t new_state[20] = {
            105, 0, 0, 0,   // x changed
            210, 0, 0, 0,   // y changed
            50, 0, 0, 0,    // z same
            95, 0, 0, 0,    // health changed (took damage)
            29, 0, 0, 0     // ammo changed (fired)
        };

        uint8_t delta[64];
        uint32_t delta_len = 0;

        int result = fastnet_delta_encode(encoder, old_state, 20, new_state, 20,
                                          delta, sizeof(delta), &delta_len);

        if (result == 0) {
            printf("  Delta size: %u bytes\n", delta_len);
        } else if (result == -3) {
            // Expected! Delta would be larger than original (4 ranges × 5 bytes = 20+)
            printf("  ✓ Correctly returned -3 (delta > state size)\n");
            printf("  Action: Send full state instead (20 bytes)\n");
            printf("  Why: 4 changes × (4 byte header + 1 byte data) = 24 bytes > 20\n");
        } else {
            printf("  ERROR: Unexpected code %d\n", result);
        }
    }

    // Test 3: No changes (should be minimal)
    printf("\n--- Test 3: No Changes ---\n");
    {
        uint8_t state[20] = {100, 0, 0, 0, 200, 0, 0, 0, 50, 0, 0, 0, 100, 0, 0, 0, 30, 0, 0, 0};

        uint8_t delta[64];
        uint32_t delta_len = 0;

        int result = fastnet_delta_encode(encoder, state, 20, state, 20,
                                          delta, sizeof(delta), &delta_len);

        if (result == 0) {
            printf("  Original size: 20 bytes\n");
            printf("  Delta size:    %u bytes (just header)\n", delta_len);
            printf("  Compression:   %.1f%%\n", (1.0 - (float)delta_len / 20.0) * 100.0);
        } else {
            printf("  ERROR: Encode failed with code %d\n", result);
        }
    }

    // Test 4: Large state (512 bytes, simulating full player state)
    printf("\n--- Test 4: Large State (512 bytes) ---\n");
    {
        uint8_t old_state[512];
        uint8_t new_state[512];
        
        // Initialize with some pattern
        for (int i = 0; i < 512; i++) {
            old_state[i] = (uint8_t)(i % 256);
            new_state[i] = (uint8_t)(i % 256);
        }
        
        // Change just a few bytes (typical game update)
        new_state[0] = 100;    // position x
        new_state[4] = 150;    // position y
        new_state[100] = 50;   // some stat

        uint8_t delta[1024];
        uint32_t delta_len = 0;

        int result = fastnet_delta_encode(encoder, old_state, 512, new_state, 512,
                                          delta, sizeof(delta), &delta_len);

        if (result == 0) {
            printf("  Original size: 512 bytes\n");
            printf("  Delta size:    %u bytes\n", delta_len);
            printf("  Compression:   %.1f%%\n", (1.0 - (float)delta_len / 512.0) * 100.0);
        } else {
            printf("  ERROR: Encode failed with code %d\n", result);
        }
    }

    // Cleanup
    fastnet_delta_encoder_destroy(encoder);
    fastnet_delta_decoder_destroy(decoder);
    printf("\n✓ Cleanup complete\n");

    printf("\n=====================================\n");
    printf("FFI Test Complete!\n");

    return 0;
}
