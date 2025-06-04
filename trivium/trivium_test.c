#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trivium.h"

/* ================= Test Vectors ================= */

// Test Case 1: 80-bit key=0x80..00, 80-bit IV=0x00..00
static const uint8_t TEST1_KEY[10] = {
    0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t TEST1_IV[10] = {
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t TEST1_KEYSTREAM[64] = {
    0x38, 0xEB, 0x86, 0xFF, 0x73, 0x0D, 0x7A, 0x9C,
    0xAF, 0x8D, 0xF1, 0x3A, 0x44, 0x20, 0x54, 0x0D,
    0xBB, 0x7B, 0x65, 0x14, 0x64, 0xC8, 0x75, 0x01,
    0x55, 0x20, 0x41, 0xC2, 0x49, 0xF2, 0x9A, 0x64,
    0xD2, 0xFB, 0xF5, 0x15, 0x61, 0x09, 0x21, 0xEB,
    0xE0, 0x6C, 0x8F, 0x92, 0xCE, 0xCF, 0x7F, 0x80,
    0x98, 0xFF, 0x20, 0xCC, 0xCC, 0x6A, 0x62, 0xB9,
    0x7B, 0xE8, 0xEF, 0x74, 0x54, 0xFC, 0x80, 0xF9
};



int test_trivium() {
    uint8_t plaintext[64] = {0}; // All-zero plaintext
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    int test_passed = 1;

    // ========== Test Case 1 ==========
    {
        printf("\n========== Test Case 1 ==========\n");

        // Print key (10 bytes)
        printf("Key (10 bytes): ");
        for (int i = 0; i < sizeof(TEST1_KEY); i++) {
            printf("%02X ", TEST1_KEY[i]);
        }
        printf("\n");

        // Print IV (10 bytes)
        printf("IV (10 bytes): ");
        for (int i = 0; i < sizeof(TEST1_IV); i++) {
            printf("%02X ", TEST1_IV[i]);
        }
        printf("\n");

        // Perform encryption
        trivium_encrypt(
            plaintext, sizeof(plaintext),
            TEST1_KEY, sizeof(TEST1_KEY),
            TEST1_IV, sizeof(TEST1_IV),
            ciphertext, sizeof(ciphertext)
        );

        // Print ciphertext (first 16 bytes)
        printf("Ciphertext (first 16 bytes): ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", ciphertext[i]);
        }
        printf("...\n");

        // Verify encryption
        if (memcmp(ciphertext, TEST1_KEYSTREAM, sizeof(ciphertext)) == 0) {
            printf("[PASS] Encryption\n");
        } else {
            printf("[FAIL] Encryption\n");
            test_passed = 0;
            for (int j = 0; j < 8; j++) { // Print first 8 mismatches
                if (ciphertext[j] != TEST1_KEYSTREAM[j]) {
                    printf("First mismatch at %d: Expected=%02X Actual=%02X\n",
                        j, TEST1_KEYSTREAM[j], ciphertext[j]);
                }
            }
        }

        // Perform decryption
        trivium_decrypt(
            ciphertext, sizeof(ciphertext),
            TEST1_KEY, sizeof(TEST1_KEY),
            TEST1_IV, sizeof(TEST1_IV),
            decrypted, sizeof(decrypted)
        );

        // Verify decryption
        if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
            printf("[PASS] Decryption\n");
        } else {
            printf("[FAIL] Decryption\n");
            test_passed = 0;
            for (int j = 0; j < sizeof(plaintext); j++) {
                if (decrypted[j] != plaintext[j]) {
                    printf("First mismatch at %d: Expected=%02X Actual=%02X\n",
                        j, plaintext[j], decrypted[j]);
                    break;
                }
            }
        }
    }



    // Final result
    printf("\n========== Final Test Result ==========\n");
    if (test_passed) {
        printf("ALL TESTS PASSED!\n");
        return 0;
    } else {
        printf("TEST FAILED!\n");
        return -1;
    }
}