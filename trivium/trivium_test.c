#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "trivium.h"
#include "../utils/test_utils.h"

#define TEST_SIZE 64

/**
 *  测试向量来源：
 */
static const uint8_t TEST_KEY[10] = {
    0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t TEST_IV[10] = {
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t EXPECTED_KEYSTREAM[TEST_SIZE] = {
    0x38, 0xEB, 0x86, 0xFF, 0x73, 0x0D, 0x7A, 0x9C,
    0xAF, 0x8D, 0xF1, 0x3A, 0x44, 0x20, 0x54, 0x0D,
    0xBB, 0x7B, 0x65, 0x14, 0x64, 0xC8, 0x75, 0x01,
    0x55, 0x20, 0x41, 0xC2, 0x49, 0xF2, 0x9A, 0x64,
    0xD2, 0xFB, 0xF5, 0x15, 0x61, 0x09, 0x21, 0xEB,
    0xE0, 0x6C, 0x8F, 0x92, 0xCE, 0xCF, 0x7F, 0x80,
    0x98, 0xFF, 0x20, 0xCC, 0xCC, 0x6A, 0x62, 0xB9,
    0x7B, 0xE8, 0xEF, 0x74, 0x54, 0xFC, 0x80, 0xF9
};


void print_hex_compact(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}


int test_trivium_keystream() {
    print_test_header("Trivium Keystream Verification");

    uint8_t plaintext[TEST_SIZE] = {0};
    uint8_t ciphertext[TEST_SIZE];

    if (!trivium_encrypt(plaintext, TEST_SIZE,
                         TEST_KEY, sizeof(TEST_KEY),
                         TEST_IV, sizeof(TEST_IV),
                         ciphertext, TEST_SIZE)) {
        printf("Error: Encryption failed\n");
        return 0;
    }

    print_hex_compact("Key", TEST_KEY, sizeof(TEST_KEY));
    print_hex_compact("IV", TEST_IV, sizeof(TEST_IV));
    print_hex_compact("Expected Keystream", EXPECTED_KEYSTREAM, 16);
    print_hex_compact("Actual Keystream", ciphertext, 16);

    if (memcmp(ciphertext, EXPECTED_KEYSTREAM, TEST_SIZE) == 0) {
        printf("Result: PASS\n");
    } else {
        printf("Result: FAIL\n");

        for (int i = 0; i < TEST_SIZE; i++) {
            if (ciphertext[i] != EXPECTED_KEYSTREAM[i]) {
                printf("First mismatch at [%d]: Expected = 0x%02X, Actual = 0x%02X\n",
                      i, EXPECTED_KEYSTREAM[i], ciphertext[i]);
                break;
            }
        }
    }

    return 1;
}


int test_trivium_encryption_symmetry() {
    print_test_header("Trivium Encryption/Decryption Symmetry");

    const char* message = "Test message for Trivium";
    size_t message_len = strlen(message);
    uint8_t ciphertext[128] = {0};
    uint8_t decrypted[128] = {0};

    printf("Original plaintext: %s\n", message);
    print_hex_compact("Plaintext (HEX)", (const uint8_t*)message, message_len);

    if (!trivium_encrypt((const uint8_t*)message, message_len,
                         TEST_KEY, sizeof(TEST_KEY),
                         TEST_IV, sizeof(TEST_IV),
                         ciphertext, message_len)) {
        printf("Error: Encryption failed\n");
        return 0;
    }

    if (!trivium_decrypt(ciphertext, message_len,
                         TEST_KEY, sizeof(TEST_KEY),
                         TEST_IV, sizeof(TEST_IV),
                         decrypted, message_len)) {
        printf("Error: Decryption failed\n");
        return 0;
    }

    print_hex_compact("Ciphertext", ciphertext, message_len);
    printf("Decrypted text: %s\n", decrypted);

    if (memcmp(message, decrypted, message_len) == 0) {
        printf("Result: PASS\n");
    } else {
        printf("Result: FAIL\n");
    }

    return 1;
}


int test_trivium() {
    printf("\n=== Starting Trivium Tests ===\n\n");

    test_trivium_keystream();
    printf("\n");
    test_trivium_encryption_symmetry();

    printf("\n=== Trivium Tests Completed ===\n");
    return 0;
}