#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "rc4.h"
#include "../utils/test_utils.h"

#define TEST_SIZE 16

/**
 * RC4 has no fixed key length requirement, so we use three official test vectors
 * with different key lengths (RFC 6229)
 */

/* ================ Test Vectors (RFC 6229) ================ */
static const uint8_t TEST1_KEY[] = {0x01, 0x02, 0x03, 0x04, 0x05};
static const uint8_t TEST1_KEYSTREAM[] = {
    0xB2, 0x39, 0x63, 0x05, 0xF0, 0x3D, 0xC0, 0x27,
    0xCC, 0xC3, 0x52, 0x4A, 0x0A, 0x11, 0x18, 0xA8
};

static const uint8_t TEST2_KEY[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
static const uint8_t TEST2_KEYSTREAM[] = {
    0x29, 0x3F, 0x02, 0xD4, 0x7F, 0x37, 0xC9, 0xB6,
    0x33, 0xF2, 0xAF, 0x52, 0x85, 0xFE, 0xB4, 0x6B
};

static const uint8_t TEST3_KEY[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const uint8_t TEST3_KEYSTREAM[] = {
    0x97, 0xAB, 0x8A, 0x1B, 0xF0, 0xAF, 0xB9, 0x61,
    0x32, 0xF2, 0xF6, 0x72, 0x58, 0xDA, 0x15, 0xA8
};

typedef struct {
    const char* name;
    const uint8_t* key;
    int key_len;
    const uint8_t* keystream;
} TestCase;

static TestCase test_cases[] = {
    {"40-bit key", TEST1_KEY, sizeof(TEST1_KEY), TEST1_KEYSTREAM},
    {"56-bit key", TEST2_KEY, sizeof(TEST2_KEY), TEST2_KEYSTREAM},
    {"64-bit key", TEST3_KEY, sizeof(TEST3_KEY), TEST3_KEYSTREAM}
};
/* ================ End of Test Vectors ================ */

void test_keystream() {
    print_test_header("RC4 Keystream Test");

    uint8_t zero_plaintext[TEST_SIZE] = {0};
    uint8_t output[TEST_SIZE];

    for (int i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        TestCase tc = test_cases[i];
        printf("\nTest Case %d: %s\n", i+1, tc.name);

        print_hex("Key", tc.key, tc.key_len);
        print_hex("Expected Keystream", tc.keystream, TEST_SIZE);

        if (!rc4_encrypt(zero_plaintext, TEST_SIZE, tc.key, tc.key_len, output, TEST_SIZE)) {
            printf("Error: Encryption failed\n");
            continue;
        }
        print_hex("Actual Keystream", output, TEST_SIZE);

        printf("Result: %s\n", memcmp(output, tc.keystream, TEST_SIZE) ? "FAIL!" : "PASS!");
    }
}

void test_symmetry() {
    print_test_header("RC4 Encryption/Decryption Test");

    const uint8_t plaintext[] = "RC4 test data";
    const int plaintext_len = sizeof(plaintext)-1;
    uint8_t ciphertext[plaintext_len];
    uint8_t decrypted[plaintext_len];

    for (int i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        TestCase tc = test_cases[i];
        printf("\nTest Case %d: %s\n", i+1, tc.name);

        print_hex("Key", tc.key, tc.key_len);
        print_hex("Plaintext", plaintext, plaintext_len);

        if (!rc4_encrypt(plaintext, plaintext_len, tc.key, tc.key_len, ciphertext, plaintext_len)) {
            printf("Error: Encryption failed\n");
            continue;
        }
        print_hex("Ciphertext", ciphertext, plaintext_len);

        if (!rc4_decrypt(ciphertext, plaintext_len, tc.key, tc.key_len, decrypted, plaintext_len)) {
            printf("Error: Decryption failed\n");
            continue;
        }
        print_hex("Decrypted Text", decrypted, plaintext_len);

        printf("Result: %s\n", memcmp(plaintext, decrypted, plaintext_len) ? "FAIL!" : "PASS!");
    }
}

int test_rc4() {
    printf("\n===== RC4 Test Suite =====\n");
    test_keystream();
    test_symmetry();
    printf("\nTesting completed\n");
    return 0;
}