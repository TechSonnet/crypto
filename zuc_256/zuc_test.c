#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "zuc.h"
#include "../utils/test_utils.h"

#define TEST_BLOCK_COUNT 20  // 20 uint32_t blocks = 80 bytes

/* ================ Test Vectors ================ */
typedef struct {
    const char* name;
    const uint8_t* key;
    size_t key_len;
    const uint8_t* iv;
    size_t iv_len;
    const uint32_t* keystream;
} TestCase;

// Test Case 1: All-zero key and IV
static const uint8_t TEST1_KEY[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint8_t TEST1_IV[23] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint32_t TEST1_KEYSTREAM[TEST_BLOCK_COUNT] = {
    0x58d03ad6,0x2e032ce2,0xdafc683a,0x39bdcb03,0x52a2bc67,
    0xf1b7de74,0x163ce3a1,0x01ef5558,0x9639d75b,0x95fa681b,
    0x7f090df7,0x56391ccc,0x903b7612,0x744d544c,0x17bc3fad,
    0x8b163b08,0x21787c0b,0x97775bb8,0x4943c6bb,0xe8ad8afd
};

// Test Case 2: All-FF key and IV
static const uint8_t TEST2_KEY[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

static const uint8_t TEST2_IV[23] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

static const uint32_t TEST2_KEYSTREAM[TEST_BLOCK_COUNT] = {
    0x3356cbae,0xd1a1c18b,0x6baa4ffe,0x343f777c,0x9e15128f,
    0x251ab65b,0x949f7b26,0xef7157f2,0x96dd2fa9,0xdf95e3ee,
    0x7a5be02e,0xc32ba585,0x505af316,0xc2f9ded2,0x7cdbd935,
    0xe441ce11,0x15fd0a80,0xbb7aef67,0x68989416,0xb8fac8c2
};

static TestCase test_cases[] = {
    {"All-zero key and IV",
     TEST1_KEY, sizeof(TEST1_KEY),
     TEST1_IV, sizeof(TEST1_IV),
     TEST1_KEYSTREAM},

    {"All-FF key and IV",
     TEST2_KEY, sizeof(TEST2_KEY),
     TEST2_IV, sizeof(TEST2_IV),
     TEST2_KEYSTREAM}
};

int test_zuc256_keystream() {
    print_test_header("ZUC-256 Keystream Verification");

    uint8_t plaintext[TEST_BLOCK_COUNT * 4] = {0};
    uint8_t ciphertext[TEST_BLOCK_COUNT * 4];
    int all_passed = 1;

    for (size_t i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        TestCase tc = test_cases[i];
        printf("\nTest Case %zu: %s\n", i+1, tc.name);

        print_hex_compact("Key", tc.key, tc.key_len);
        print_hex_compact("IV", tc.iv, tc.iv_len);
        print_keystream("ExpectedKeystream", tc.keystream, TEST_BLOCK_COUNT);

        if (!zuc256_encrypt(plaintext, sizeof(plaintext),
                          tc.key, tc.key_len,
                          tc.iv, tc.iv_len,
                          ciphertext, sizeof(ciphertext))) {
            printf("Error:Encryption failed\n");
            all_passed = 0;
            continue;
        }

        print_keystream("ActualKeystream", (const uint32_t*)ciphertext, TEST_BLOCK_COUNT);

        if (memcmp(ciphertext, tc.keystream, sizeof(ciphertext)) == 0) {
            printf("Result:PASS\n");
        } else {
            printf("Result:FAIL\n");
            all_passed = 0;
        }
    }

    return all_passed;
}

int test_zuc256_symmetry() {
    print_test_header("ZUC-256 Encryption/Decryption Test");

    const uint8_t plaintext[] = "ZUC-256 test data";
    const size_t plaintext_len = sizeof(plaintext) - 1;
    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    int all_passed = 1;

    for (size_t i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        TestCase tc = test_cases[i];
        printf("\nTest Case %zu: %s\n", i+1, tc.name);

        print_hex_compact("Key", tc.key, tc.key_len);
        print_hex_compact("IV", tc.iv, tc.iv_len);
        print_hex_compact("Plaintext", plaintext, plaintext_len);

        if (!zuc256_encrypt(plaintext, plaintext_len,
                          tc.key, tc.key_len,
                          tc.iv, tc.iv_len,
                          ciphertext, sizeof(ciphertext))) {
            printf("Error:Encryption failed\n");
            all_passed = 0;
            continue;
        }

        print_hex_compact("Ciphertext", ciphertext, plaintext_len);

        if (!zuc256_decrypt(ciphertext, plaintext_len,
                          tc.key, tc.key_len,
                          tc.iv, tc.iv_len,
                          decrypted, sizeof(decrypted))) {
            printf("Error:Decryption failed\n");
            all_passed = 0;
            continue;
        }

        print_hex_compact("DecryptedText", decrypted, plaintext_len);

        if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
            printf("Result:PASS\n");
        } else {
            printf("Result:FAIL\n");
            all_passed = 0;
        }
    }

    return all_passed;
}

int test_zuc_256() {
    printf("\n=====Starting ZUC-256 Tests=====\n");

    test_zuc256_keystream();
    test_zuc256_symmetry();

    printf("\n=====ZUC-256 Tests Completed=====\n");
    return 0;
}