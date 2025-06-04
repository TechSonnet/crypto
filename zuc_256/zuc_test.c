#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "zuc.h"

/* ================= 测试向量定义 ================= */

// 数据来源 https://github.com/guanzhi/GmSSL/blob/master/tests/zuctest.c

// 测试用例1：全零密钥和IV
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

static const uint32_t TEST1_CIPHERTEXT[20] = {
    0x58d03ad6,0x2e032ce2,0xdafc683a,0x39bdcb03,0x52a2bc67,
    0xf1b7de74,0x163ce3a1,0x01ef5558,0x9639d75b,0x95fa681b,
    0x7f090df7,0x56391ccc,0x903b7612,0x744d544c,0x17bc3fad,
    0x8b163b08,0x21787c0b,0x97775bb8,0x4943c6bb,0xe8ad8afd
};

// 测试用例2：全FF密钥和IV
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

static const uint32_t TEST2_CIPHERTEXT[20] = {
    0x3356cbae,0xd1a1c18b,0x6baa4ffe,0x343f777c,0x9e15128f,
    0x251ab65b,0x949f7b26,0xef7157f2,0x96dd2fa9,0xdf95e3ee,
    0x7a5be02e,0xc32ba585,0x505af316,0xc2f9ded2,0x7cdbd935,
    0xe441ce11,0x15fd0a80,0xbb7aef67,0x68989416,0xb8fac8c2
};

int test_zuc_256() {
    uint8_t plaintext[80] = {0}; // 20 uint32_t blocks of all-zero plaintext
    uint8_t ciphertext[80];
    uint8_t decrypted[80];
    int test_passed = 1;

    // ========== Test Case 1 ==========
    {
        printf("\n========== Test Case 1 ==========\n");

        // Print key (32 bytes)
        printf("Key (32 bytes): ");
        for (int i = 0; i < sizeof(TEST1_KEY); i++) {
            printf("%02X ", TEST1_KEY[i]);
        }
        printf("\n");

        // Print initialization vector (23 bytes)
        printf("IV (23 bytes): ");
        for (int i = 0; i < sizeof(TEST1_IV); i++) {
            printf("%02X ", TEST1_IV[i]);
        }
        printf("\n");

        // Perform encryption
        zuc256_encrypt(
            plaintext, sizeof(plaintext),
            TEST1_KEY, sizeof(TEST1_KEY),
            TEST1_IV, sizeof(TEST1_IV),
            ciphertext, sizeof(ciphertext)
        );

        // Print ciphertext
        printf("Encryption result: ");
        for (int i = 0; i < sizeof(ciphertext); i++) {
            printf("%02X ", ciphertext[i]);
        }
        printf("\n");

        // Verify encryption result
        if (memcmp(ciphertext, TEST1_CIPHERTEXT, sizeof(ciphertext)) == 0) {
            printf("Encryption verification passed\n");
        } else {
            printf("Encryption verification failed\n");
            test_passed = 0;
            for (int j = 0; j < 20; j++) {
                printf("Block%2d: Expected=%08X Actual=%08X\n",
                    j, TEST1_CIPHERTEXT[j], ((uint32_t*)ciphertext)[j]);
            }
        }

        // Perform decryption
        zuc256_decrypt(
            ciphertext, sizeof(ciphertext),
            TEST1_KEY, sizeof(TEST1_KEY),
            TEST1_IV, sizeof(TEST1_IV),
            decrypted, sizeof(decrypted)
        );

        // Verify decryption result
        if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
            printf("Decryption verification passed\n");
        } else {
            printf("Decryption verification failed\n");
            test_passed = 0;
            for (int j = 0; j < sizeof(plaintext); j++) {
                if (decrypted[j] != plaintext[j]) {
                    printf("First difference at position %d: Expected=%02X Actual=%02X\n",
                        j, plaintext[j], decrypted[j]);
                    break;
                }
            }
        }
    }

    // ========== Test Case 2 ==========
    {
        printf("\n========== Test Case 2 ==========\n");

        // Print key (32 bytes)
        printf("Key (32 bytes): ");
        for (int i = 0; i < sizeof(TEST2_KEY); i++) {
            printf("%02X ", TEST2_KEY[i]);
        }
        printf("\n");

        // Print initialization vector (23 bytes)
        printf("IV (23 bytes): ");
        for (int i = 0; i < sizeof(TEST2_IV); i++) {
            printf("%02X ", TEST2_IV[i]);
        }
        printf("\n");

        // Perform encryption
        zuc256_encrypt(
            plaintext, sizeof(plaintext),
            TEST2_KEY, sizeof(TEST2_KEY),
            TEST2_IV, sizeof(TEST2_IV),
            ciphertext, sizeof(ciphertext)
        );

        // Print ciphertext
        printf("Encryption result: ");
        for (int i = 0; i < sizeof(ciphertext); i++) {
            printf("%02X ", ciphertext[i]);
        }
        printf("\n");

        // Verify encryption result
        if (memcmp(ciphertext, TEST2_CIPHERTEXT, sizeof(ciphertext)) == 0) {
            printf("Encryption verification passed\n");
        } else {
            printf("Encryption verification failed\n");
            test_passed = 0;
            for (int j = 0; j < 20; j++) {
                printf("Block%2d: Expected=%08X Actual=%08X\n",
                    j, TEST2_CIPHERTEXT[j], ((uint32_t*)ciphertext)[j]);
            }
        }

        // Perform decryption
        zuc256_decrypt(
            ciphertext, sizeof(ciphertext),
            TEST2_KEY, sizeof(TEST2_KEY),
            TEST2_IV, sizeof(TEST2_IV),
            decrypted, sizeof(decrypted)
        );

        // Verify decryption result
        if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
            printf("Decryption verification passed\n");
        } else {
            printf("Decryption verification failed\n");
            test_passed = 0;
            for (int j = 0; j < sizeof(plaintext); j++) {
                if (decrypted[j] != plaintext[j]) {
                    printf("First difference at position %d: Expected=%02X Actual=%02X\n",
                        j, plaintext[j], decrypted[j]);
                    break;
                }
            }
        }
    }

    // Final test result
    printf("\n========== Final Test Result ==========\n");
    if (test_passed) {
        printf("PASS!\n");
        return 0;
    } else {
        printf("FAIL!\n");
        return -1;
    }
}