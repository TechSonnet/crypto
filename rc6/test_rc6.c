#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "rc6.h"

typedef struct {
    const char* name;
    const uint8_t key[16];  // 固定16字节密钥
    const uint8_t plaintext[16];
    const uint8_t ciphertext[16];
} TestCase;

// 修正后的测试向量初始化
static const TestCase test_cases[] = {
    { // 测试用例1 - 全零密钥
        "128-bit zero key",
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x8F, 0xC3, 0xA5, 0x3D, 0x33, 0xE4, 0x33, 0x68,
         0x3E, 0x8C, 0x33, 0x5B, 0xE4, 0x85, 0x5E, 0x1B}
    },
    { // 测试用例2 - NIST标准测试
        "NIST Sample 1",
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
         0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78},
        {0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79,
         0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1},
        {0x52, 0x4E, 0x19, 0x2F, 0x47, 0x15, 0xC6, 0x23,
         0x1F, 0x51, 0x0A, 0x52, 0xEF, 0x0F, 0x84, 0x05}
    }
};

void print_block(const char* label, const uint8_t* block) {
    printf("%-12s", label);
    for (int i = 0; i < 16; ++i) {
        printf("%02X ", block[i]);
    }
    printf("\n");
}

int test_rc6() {
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    int all_passed = 1;

    for (size_t i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        const TestCase* tc = &test_cases[i];
        printf("\nTest %zu: %s\n", i+1, tc->name);

        print_block("Key:", tc->key);
        print_block("Plaintext:", tc->plaintext);

        // 加密测试
        rc6_encrypt_block(tc->key, tc->plaintext, ciphertext);
        print_block("Ciphertext:", ciphertext);

        // 验证加密结果
        if (memcmp(ciphertext, tc->ciphertext, 16) != 0) {
            print_block("Expected:", tc->ciphertext);
            printf("❌ Encryption failed!\n");
            all_passed = 0;
        }

        // 解密测试
        rc6_decrypt_block(tc->key, ciphertext, decrypted);
        print_block("Decrypted:", decrypted);

        // 验证解密结果
        if (memcmp(tc->plaintext, decrypted, 16) == 0) {
            printf("✅ Test passed\n");
        } else {
            printf("❌ Decryption failed!\n");
            all_passed = 0;
        }
    }

    printf("\n=== Overall result: %s ===\n", all_passed ? "PASS" : "FAIL");
    return all_passed ? 0 : -1;
}