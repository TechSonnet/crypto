#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "rc4.h"

#define TEST_SIZE 16

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

void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%s: ", label);  // 冒号后加一个空格
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void print_test_header(const char* title) {
    printf("\n=== %s ===\n", title);
}

void test_keystream() {
    print_test_header("RC4 密钥流测试");
    
    uint8_t zero_plaintext[TEST_SIZE] = {0};
    uint8_t output[TEST_SIZE];
    
    for (int i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        TestCase tc = test_cases[i];
        printf("\n测试用例 %d: %s\n", i+1, tc.name);
        
        print_hex("密钥", tc.key, tc.key_len);
        print_hex("期望密钥流", tc.keystream, TEST_SIZE);
        
        if (!rc4_encrypt(zero_plaintext, TEST_SIZE, tc.key, tc.key_len, output, TEST_SIZE)) {
            printf("错误: 加密失败\n");
            continue;
        }
        print_hex("实际密钥流", output, TEST_SIZE);
        
        printf("结果: %s\n", memcmp(output, tc.keystream, TEST_SIZE) ? "FAIL!" : "PASS!");
    }
}

void test_symmetry() {
    print_test_header("RC4 加解密测试");
    
    const uint8_t plaintext[] = "RC4测试数据";
    const int plaintext_len = sizeof(plaintext)-1;
    uint8_t ciphertext[plaintext_len];
    uint8_t decrypted[plaintext_len];
    
    for (int i = 0; i < sizeof(test_cases)/sizeof(TestCase); i++) {
        TestCase tc = test_cases[i];
        printf("\n测试用例 %d: %s\n", i+1, tc.name);
        
        print_hex("密钥", tc.key, tc.key_len);
        print_hex("明文", plaintext, plaintext_len);
        
        if (!rc4_encrypt(plaintext, plaintext_len, tc.key, tc.key_len, ciphertext, plaintext_len)) {
            printf("错误: 加密失败\n");
            continue;
        }
        print_hex("密文", ciphertext, plaintext_len);
        
        if (!rc4_decrypt(ciphertext, plaintext_len, tc.key, tc.key_len, decrypted, plaintext_len)) {
            printf("错误: 解密失败\n");
            continue;
        }
        print_hex("解密结果", decrypted, plaintext_len);
        
        printf("结果: %s\n", memcmp(plaintext, decrypted, plaintext_len) ? "FAIL!" : "PASS!");
    }
}

int test_rc4() {
    printf("\n===== RC4 测试 =====\n");
    test_keystream();
    test_symmetry();
    printf("\n测试结束\n");
    return 0;
}