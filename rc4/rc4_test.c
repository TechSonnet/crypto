#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "rc4.h"

/* ================= 测试向量定义 ================= */

// 来源 https://datatracker.ietf.org/doc/html/rfc6229

// 测试用例1：40位密钥 (DEC 0)
#define TEST1_KEY        0x01, 0x02, 0x03, 0x04, 0x05
#define TEST1_KEY_LEN    5
#define TEST1_PLAINTEXT  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define TEST1_PLAINTEXT_LEN 16
#define TEST1_CIPHERTEXT 0xB2, 0x39, 0x63, 0x05, 0xF0, 0x3D, 0xC0, 0x27, \
0xCC, 0xC3, 0x52, 0x4A, 0x0A, 0x11, 0x18, 0xA8

// 测试用例2：56位密钥 (DEC 0)
#define TEST2_KEY        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
#define TEST2_KEY_LEN    7
#define TEST2_PLAINTEXT  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define TEST2_PLAINTEXT_LEN 16
#define TEST2_CIPHERTEXT 0x29, 0x3F, 0x02, 0xD4, 0x7F, 0x37, 0xC9, 0xB6, \
0x33, 0xF2, 0xAF, 0x52, 0x85, 0xFE, 0xB4, 0x6B

// 测试用例3：64位密钥 (DEC 0)
#define TEST3_KEY        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
#define TEST3_KEY_LEN    8
#define TEST3_PLAINTEXT  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define TEST3_PLAINTEXT_LEN 16
#define TEST3_CIPHERTEXT 0x97, 0xAB, 0x8A, 0x1B, 0xF0, 0xAF, 0xB9, 0x61, \
0x32, 0xF2, 0xF6, 0x72, 0x58, 0xDA, 0x15, 0xA8

/* ================= 测试函数 ================= */
void test_rc4_vector(const char* name, 
                    const uint8_t* key, uint32_t key_len,
                    const uint8_t* plaintext, const uint8_t* expected, uint32_t len) {
    rc4_ctx ctx;
    uint8_t ciphertext[256];
    int passed = 1;

    printf("\n=== %s ===\n", name);
    
    // 初始化并跳过指定偏移量
    rc4_ks(&ctx, key, key_len);

    // 执行加密
    rc4_encrypt(&ctx, plaintext, ciphertext, len);

    // 打印结果
    printf("Plaintext:  ");
    for (uint32_t i = 0; i < len; i++) printf("%02X ", plaintext[i]);
    printf("\nExpected:   ");
    for (uint32_t i = 0; i < len; i++) printf("%02X ", expected[i]);
    printf("\nCiphertext: ");
    for (uint32_t i = 0; i < len; i++) printf("%02X ", ciphertext[i]);
    printf("\n");

    // 验证结果
    if (memcmp(expected, ciphertext, len) != 0) {
        passed = 0;
        printf("--> FAIL\n");
    } else {
        printf("--> PASS\n");
    }
}

void test_rc4() {
    // 测试用例1
    {
        const uint8_t key[] = {TEST1_KEY};
        const uint8_t plaintext[] = {TEST1_PLAINTEXT};
        const uint8_t expected[] = {TEST1_CIPHERTEXT};
        test_rc4_vector("Test 1 (40-bit key)", key, TEST1_KEY_LEN, plaintext, expected, TEST1_PLAINTEXT_LEN);
    }

    // 测试用例2
    {
        const uint8_t key[] = {TEST2_KEY};
        const uint8_t plaintext[] = {TEST2_PLAINTEXT};
        const uint8_t expected[] = {TEST2_CIPHERTEXT};
        test_rc4_vector("Test 2 (56-bit key)", key, TEST2_KEY_LEN, plaintext, expected, TEST2_PLAINTEXT_LEN);
    }

    // 测试用例3
    {
        const uint8_t key[] = {TEST3_KEY};
        const uint8_t plaintext[] = {TEST3_PLAINTEXT};
        const uint8_t expected[] = {TEST3_CIPHERTEXT};
        test_rc4_vector("Test 3 (64-bit key)", key, TEST3_KEY_LEN, plaintext, expected, TEST3_PLAINTEXT_LEN);
    }
}