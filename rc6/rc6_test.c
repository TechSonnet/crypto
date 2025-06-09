#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "rc6.h"
#include "../utils/test_utils.h"  // 如果你有这个头文件，用于 print_hex

int test_rc6() {
    // 官方测试向量（Set 1, vector#0）
    uint8_t key[16] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t plaintext[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t expected_cipher[16] = {
        0x1A, 0xD5, 0x78, 0xA0, 0x2A, 0x08, 0x16, 0x28,
        0x50, 0xA1, 0x5A, 0x15, 0x52, 0xA1, 0x7A, 0xD4
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    rc6_ctx_t ctx;
    if (rc6_init(&ctx, key, 128) != 0) {
        printf("RC6 initialization failed!\n");
        return 1;
    }

    printf("=== RC6 Official Test Vector ===\n");
    print_hex("Key       ", key, 16);
    print_hex("Plaintext ", plaintext, 16);

    // 加密
    memcpy(ciphertext, plaintext, 16);
    rc6_enc(&ctx, ciphertext);
    print_hex("Ciphertext", ciphertext, 16);

    // 检查加密结果
    if (memcmp(ciphertext, expected_cipher, 16) == 0) {
        printf("Encryption PASSED: Matches expected ciphertext\n");
    } else {
        printf("Encryption FAILED: Mismatch with expected ciphertext\n");
    }

    // 解密
    memcpy(decrypted, ciphertext, 16);
    rc6_dec(&ctx, decrypted);
    print_hex("Decrypted ", decrypted, 16);

    if (memcmp(plaintext, decrypted, 16) == 0) {
        printf("Decryption PASSED: Recovered original plaintext\n");
    } else {
        printf("Decryption FAILED: Decrypted result incorrect\n");
    }

    rc6_free(&ctx);
    return 0;
}
