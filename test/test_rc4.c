//
// Created by chang on 2025/5/15.
//
#include <stdio.h>
#include <string.h>
#include "../crypto.h"

void test_rc4() {
    // 明文数据
    const char *plaintext = "Hello, RC4 Test!";
    uint32 len = strlen(plaintext);

    // RC4 密钥
    const uint8 key[] = "testkey";
    uint32 key_len = strlen((const char *)key);

    // 加解密上下文
    rc4_ctx ctx_enc, ctx_dec;

    // 输出缓冲区
    uint8 ciphertext[256];
    uint8 decrypted[256];

    // 初始化 RC4 密钥调度
    rc4_ks(&ctx_enc, key, key_len);
    rc4_ks(&ctx_dec, key, key_len);

    // 执行加密
    rc4_encrypt(&ctx_enc, (const uint8 *)plaintext, ciphertext, len);

    printf("Ciphertext (hex): ");
    for (uint32 i = 0; i < len; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // 执行解密
    rc4_decrypt(&ctx_dec, ciphertext, decrypted, len);
    decrypted[len] = '\0'; // 添加终止符以打印字符串

    printf("Decrypted text: %s\n", decrypted);

}

