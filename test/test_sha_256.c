#include "../crypto.h"
#include <stdio.h>
#include <string.h>

#define HEX_LENGTH (2 * SHA_256_DIGEST_LENGTH + 1)  // 十六进制输出字符串长度 = 2 * 哈希长度 + 1（含 null 结尾）
#define SHA_256_DIGEST_LENGTH 32  // SHA-256 输出摘要长度（字节）

/*
 * SHA2-256 测试向量
 */
// 测试向量1
#define SHA_256_TEST_VECTOR_INPUT1 ""
const unsigned char SHA_256_TEST_VECTOR_OUTPUT1[SHA_256_DIGEST_LENGTH] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
// 测试向量2
#define SHA_256_TEST_VECTOR_INPUT2 "abc"
const unsigned char SHA_256_TEST_VECTOR_OUTPUT2[SHA_256_DIGEST_LENGTH] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
// 测试向量3
#define SHA_256_TEST_VECTOR_INPUT3 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" \
                    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
const unsigned char SHA_256_TEST_VECTOR_OUTPUT3[SHA_256_DIGEST_LENGTH] = {
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80,
        0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
        0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51,
        0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1
};

int test_sha_256() {
    int all_passed = 1;
    unsigned char digest[SHA_256_DIGEST_LENGTH];

    // 向量1测试
    memset(digest, 0, SHA_256_DIGEST_LENGTH);
    SHA_256((const unsigned char *)SHA_256_TEST_VECTOR_INPUT1,
            strlen(SHA_256_TEST_VECTOR_INPUT1),
            digest,
            SHA_256_DIGEST_LENGTH);

    printf("Test Vector 1:\n");
    printf("input: \"%s\"\n", SHA_256_TEST_VECTOR_INPUT1);
    printf("output: ");
    for (int i = 0; i < SHA_256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, SHA_256_TEST_VECTOR_OUTPUT1, SHA_256_DIGEST_LENGTH) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // 向量2测试
    memset(digest, 0, SHA_256_DIGEST_LENGTH);
    SHA_256((const unsigned char *)SHA_256_TEST_VECTOR_INPUT2,
            strlen(SHA_256_TEST_VECTOR_INPUT2),
            digest,
            SHA_256_DIGEST_LENGTH);

    printf("Test Vector 2:\n");
    printf("input: \"%s\"\n", SHA_256_TEST_VECTOR_INPUT2);
    printf("output: ");
    for (int i = 0; i < SHA_256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, SHA_256_TEST_VECTOR_OUTPUT2, SHA_256_DIGEST_LENGTH) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // 向量3测试
    memset(digest, 0, SHA_256_DIGEST_LENGTH);
    SHA_256((const unsigned char *)SHA_256_TEST_VECTOR_INPUT3,
            strlen(SHA_256_TEST_VECTOR_INPUT3),
            digest,
            SHA_256_DIGEST_LENGTH);

    printf("Test Vector 3:\n");
    printf("input: \"%s\"\n", SHA_256_TEST_VECTOR_INPUT3);
    printf("output: ");
    for (int i = 0; i < SHA_256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, SHA_256_TEST_VECTOR_OUTPUT3, SHA_256_DIGEST_LENGTH) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // 测试结果汇总
    if (all_passed) {
        printf("All test vectors passed!\n");
    } else {
        printf("Some test vectors failed.\n");
    }

    return 0;
}