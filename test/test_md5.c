/*
    测试向量
    {"",     "d41d8cd98f00b204e9800998ecf8427e"},
    {"abc",  "900150983cd24fb0d6963f7d28e17f72"},
    {"The quick brown fox jumps over the lazy dog",    "9e107d9d372bb6826bd81d3542a419d6"}
*/

#include "../crypto.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 测试向量定义
#define MD5_TEST_VECTOR_INPUT1 ""
const uint8_t MD5_TEST_VECTOR_OUTPUT1[16] = {
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
};

#define MD5_TEST_VECTOR_INPUT2 "abc"
const uint8_t MD5_TEST_VECTOR_OUTPUT2[16] = {
    0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
    0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
};

#define MD5_TEST_VECTOR_INPUT3 "The quick brown fox jumps over the lazy dog"
const uint8_t MD5_TEST_VECTOR_OUTPUT3[16] = {
    0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82,
    0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6
};

int test_md5() {
    uint8_t digest[16];  // MD5输出为16字节
    int all_passed = 1;

    // 测试向量1：空字符串
    MD5((const uint8_t *)MD5_TEST_VECTOR_INPUT1, 
        strlen(MD5_TEST_VECTOR_INPUT1), 
        digest, 
        sizeof(digest));

    printf("Test Vector 1:\n");
    printf("input: \"%s\"\n", MD5_TEST_VECTOR_INPUT1);
    printf("output (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]); // 直接打印二进制哈希值
    printf("\n");
    if (memcmp(digest, MD5_TEST_VECTOR_OUTPUT1, sizeof(digest)) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // 测试向量2："abc"
    MD5((const uint8_t *)MD5_TEST_VECTOR_INPUT2, 
        strlen(MD5_TEST_VECTOR_INPUT2), 
        digest, 
        sizeof(digest));

    printf("Test Vector 2:\n");
    printf("input: \"%s\"\n", MD5_TEST_VECTOR_INPUT2);
    printf("output (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("\n");
    if (memcmp(digest, MD5_TEST_VECTOR_OUTPUT2, sizeof(digest)) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // 测试向量3：长字符串
    MD5((const uint8_t *)MD5_TEST_VECTOR_INPUT3, 
        strlen(MD5_TEST_VECTOR_INPUT3), 
        digest, 
        sizeof(digest));

    printf("Test Vector 3:\n");
    printf("input: \"%s\"\n", MD5_TEST_VECTOR_INPUT3);
    printf("output (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("\n");
    if (memcmp(digest, MD5_TEST_VECTOR_OUTPUT3, sizeof(digest)) == 0) {
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