#include "../crypto.h"
#include <stdio.h>
#include <string.h>

#define SHA3_512_DIGEST_SIZE 64

/*
 * SHA3-512 测试向量
 * 字符串 ""：
 *     a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
 * 字符串 "abc"：
 *     b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
 * 字符串 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"：
 *     04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e
 */

// SHA3-512 test vectors 1
#define SHA3_512_TEST_VECTOR_INPUT1 "abc"
const unsigned char SHA3_512_TEST_VECTOR_OUTPUT1[SHA3_512_DIGEST_SIZE] = {
    0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
    0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
    0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
    0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
};

// SHA3-512 Test vector 2
#define SHA3_512_TEST_VECTOR_INPUT2 ""
const unsigned char SHA3_512_TEST_VECTOR_OUTPUT2[SHA3_512_DIGEST_SIZE] = {
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
    0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
    0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
};

// SHA3-512 Test vector 3
#define SHA3_512_TEST_VECTOR_INPUT3 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
const unsigned char SHA3_512_TEST_VECTOR_OUTPUT3[SHA3_512_DIGEST_SIZE] = {
    0x04, 0xa3, 0x71, 0xe8, 0x4e, 0xcf, 0xb5, 0xb8, 0xb7, 0x7c, 0xb4, 0x86, 0x10, 0xfc, 0xa8, 0x18,
    0x2d, 0xd4, 0x57, 0xce, 0x6f, 0x32, 0x6a, 0x0f, 0xd3, 0xd7, 0xec, 0x2f, 0x1e, 0x91, 0x63, 0x6d,
    0xee, 0x69, 0x1f, 0xbe, 0x0c, 0x98, 0x53, 0x02, 0xba, 0x1b, 0x0d, 0x8d, 0xc7, 0x8c, 0x08, 0x63,
    0x46, 0xb5, 0x33, 0xb4, 0x9c, 0x03, 0x0d, 0x99, 0xa2, 0x7d, 0xaf, 0x11, 0x39, 0xd6, 0xe7, 0x5e
};

int test_sha3_512() {
    int all_passed = 1;

    unsigned char digest[SHA3_512_DIGEST_SIZE];

    // Test Vector 1
    sha3_512((const unsigned char *)SHA3_512_TEST_VECTOR_INPUT1, strlen(SHA3_512_TEST_VECTOR_INPUT1), digest, SHA3_512_DIGEST_SIZE);
    printf("Test Vector 1:\n");
    printf("input: \"%s\"\n", SHA3_512_TEST_VECTOR_INPUT1);
    printf("output: ");
    for (int i = 0; i < SHA3_512_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, SHA3_512_TEST_VECTOR_OUTPUT1, SHA3_512_DIGEST_SIZE) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // Test Vector 2
    sha3_512((const unsigned char *)SHA3_512_TEST_VECTOR_INPUT2, strlen(SHA3_512_TEST_VECTOR_INPUT2), digest, SHA3_512_DIGEST_SIZE);
    printf("Test Vector 2:\n");
    printf("input: \"%s\"\n", SHA3_512_TEST_VECTOR_INPUT2);
    printf("output: ");
    for (int i = 0; i < SHA3_512_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, SHA3_512_TEST_VECTOR_OUTPUT2, SHA3_512_DIGEST_SIZE) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // Test Vector 3
    sha3_512((const unsigned char *)SHA3_512_TEST_VECTOR_INPUT3, strlen(SHA3_512_TEST_VECTOR_INPUT3), digest, SHA3_512_DIGEST_SIZE);
    printf("Test Vector 3:\n");
    printf("input: \"%s\"\n", SHA3_512_TEST_VECTOR_INPUT3);
    printf("output: ");
    for (int i = 0; i < SHA3_512_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, SHA3_512_TEST_VECTOR_OUTPUT3, SHA3_512_DIGEST_SIZE) == 0) {
        printf("PASS!\n\n");
    } else {
        printf("FAILED\n\n");
        all_passed = 0;
    }

    // Final result
    if (all_passed) {
        printf("All test vectors passed!\n");
    } else {
        printf("Some test vectors failed.\n");
    }

    return 0;
}
