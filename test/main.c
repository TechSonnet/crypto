//
// Created by chang on 2025/5/14.
//

#include <stdio.h>

extern void test_sha3_512();
extern void test_md5();
extern void test_sha_256();
extern void test_rc4();

int main() {
    printf("\n\n");
    printf("== Crypto Library Test ==\n");
    printf("\n\n");
    printf("== Crypto Library SHA3_512 Test ==\n");
    test_sha3_512();
    printf("== Crypto Library MD5 Test ==\n");
    printf("\n\n");
    test_md5();
    printf("== Crypto Library SHA_256 Test ==\n");
    test_sha_256();
    printf("\n\n");
    printf("== Crypto Library RC4 Test ==\n");
    test_rc4();
    printf("\n\n");
    return 0;
}

