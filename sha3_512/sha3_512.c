// #include "sha3_512.h"
#include <stdint.h>
#include <string.h>


#define KECCAKF_ROUNDS 24
#define SHA3_512_DIGEST_SIZE 64

/**
 * sha3 属于 keccakf 架构，不需 init、update 和 final 等多轮次处理，其设计上是将数据直接与状态结合并一次性处理的。
 */

// Keccak 的常量轮次数据，定义了轮次常量
static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Keccak 每轮旋转量，定义了每个列在进行置换时的旋转位数
static const int keccakf_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44
};

// Keccak 的置换规则，定义了每轮列置换的顺序
static const int keccakf_piln[24] = {
    10,  7, 11, 17, 18, 3, 5, 16,
     8, 21, 24, 4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9, 6,  1
};


/**
 * Keccak 的核心置换函数，对状态进行轮次迭代更新
 */
static void keccakf(uint64_t st[25]) {
    int i, j, round;
    uint64_t t, bc[5];

    for (round = 0; round < KECCAKF_ROUNDS; round++) {
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> (64 - 1)));
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5];
        }

        st[0] ^= keccakf_rndc[round];
    }
}

/**
 * Keccak 执行函数，用于处理输入并计算哈希值
 */
static void keccak(const uint8_t *in, size_t inlen, uint8_t *md, size_t mdlen, int pad) {
    uint64_t st[25] = {0};
    uint8_t temp[144] = {0};
    size_t rate = 72; // SHA3-512: 1600 - 2*512 = 576 bits = 72 bytes
    size_t i;

    while (inlen >= rate) {
        for (i = 0; i < rate / 8; i++)
            st[i] ^= ((uint64_t *)in)[i];
        keccakf(st);
        in += rate;
        inlen -= rate;
    }

    memset(temp, 0, rate);
    memcpy(temp, in, inlen);
    temp[inlen] = pad;
    temp[rate - 1] |= 0x80;
    for (i = 0; i < rate / 8; i++)
        st[i] ^= ((uint64_t *)temp)[i];
    keccakf(st);

    memcpy(md, st, mdlen);
}

/**
 * SHA3-512 哈希函数，计算并返回消息的 SHA3-512 哈希值
 */
void sha3_512(const uint8_t *message, size_t message_len, uint8_t *digest, size_t digest_len) {
    keccak(message, message_len, digest, SHA3_512_DIGEST_SIZE, 0x06);
}
