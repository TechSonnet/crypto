#include "rc6.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define P32 0xB7E15163
#define Q32 0x9E3779B9
#define LG_W 5


#define ROUNDS      20      // Количество раундов
#define KEY_LENGTH  256     // Длина ключа
#define W           32      // Длина машинного слова в битах



// Контекст RC6
typedef struct rc6_ctx
{
    uint8_t r;      // Число раундов, по умолчанию 20
    uint32_t *S;    // 32-битные раундовые ключи
} rc6_ctx_t;


rc6_ctx_t* ak_rc6_ctx_create_new()
{
    rc6_ctx_t *new_ctx = malloc(sizeof(rc6_ctx_t));
    new_ctx->S = (uint32_t*) calloc(2*ROUNDS+4, sizeof(uint32_t));
    new_ctx->r = ROUNDS;
    return new_ctx;
}

void ak_rc6_ctx_free(rc6_ctx_t *ctx)
{
    free(ctx->S);
    free(ctx);
}

uint32_t rol32(uint32_t a, uint8_t n)
{
    return (a << n) | (a >> (32 - n));
}

uint32_t ror32(uint32_t a, uint8_t n)
{
    return (a >> n) | (a << (32 - n));
}

void ak_rc6_ctx_key_schedule(rc6_ctx_t *ctx, void *key)
{
    ctx->S[0] = P32;
    uint8_t i = 0, j = 0;
    for(i = 1; i <= 2*ctx->r+3; ++i)
        ctx->S[i] = ctx->S[i-1] + Q32;

    i = 0;
    uint32_t a = 0, b = 0;
    for(uint8_t k=1; k<=3*(2*ctx->r+4); ++k)
    {
        a = ctx->S[i] = rol32((ctx->S[i] + a + b), 3);
        b = ((uint32_t*)key)[j] = rol32(((uint32_t*)key)[j] + a + b, a + b);
        i = (i+1) % (2*ctx->r+4);
        j = (j+1) % (KEY_LENGTH/W);
    }
}

void ak_rc6_ctx_encrypt(rc6_ctx_t *ctx, void* block)
{
    register uint32_t A = ((uint32_t *)block)[0];
    register uint32_t B = ((uint32_t *)block)[1];
    register uint32_t C = ((uint32_t *)block)[2];
    register uint32_t D = ((uint32_t *)block)[3];

    B += ctx->S[0];
    D += ctx->S[1];
    uint32_t t=0, u=0, temp_reg;
    for(uint8_t i = 1; i <= ctx->r; ++i)
    {
        t = rol32((B * (2 * B + 1)), LG_W);
        u = rol32((D * (2 * D + 1)), LG_W);
        A = rol32(A ^ t, u) + ctx->S[2*i];
        C = rol32(C ^ u, t) + ctx->S[2*i+1];
        temp_reg = A;
        A = B;
        B = C;
        C = D;
        D = temp_reg;
    }
    A += ctx->S[2*ctx->r + 2];
    C += ctx->S[2*ctx->r + 3];
    ((uint32_t *)block)[0]=A;
    ((uint32_t *)block)[1]=B;
    ((uint32_t *)block)[2]=C;
    ((uint32_t *)block)[3]=D;
}

void ak_rc6_ctx_decrypt(rc6_ctx_t *ctx, void *block)
{
    register uint32_t A = ((uint32_t *)block)[0];
    register uint32_t B = ((uint32_t *)block)[1];
    register uint32_t C = ((uint32_t *)block)[2];
    register uint32_t D = ((uint32_t *)block)[3];
    C = C - ctx->S[2*ctx->r + 3];
    A = A - ctx->S[2*ctx->r + 2];
    uint32_t t=0, u=0, temp_reg;
    for(uint8_t i = ctx->r; i > 0; --i)
    {
        temp_reg = D;
        D = C;
        C = B;
        B = A;
        A = temp_reg;
        t = rol32((B*(2*B+1)), LG_W);
        u = rol32((D*(2*D+1)), LG_W);
        C = ror32((C-ctx->S[2*i+1]), t) ^ u;
        A = ror32((A-ctx->S[2*i]), u) ^ t;
    }
    D = D - ctx->S[1];
    B = B - ctx->S[0];
    ((uint32_t *)block)[0]=A;
    ((uint32_t *)block)[1]=B;
    ((uint32_t *)block)[2]=C;
    ((uint32_t *)block)[3]=D;
}
// 添加在 rc6.c 文件末尾

void rc6_encrypt_block(uint8_t *key, uint8_t *plaintext, uint8_t *ciphertext)
{
    rc6_ctx_t *ctx = ak_rc6_ctx_create_new();
    uint8_t key_copy[32];
    memcpy(key_copy, key, 32); // 避免 key_schedule 修改原始 key
    ak_rc6_ctx_key_schedule(ctx, key_copy);

    uint8_t block[16];
    memcpy(block, plaintext, 16);
    ak_rc6_ctx_encrypt(ctx, block);
    memcpy(ciphertext, block, 16);

    ak_rc6_ctx_free(ctx);
}

void rc6_decrypt_block(uint8_t *key, uint8_t *ciphertext, uint8_t *plaintext)
{
    rc6_ctx_t *ctx = ak_rc6_ctx_create_new();
    uint8_t key_copy[32];
    memcpy(key_copy, key, 32); // 避免 key_schedule 修改原始 key
    ak_rc6_ctx_key_schedule(ctx, key_copy);

    uint8_t block[16];
    memcpy(block, ciphertext, 16);
    ak_rc6_ctx_decrypt(ctx, block);
    memcpy(plaintext, block, 16);

    ak_rc6_ctx_free(ctx);
}



