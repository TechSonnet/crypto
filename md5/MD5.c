#include "MD5.h"
#include <string.h>
#include <stdint.h>

/*
 * MD5算法定义的常量
 */
#define A   (0x67452301)
#define B   (0xefcdab89)
#define C   (0x98badcfe)
#define D   (0x10325476)

/*
 * MD5算法定义的位操作函数
 */
#define F(X, Y, Z)  ((X & Y) | (~X & Z))
#define G(X, Y, Z)  ((X & Z) | (Y & ~Z))
#define H(X, Y, Z)  (X ^ Y ^ Z)
#define I(X, Y, Z)  (Y ^ (X | ~Z))

typedef struct _MD5_CONTEXT
{
    uint64_t size;        // 输入的字节大小
    uint32_t buffer[4];   // 当前哈希计算的中间状态
    uint8_t input[64];    // 待处理的下一个输入块
    uint8_t digest[16];   // 最终生成的MD5摘要
}MD5_CONTEXT;

static const uint32_t S[] =
{
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static const uint32_t K[] =
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/*
 * 填充字节，使输入的总比特数满足 448 ≡ 0 mod 512
 */
static const uint8_t PADDING[] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint32_t RotateLeft(uint32_t x, uint32_t n);
static void MD5_Init(MD5_CONTEXT *ctx);
static void MD5_Update(MD5_CONTEXT *ctx, uint8_t *input, size_t input_len);
static void MD5_Final(MD5_CONTEXT *ctx);
static void MD5_Step(uint32_t *buffer, uint32_t *input);

/*
 * 将32位字左移n位
 */
static uint32_t RotateLeft(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

/*
 * 初始化上下文
 */
static void MD5_Init(MD5_CONTEXT *ctx)
{
    ctx->size = (uint64_t)0;

    ctx->buffer[0] = (uint32_t)A;
    ctx->buffer[1] = (uint32_t)B;
    ctx->buffer[2] = (uint32_t)C;
    ctx->buffer[3] = (uint32_t)D;
}

/*
 * 向上下文中添加输入数据
 * 
 * 当输入填满512位块时，执行MD5计算（MD5_Step）
 * 并将结果更新到缓冲区，同时更新总输入大小
 */
static void MD5_Update(MD5_CONTEXT *ctx, uint8_t *input_buffer, size_t input_len)
{
    uint32_t input[16] = {0};
    uint32_t offset = ctx->size % 64;
    ctx->size += (uint64_t)input_len;
    uint32_t i = 0;
    uint32_t j = 0;

    // 将输入数据按字节复制到上下文的input缓冲区
    for (i = 0; i < input_len; i++)
    {
        ctx->input[offset++] = (uint8_t)(*(input_buffer + i));

        // 当缓冲区填满64字节时，转换为小端序的32位字数组
        // 执行MD5计算并重置偏移量
        if (offset % 64 == 0)
        {
            for (j = 0; j < 16; j++)
            {
                input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
                           (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
                           (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
                           (uint32_t)(ctx->input[(j * 4)]);
            }
            MD5_Step(ctx->buffer, input);
            offset = 0;
        }
    }
}

/*
 * 对输入进行填充，使其长度满足448比特的条件
 * 并在末尾附加原始长度的比特表示，最终生成摘要
 */
static void MD5_Final(MD5_CONTEXT *ctx)
{
    uint32_t input[16] = {0};
    uint32_t offset = ctx->size % 64;
    uint32_t padding_length = (offset < 56) ? (56 - offset) : ((56 + 64) - offset);
    uint32_t i = 0;
    uint32_t j = 0;

    // 填充字节并调整总长度
    MD5_Update(ctx, PADDING, padding_length);
    ctx->size -= (uint64_t)padding_length;

    // 处理最后一块数据（包含长度信息）
    for (j = 0; j < 14; j++)
    {
        input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
                   (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
                   (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
                   (uint32_t)(ctx->input[(j * 4)]);
    }
    input[14] = (uint32_t)(ctx->size * 8);      // 低32位长度（比特）
    input[15] = (uint32_t)((ctx->size * 8) >> 32); // 高32位长度（比特）

    MD5_Step(ctx->buffer, input);

    // 将结果转换为小端序的字节数组
    for (i = 0; i < 4; i++)
    {
        ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
        ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
        ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
        ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
    }
}

/*
 * MD5核心计算步骤，处理512位输入块
 */
static void MD5_Step(uint32_t *buffer, uint32_t *input)
{
    uint32_t AA = buffer[0];
    uint32_t BB = buffer[1];
    uint32_t CC = buffer[2];
    uint32_t DD = buffer[3];

    uint32_t E = 0;
    uint32_t temp = 0;

    uint32_t i = 0;
    uint32_t j = 0;

    for(i = 0; i < 64; i++)
    {
        switch (i / 16)
        {
            case (0):  // 第1轮计算（F函数）
            {
                E = F(BB, CC, DD);
                j = i;
                break;
            }
            case (1):  // 第2轮计算（G函数）
            {
                E = G(BB, CC, DD);
                j = ((i * 5) + 1) % 16;
                break;
            }
            case (2):  // 第3轮计算（H函数）
            {
                E = H(BB, CC, DD);
                j = ((i * 3) + 5) % 16;
                break;
            }
            default:  // 第4轮计算（I函数）
            {
                E = I(BB, CC, DD);
                j = (i * 7) % 16;
                break;
            }
        }

        temp = DD;
        DD = CC;
        CC = BB;
        BB = BB + RotateLeft(AA + E + K[i] + input[j], S[i]);
        AA = temp;
    }

    buffer[0] += AA;
    buffer[1] += BB;
    buffer[2] += CC;
    buffer[3] += DD;
}

/*
 * MD5算法主函数
 */
void MD5(const unsigned char *message, size_t len, unsigned char *digest, size_t digest_len)
{
    MD5_CONTEXT ctx;
    digest_len = 32;

    if ((message == NULL) || (digest == NULL))
    {
        return ;
    }

    MD5_Init(&ctx);
    MD5_Update(&ctx, (uint8_t *)message, strlen(message));
    MD5_Final(&ctx);

    memcpy(digest, ctx.digest, 16);
}