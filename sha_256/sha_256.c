#include <string.h>
#include <stdint.h>

// 定义 SHA_256 输出摘要长度（字节）
#define SHA_256_DIGEST_LENGTH 32
// 定义 SHA_256 数据块大小（字节）
#define SHA_256_BLOCK_SIZE 64

// 定义 SHA_256 上下文结构体，用于存储哈希计算过程中的中间状态
typedef struct {
    uint32_t h[8];  // 存储当前的哈希值
    uint64_t bitcount;  // 记录输入数据的总位数
    uint8_t buffer[SHA_256_BLOCK_SIZE];  // 用于暂存未处理完的数据块
    size_t buffer_len;  // 记录 buffer 中已存储的数据长度
} SHA_256_CTX;

// 右循环宏，用于将 32 位整数 x 循环右移 n 位
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// 定义常量表，SHA-256 算法中使用的 64 个常量
static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * 主压缩函数，对每个 64 字节的数据块执行哈希运算
 *
 * @param ctx 指向 SHA_256 上下文结构体的指针，存储当前哈希计算的中间状态
 * @param data 指向 64 字节数据块的指针，待处理的数据块
 */
static void sha_256_transform(SHA_256_CTX *ctx, const unsigned char *data) {
    uint32_t w[64];  // 用于存储扩展后的消息块

    // 把输入块按大端展开到 w[0..15]
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4]     << 24)  // 取第 i 个 4 字节块的第一个字节并左移 24 位
               | ((uint32_t)data[i*4 + 1] << 16)  // 取第 i 个 4 字节块的第二个字节并左移 16 位
               | ((uint32_t)data[i*4 + 2] << 8)   // 取第 i 个 4 字节块的第三个字节并左移 8 位
               | ((uint32_t)data[i*4 + 3]);       // 取第 i 个 4 字节块的第四个字节
    }

    // 扩展消息到 w[16..63]
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15], 7)  ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);  // 计算 s0
        uint32_t s1 = ROTR(w[i-2], 17)  ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);  // 计算 s1
        w[i] = w[i-16] + s0 + w[i-7] + s1;  // 计算 w[i]
    }

    // 初始化工作变量，将当前哈希值赋值给工作变量
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
    uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];

    // 主压缩循环，进行 64 轮迭代
    for (int i = 0; i < 64; i++) {
        uint32_t S1    = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);  // 计算 S1
        uint32_t ch    = (e & f) ^ (~e & g);  // 计算 ch
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];  // 计算 temp1
        uint32_t S0    = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);  // 计算 S0
        uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);  // 计算 maj
        uint32_t temp2 = S0 + maj;  // 计算 temp2

        // 更新工作变量
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // 更新哈希值，将工作变量的值累加到当前哈希值上
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

/**
 * 初始化 SHA_256 上下文结构体
 *
 * @param ctx 指向 SHA_256 上下文结构体的指针
 */
void SHA_256_Init(SHA_256_CTX *ctx) {
    // 初始哈希值，SHA-256 算法规定的初始常量
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;

    ctx->bitcount = 0;  // 初始化输入数据总位数为 0
    ctx->buffer_len = 0;  // 初始化 buffer 中已存储的数据长度为 0
}

/**
 * 处理输入数据，将输入数据分块传递给 sha_256_transform 函数进行处理
 *
 * @param ctx 指向 SHA_256 上下文结构体的指针，存储当前哈希计算的中间状态
 * @param data 指向输入数据的指针
 * @param len 输入数据的长度（字节）
 * @return 成功返回 1
 */
int SHA_256_Update(SHA_256_CTX *ctx, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;  // 将输入数据指针转换为 unsigned char 类型
    size_t n;

    // 更新输入数据的总位数
    ctx->bitcount += len * 8;

    // 如果 buffer 中还有未处理完的数据
    if (ctx->buffer_len) {
        n = SHA_256_BLOCK_SIZE - ctx->buffer_len;  // 计算 buffer 还能容纳的数据长度
        if (n > len)
            n = len;  // 如果输入数据长度小于 buffer 剩余空间，则取输入数据长度
        memcpy(ctx->buffer + ctx->buffer_len, p, n);  // 将输入数据复制到 buffer 中
        ctx->buffer_len += n;  // 更新 buffer 中已存储的数据长度
        p += n;  // 移动输入数据指针
        len -= n;  // 更新剩余未处理的输入数据长度

        // 如果 buffer 已满
        if (ctx->buffer_len == SHA_256_BLOCK_SIZE) {
            sha_256_transform(ctx, ctx->buffer);  // 对 buffer 中的数据块进行处理
            ctx->buffer_len = 0;  // 清空 buffer
        }
    }

    // 处理完整的数据块
    while (len >= SHA_256_BLOCK_SIZE) {
        sha_256_transform(ctx, p);  // 对当前数据块进行处理
        p += SHA_256_BLOCK_SIZE;  // 移动输入数据指针
        len -= SHA_256_BLOCK_SIZE;  // 更新剩余未处理的输入数据长度
    }

    // 如果还有剩余数据，将其复制到 buffer 中
    if (len) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }

    return 1;
}

/**
 * 结束处理函数，对剩余的数据进行填充，并处理最后一个或两个数据块，最终输出哈希值
 *
 * @param digest 指向输出哈希值的指针
 * @param ctx 指向 SHA_256 上下文结构体的指针，存储当前哈希计算的中间状态
 * @return 成功返回 1
 */
int SHA_256_Final(unsigned char *digest, SHA_256_CTX *ctx) {
    uint64_t bit_len = ctx->bitcount;  // 获取输入数据的总位数
    uint64_t be_bit_len = __builtin_bswap64(bit_len);  // 将总位数转换为大端序
    size_t rem = ctx->buffer_len;  // 获取 buffer 中剩余未处理的数据长度

    ctx->buffer[rem] = 0x80;  // 在剩余数据后面添加二进制填充位 0x80

    // 显式清零剩余字节（确保 block[rem+1..63] 为 0）
    if (rem + 1 < SHA_256_BLOCK_SIZE) {
        memset(ctx->buffer + rem + 1, 0, SHA_256_BLOCK_SIZE - (rem + 1));
    }

    // 根据剩余数据长度决定处理方式
    if (rem <= 55) {
        // 使用 memcpy 写入长度字段（避免对齐问题）
        memcpy(ctx->buffer + 56, &be_bit_len, sizeof(be_bit_len));
        sha_256_transform(ctx, ctx->buffer);  // 处理最后一个数据块
    } else {
        sha_256_transform(ctx, ctx->buffer);  // 处理当前数据块
        // 创建全零的填充块并写入长度
        uint8_t pad[SHA_256_BLOCK_SIZE] = {0};
        memcpy(pad + 56, &be_bit_len, sizeof(be_bit_len));
        sha_256_transform(ctx, pad);  // 处理填充块
    }

    // 输出大端字节序的哈希值
    for (int i = 0; i < 8; i++) {
        digest[i*4    ] = (ctx->h[i] >> 24) & 0xFF;  // 取第 i 个 32 位哈希值的最高 8 位
        digest[i*4 + 1] = (ctx->h[i] >> 16) & 0xFF;  // 取第 i 个 32 位哈希值的次高 8 位
        digest[i*4 + 2] = (ctx->h[i] >> 8)  & 0xFF;  // 取第 i 个 32 位哈希值的次低 8 位
        digest[i*4 + 3] =  ctx->h[i]        & 0xFF;  // 取第 i 个 32 位哈希值的最低 8 位
    }

    return 1;
}

/**
 * 封装接口，初始化上下文结构体，调用 SHA_256_Update 和 SHA_256_Final 函数完成哈希计算
 *
 * @param message 指向输入消息的指针
 * @param len 输入消息的长度（字节）
 * @param digest 指向输出哈希值的指针
 * @param digest_len 输出哈希值的长度（字节）
 */
void SHA_256(const unsigned char *message, size_t len, unsigned char *digest, size_t digest_len) {
    SHA_256_CTX ctx;
    SHA_256_Init(&ctx);
    SHA_256_Update(&ctx, message, len);
    SHA_256_Final(digest, &ctx);

    // 如果指定的输出长度大于 SHA_256_DIGEST_LENGTH，则将其截断
    if (digest_len > SHA_256_DIGEST_LENGTH) {
        digest_len = SHA_256_DIGEST_LENGTH;
    }
    // 如果需要截断结果
    if (digest_len < SHA_256_DIGEST_LENGTH) {
        memcpy(digest, digest, digest_len);
    }
}