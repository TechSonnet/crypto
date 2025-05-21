#ifndef SHA_256_H
#define SHA_256_H

#include <stdint.h>
#include <stddef.h>

/**
 * 计算输入消息的 SHA-256 哈希值，允许指定输出长度（不超过 64 字节）。
 *
 * @param message     输入消息指针
 * @param len         输入消息长度（单位：字节）
 * @param digest      输出缓冲区（应预留足够空间）
 * @param digest_len  输出摘要长度（单位：字节，最大为 64）
 */
void SHA_256(const unsigned char *message, size_t len, unsigned char *digest, size_t digest_len);

#endif // SHA_256_H