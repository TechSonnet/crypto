#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

/**

 * 此函数计算输入消息的 SHA3-512 哈希值，并将结果存储在提供的 `digest` 缓冲区中。
 * SHA3-512 是 SHA-3 系列哈希函数的一种，输出为 512 位（64 字节）。
 *
 * @param  message       输入消息的指针。
 * @param  message_len   输入消息的长度（字节）。
 * @param digest        存储计算结果的缓冲区，大小应至少为 64 字节。
 * @param  digest_len    输出缓冲区的大小，必须为 64 字节（SHA3-512 输出大小）。
 *
 *
 * @return 无返回值，计算结果存储在 `digest` 中。
 */
void sha3_512(const uint8_t *message, size_t message_len, uint8_t *digest, size_t digest_len);

#endif
