#ifndef MD5_H
#define MD5_H

#include <stdint.h>

 /**
 * 计算输入消息的 MD5 哈希值，固定输出长度32字节。
 *
 * @param message     输入消息指针
 * @param len         输入消息长度（单位：字节）
 * @param digest      输出缓冲区（应预留足够空间）
 * @param digest_len  输出摘要长度（单位：字节，最大为 64）
 */
void MD5(const unsigned char *message, size_t len, unsigned char *digest, size_t digest_len);
 
#endif
