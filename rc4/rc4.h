#ifndef RC4_H
#define RC4_H

/**
 * RC4加密函数
 *
 * @param plaintext 明文数据指针
 * @param plaintext_len 明文数据长度
 * @param key 加密密钥指针
 * @param key_len 密钥长度
 * @param ciphertext 密文输出缓冲区指针
 * @param ciphertext_len 密文缓冲区大小
 * @return 成功返回1，失败返回0
 */
int rc4_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, int key_len,
                unsigned char *ciphertext, int ciphertext_len);

/**
 * RC4解密函数
 *
 * @param ciphertext 密文数据指针
 * @param ciphertext_len 密文数据长度
 * @param key 解密密钥指针
 * @param key_len 密钥长度
 * @param plaintext 明文输出缓冲区指针
 * @param plaintext_len 明文缓冲区大小
 * @return 成功返回1，失败返回0
 */
int rc4_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, int key_len,
                 unsigned char *plaintext, int plaintext_len);

#endif
