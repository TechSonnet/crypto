
#ifndef TRIVIUM_H_
#define TRIVIUM_H_
#include <stdint.h>


/**
 * @brief Trivium流加密接口
 * @param plaintext     明文数据
 * @param plaintext_len 明文长度（字节）
 * @param key           输入密钥（10字节固定长度）
 * @param key_len       密钥长度（必须为10）
 * @param iv            输入初始向量（10字节固定长度）
 * @param iv_len        初始向量长度（必须为10）
 * @param ciphertext    密文输出缓冲区
 * @param ciphertext_len 输出缓冲区长度（必须 >= plaintext_len）
 */
void trivium_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[10],
    size_t key_len,
    const uint8_t iv[10],
    size_t iv_len,
    uint8_t *ciphertext,
    size_t ciphertext_len);

/**
 * @brief Trivium流解密接口
 * @param ciphertext    密文数据
 * @param ciphertext_len 密文长度（字节）
 * @param key           输入密钥（10字节固定长度）
 * @param key_len       密钥长度（必须为10）
 * @param iv            输入初始向量（10字节固定长度）
 * @param iv_len        初始向量长度（必须为10）
 * @param plaintext     明文输出缓冲区
 * @param plaintext_len 输出缓冲区长度（必须 >= ciphertext_len）
 */
void trivium_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[10],
    size_t key_len,
    const uint8_t iv[10],
    size_t iv_len,
    uint8_t *plaintext,
    size_t plaintext_len);

#endif /*TRIVIUM_H_*/
