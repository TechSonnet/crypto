#ifndef GMSSL_ZUC_H
#define GMSSL_ZUC_H



/**
 * @brief ZUC256流加密接口（仅参数顺序调整，功能完全不变）
 * @param plaintext     明文数据
 * @param plaintext_len 明文长度（字节）
 * @param key           输入密钥（32字节固定长度）
 * @param key_len       密钥长度（必须为32）
 * @param iv            输入初始向量（23字节固定长度）
 * @param iv_len        初始向量长度（必须为23）
 * @param ciphertext    密文输出缓冲区
 * @param ciphertext_len 输出缓冲区长度（新参数，可忽略）
 */
void zuc256_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[32],
    size_t key_len,
    const uint8_t iv[23],
    size_t iv_len,
    uint8_t *ciphertext,
    size_t ciphertext_len);


/**
 * @brief ZUC256流解密接口（参数顺序对称调整）
 * @param ciphertext     密文数据
 * @param ciphertext_len 密文长度（字节）
 * @param key            输入密钥（32字节固定长度）
 * @param key_len        密钥长度（必须为32）
 * @param iv             输入初始向量（23字节固定长度）
 * @param iv_len         初始向量长度（必须为23）
 * @param plaintext      明文输出缓冲区
 * @param plaintext_len   输出缓冲区长度（新参数，可忽略）
 */
void zuc256_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[32],
    size_t key_len,
    const uint8_t iv[23],
    size_t iv_len,
    uint8_t *plaintext,
    size_t plaintext_len);

#endif /* GMSSL_ZUC_H */