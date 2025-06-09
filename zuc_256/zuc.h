#ifndef GMSSL_ZUC_H
#define GMSSL_ZUC_H


/**
 * @brief ZUC256 stream encryption interface
 * @param plaintext      Plaintext data
 * @param plaintext_len  Plaintext length (bytes)
 * @param key            Input key (32 bytes fixed length)
 * @param key_len        Key length (must be 32)
 * @param iv             Initialization vector (23 bytes fixed length)
 * @param iv_len         IV length (must be 23)
 * @param ciphertext     Ciphertext output buffer
 * @param ciphertext_len Output buffer length (must be >= plaintext_len)
 * @return 1 if successful, 0 if failed
 */
int zuc256_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[32],
    size_t key_len,
    const uint8_t iv[23],
    size_t iv_len,
    uint8_t *ciphertext,
    size_t ciphertext_len);


/**
 * @brief ZUC256 stream decryption interface
 * @param ciphertext     Ciphertext data
 * @param ciphertext_len Ciphertext length (bytes)
 * @param key            Input key (32 bytes fixed length)
 * @param key_len        Key length (must be 32)
 * @param iv            Initialization vector (23 bytes fixed length)
 * @param iv_len         IV length (must be 23)
 * @param plaintext      Plaintext output buffer
 * @param plaintext_len  Output buffer length (must be >= ciphertext_len)
 * @return 1 if successful, 0 if failed
 */
int zuc256_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[32],
    size_t key_len,
    const uint8_t iv[23],
    size_t iv_len,
    uint8_t *plaintext,
    size_t plaintext_len);

#endif /* GMSSL_ZUC_H */