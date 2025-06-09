#ifndef RC4_H
#define RC4_H

/**
 * RC4���ܺ���
 *
 * @param plaintext ��������ָ��
 * @param plaintext_len �������ݳ���
 * @param key ������Կָ��
 * @param key_len ��Կ����
 * @param ciphertext �������������ָ��
 * @param ciphertext_len ���Ļ�������С
 * @return �ɹ�����1��ʧ�ܷ���0
 */
int rc4_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, int key_len,
                unsigned char *ciphertext, int ciphertext_len);

/**
 * RC4���ܺ���
 *
 * @param ciphertext ��������ָ��
 * @param ciphertext_len �������ݳ���
 * @param key ������Կָ��
 * @param key_len ��Կ����
 * @param plaintext �������������ָ��
 * @param plaintext_len ���Ļ�������С
 * @return �ɹ�����1��ʧ�ܷ���0
 */
int rc4_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, int key_len,
                 unsigned char *plaintext, int plaintext_len);

#endif
