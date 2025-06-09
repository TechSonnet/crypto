#include <stdint.h>
/**
 * RC4��Կ�ṹ�嶨��
 *
 * �ýṹ�����ڴ洢RC4�����㷨����Կ״̬
 * RC4��һ�ֶԳ��������㷨������Կ����Ϊ256�ֽ�
 * �ڼ��ܺͽ��ܹ����У���Կ״̬������ض����㷨���г�ʼ���͸���
 */
typedef struct RC4_KEY_S{
	unsigned char S[256];
}RC4_KEY;


/**
 * ��ʼ��RC4��Կ
 *
 * �ú������ڳ�ʼ��RC4��Կ�ṹ�壬���ݸ�������Կ����Կ���Ƚ��г�ʼ��
 *
 * @param rc4_key RC4��Կ�ṹ��ָ��
 * @param key ��Կ
 * @param keylength ��Կ����
 */
void RC4_key(RC4_KEY *rc4_key, unsigned char *key, int *keylength) {
	int i, j, temp;
	for (i = 0; i < 256; i++)
		rc4_key->S[i] = i;
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + rc4_key->S[i] + *(key + i % *keylength)) % 256;
		temp = rc4_key->S[i];
		rc4_key->S[i] = rc4_key->S[j];
		rc4_key->S[j] = temp;
	}
}

/**
 * RC4�����㷨
 *
 * �ú������ڼ������ģ�����RC4��Կ�����Ľ��м���
 *
 * @param rc4_key RC4��Կ�ṹ��ָ��
 * @param plaintext ����
 * @param plaintext_length ���ĳ���
 * @param ciphertext ����
 */
void RC4(RC4_KEY *rc4_key, unsigned char *plaintext, int *plaintext_length, unsigned char *ciphertext) {
	int i = 0, j = 0, k = 0, n, temp;
	for (k = 0; k < *plaintext_length; k++) {
		i = (i + 1) % 256;
		j = (j + rc4_key->S[i]) % 256;
		temp = rc4_key->S[i];
		rc4_key->S[i] = rc4_key->S[j];
		rc4_key->S[j] = temp;
		n = rc4_key->S[(rc4_key->S[i] + rc4_key->S[j]) % 256];
		*(ciphertext + k) = *(plaintext + k) ^ n;
	}
}


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
int rc4_encrypt(const uint8_t *plaintext, int plaintext_len,
				const uint8_t *key, int key_len,
				uint8_t *ciphertext, int ciphertext_len)
{
	// ǿ���������
	if (!plaintext || !ciphertext || !key ||
		plaintext_len <= 0 || key_len <= 0 ||
		ciphertext_len < plaintext_len)
	{
		return 0;
	}

	// ��ʼ��RC4��Կ�ṹ
	RC4_KEY rc4_key;
	int tmp_keylen = key_len;
	int tmp_plaintext_len = plaintext_len;

	// ������Կ�����㷨��ʼ�� - ����ԭʼ���÷�ʽ
	RC4_key(&rc4_key, (unsigned char*)key, &tmp_keylen);

	// ִ��RC4���ܲ��� - ����ԭʼ���÷�ʽ
	RC4(&rc4_key, (unsigned char*)plaintext, &tmp_plaintext_len, ciphertext);

	return 1;
}

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
int rc4_decrypt(const uint8_t *ciphertext, int ciphertext_len,
				const uint8_t *key, int key_len,
				uint8_t *plaintext, int plaintext_len)
{
	// ֱ�ӵ��ü��ܺ�����RC4�Գ����ԣ�
	return rc4_encrypt(ciphertext, ciphertext_len,
					  key, key_len,
					  plaintext, plaintext_len);
}