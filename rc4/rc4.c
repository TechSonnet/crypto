#include <stdint.h>
/**
 * RC4密钥结构体定义
 *
 * 该结构体用于存储RC4加密算法的密钥状态
 * RC4是一种对称流加密算法，其密钥长度为256字节
 * 在加密和解密过程中，密钥状态会根据特定的算法进行初始化和更新
 */
typedef struct RC4_KEY_S{
	unsigned char S[256];
}RC4_KEY;


/**
 * 初始化RC4密钥
 *
 * 该函数用于初始化RC4密钥结构体，根据给定的密钥和密钥长度进行初始化
 *
 * @param rc4_key RC4密钥结构体指针
 * @param key 密钥
 * @param keylength 密钥长度
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
 * RC4加密算法
 *
 * 该函数用于加密明文，根据RC4密钥和明文进行加密
 *
 * @param rc4_key RC4密钥结构体指针
 * @param plaintext 明文
 * @param plaintext_length 明文长度
 * @param ciphertext 密文
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
int rc4_encrypt(const uint8_t *plaintext, int plaintext_len,
				const uint8_t *key, int key_len,
				uint8_t *ciphertext, int ciphertext_len)
{
	// 强化参数检查
	if (!plaintext || !ciphertext || !key ||
		plaintext_len <= 0 || key_len <= 0 ||
		ciphertext_len < plaintext_len)
	{
		return 0;
	}

	// 初始化RC4密钥结构
	RC4_KEY rc4_key;
	int tmp_keylen = key_len;
	int tmp_plaintext_len = plaintext_len;

	// 设置密钥调度算法初始化 - 保持原始调用方式
	RC4_key(&rc4_key, (unsigned char*)key, &tmp_keylen);

	// 执行RC4加密操作 - 保持原始调用方式
	RC4(&rc4_key, (unsigned char*)plaintext, &tmp_plaintext_len, ciphertext);

	return 1;
}

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
int rc4_decrypt(const uint8_t *ciphertext, int ciphertext_len,
				const uint8_t *key, int key_len,
				uint8_t *plaintext, int plaintext_len)
{
	// 直接调用加密函数（RC4对称特性）
	return rc4_encrypt(ciphertext, ciphertext_len,
					  key, key_len,
					  plaintext, plaintext_len);
}