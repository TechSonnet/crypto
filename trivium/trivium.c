#include <stdint.h>
#include <string.h>

typedef uint8_t trivium_ctx_t[36]; /* 288bit */
#define G(i) ((((*ctx)[(i)/8]) >> ((i)%8)) & 1)
#define S(i,v) ((*ctx)[(i)/8] = (((*ctx)[(i)/8]) & (uint8_t)~(1<<((i)%8))) | ((v)<<((i)%8)))

uint8_t trivium_enc(trivium_ctx_t *ctx){
	uint8_t t1, t2, t3, z;

	t1 = G(65)  ^ G(92);
	t2 = G(161) ^ G(176);
	t3 = G(242) ^ G(287);
	z  = t1 ^ t2 ^ t3;

	t1 ^= (G(90)  & G(91))  ^ G(170);
	t2 ^= (G(174) & G(175)) ^ G(263);
	t3 ^= (G(285) & G(286)) ^ G(68);

	// Shift entire state
	uint8_t i, c1 = 0, c2;
	for(i = 0; i < 36; ++i){
		c2 = ((*ctx)[i]) >> 7;
		(*ctx)[i] = (((*ctx)[i]) << 1) | c1;
		c1 = c2;
	}

	// Insert bits
	S(0,   t3);
	S(93,  t1);
	S(177, t2);

	return z ? 0x80 : 0x00;
}

uint8_t trivium_getbyte(trivium_ctx_t *ctx){
	uint8_t r = 0, i = 0;
	do {
		r >>= 1;
		r |= trivium_enc(ctx);
	} while (++i < 8);
	return r;
}

#define KEYSIZE_B ((keysize_b + 7) / 8)
#define IVSIZE_B  ((ivsize_b  + 7) / 8)

static const uint8_t rev_table[16] = {
	0x00, 0x08, 0x04, 0x0C,
	0x02, 0x0A, 0x06, 0x0E,
	0x01, 0x09, 0x05, 0x0D,
	0x03, 0x0B, 0x07, 0x0F
};

void trivium_init(const void *key, uint16_t keysize_b,
				  const void *iv,  uint16_t ivsize_b,
				  trivium_ctx_t *ctx){
	uint16_t i;
	uint8_t c1, c2;
	uint8_t t1, t2;

	// Zero-fill
	memset((*ctx) + KEYSIZE_B, 0, 35 - KEYSIZE_B);

	// Reverse bits in key
	c2 = 0;
	c1 = KEYSIZE_B;
	do {
		t1 = ((const uint8_t*)key)[--c1];
		t2 = (rev_table[t1 & 0x0F] << 4) | rev_table[t1 >> 4];
		(*ctx)[c2++] = t2;
	} while(c1 != 0);

	// Reverse bits in IV
	c2 = 12;
	c1 = IVSIZE_B;
	do {
		t1 = ((const uint8_t*)iv)[--c1];
		t2 = (rev_table[t1 & 0x0F] << 4) | rev_table[t1 >> 4];
		(*ctx)[c2++] = t2;
	} while(c1 != 0);

	// Adjust IV placement
	for(i = 12 + IVSIZE_B; i > 10; --i){
		c2 = ((*ctx)[i]) << 5;
		(*ctx)[i] = (((*ctx)[i]) >> 3) | c1;
		c1 = c2;
	}

	// Fill tail with constant
	(*ctx)[35] = 0xE0;

	// Run warm-up
	for(i = 0; i < 4 * 288; ++i){
		trivium_enc(ctx);
	}
}

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
	size_t ciphertext_len)
{
	trivium_ctx_t ctx;
	size_t i;

	// 参数检查
	if (key_len != 10 || iv_len != 10 || ciphertext_len < plaintext_len) {
		return;
	}

	// 初始化上下文
	trivium_init(key, 80, iv, 80, &ctx);

	// 加密过程（逐字节异或）
	for (i = 0; i < plaintext_len; i++) {
		ciphertext[i] = plaintext[i] ^ trivium_getbyte(&ctx);
	}
}

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
	size_t plaintext_len)
{
	// 流密码的解密与加密过程相同
	trivium_encrypt(ciphertext, ciphertext_len,
				   key, key_len,
				   iv, iv_len,
				   plaintext, plaintext_len);
}
