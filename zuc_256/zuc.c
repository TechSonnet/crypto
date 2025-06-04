#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>


// endian
/* Little Endian */
#define GETU16(p) \
((uint16_t)(p)[0] <<  8 | \
(uint16_t)(p)[1])

/* Big Endian */
#define GETU32(p) \
((uint32_t)(p)[0] << 24 | \
(uint32_t)(p)[1] << 16 | \
(uint32_t)(p)[2] <<  8 | \
(uint32_t)(p)[3])

/* Big Endian */
#define GETU64(p) \
((uint64_t)(p)[0] << 56 | \
(uint64_t)(p)[1] << 48 | \
(uint64_t)(p)[2] << 40 | \
(uint64_t)(p)[3] << 32 | \
(uint64_t)(p)[4] << 24 | \
(uint64_t)(p)[5] << 16 | \
(uint64_t)(p)[6] <<  8 | \
(uint64_t)(p)[7])


// WARNING: must not write PUTU32(buf, val++)
#define PUTU16(p,V) \
((p)[0] = (uint8_t)((V) >> 8), \
(p)[1] = (uint8_t)(V))

/* Big Endian R/W */
#define PUTU32(p,V) \
((p)[0] = (uint8_t)((V) >> 24), \
(p)[1] = (uint8_t)((V) >> 16), \
(p)[2] = (uint8_t)((V) >>  8), \
(p)[3] = (uint8_t)(V))

/* Big Endian */
#define PUTU64(p,V) \
((p)[0] = (uint8_t)((V) >> 56), \
(p)[1] = (uint8_t)((V) >> 48), \
(p)[2] = (uint8_t)((V) >> 40), \
(p)[3] = (uint8_t)((V) >> 32), \
(p)[4] = (uint8_t)((V) >> 24), \
(p)[5] = (uint8_t)((V) >> 16), \
(p)[6] = (uint8_t)((V) >>  8), \
(p)[7] = (uint8_t)(V))

/* Little Endian R/W */

#define GETU16_LE(p)	(*(const uint16_t *)(p))
#define GETU32_LE(p)	(*(const uint32_t *)(p))
#define GETU64_LE(p)	(*(const uint64_t *)(p))

#define PUTU16_LE(p,V)	*(uint16_t *)(p) = (V)
#define PUTU32_LE(p,V)	*(uint32_t *)(p) = (V)
#define PUTU64_LE(p,V)	*(uint64_t *)(p) = (V)

/* Rotate */

#define ROL32(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#define ROL64(a,n)	(((a)<<(n))|((a)>>(64-(n))))

#define ROR32(a,n)	ROL32((a),32-(n))
#define ROR64(a,n)	ROL64(a,64-n)
// endian end


// zuc.h

# define ZUC_KEY_SIZE	16
# define ZUC_IV_SIZE	16
# define ZUC_MAC_SIZE	4


typedef uint32_t ZUC_BIT;
typedef uint32_t ZUC_UINT5;
typedef uint8_t  ZUC_UINT6;
typedef uint32_t ZUC_UINT15;
typedef uint32_t ZUC_UINT31;
typedef uint32_t ZUC_UINT32;

typedef struct {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
} ZUC_STATE;


/**
 * @brief ZUC消息认证码上下文结构体
 *
 * 该结构体用于存储ZUC算法在计算消息认证码时的中间状态，
 * 包括线性反馈移位寄存器(LFSR)、寄存器R1和R2、临时变量T、
 * 密钥流K0以及缓冲区buf等信息。
 */
typedef struct ZUC_MAC_CTX_st {
	ZUC_UINT31 LFSR[16]; /**< 线性反馈移位寄存器，用于生成密钥流 */
	ZUC_UINT32 R1;       /**< 寄存器R1，参与F函数的计算 */
	ZUC_UINT32 R2;       /**< 寄存器R2，参与F函数的计算 */
	ZUC_UINT32 T;        /**< 临时变量，用于消息认证码的中间计算 */
	ZUC_UINT32 K0;       /**< 初始密钥流，用于消息认证码的计算 */
	uint8_t buf[4];      /**< 输入数据缓冲区，用于处理不足4字节的数据块 */
	size_t buflen;       /**< 缓冲区中当前数据的字节数 */
} ZUC_MAC_CTX;


#define ZUC_EEA_ENCRYPT_NWORDS(nbits) ((nbits + 31)/32)
#define ZUC_EEA_ENCRYPT_NBYTES(nbits) (ZUC_EEA_ENCRYPT_NWORDS(nbits)*4)



# define ZUC256_KEY_SIZE	32
# define ZUC256_IV_SIZE		23
# define ZUC256_MAC32_SIZE	4
# define ZUC256_MAC64_SIZE	8
# define ZUC256_MAC128_SIZE	16
# define ZUC256_MIN_MAC_SIZE	ZUC256_MAC32_SIZE
# define ZUC256_MAX_MAC_SIZE	ZUC256_MAC128_SIZE

typedef ZUC_STATE ZUC256_STATE;

/**
 * @brief ZUC256消息认证码上下文结构体
 *
 * 该结构体用于存储ZUC256算法在计算消息认证码时的中间状态，
 * 包括线性反馈移位寄存器(LFSR)、寄存器R1和R2、临时变量T、
 * 密钥流K0以及缓冲区buf等信息。
 */
typedef struct ZUC256_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T[4];
	ZUC_UINT32 K0[4];
	uint8_t buf[4];
	size_t buflen;
	int macbits;
} ZUC256_MAC_CTX;


/**
 * @brief ZUC加密上下文结构体
 *
 * 该结构体用于存储ZUC算法在加密数据时的中间状态，
 * 包括线性反馈移位寄存器(LFSR)、寄存器R1和R2、临时变量T、
 * 密钥流K0以及缓冲区buf等信息。
 */
typedef struct {
	ZUC_STATE zuc_state;
	uint8_t block[4];
	size_t block_nbytes;
} ZUC_CTX;

// zuc.h end



/**
 * @brief ZUC加密算法的密钥流生成函数
 *
 * 该函数根据给定的密钥和初始状态，生成ZUC加密算法的密钥流。
 *
 * @param[in] key 密钥，长度为16字节
 * @param[in] iv 初始状态，长度为16字节
 * @param[out] ciphertext 密钥流，长度为16字节
 */
static const ZUC_UINT15 KD[16] = {
	0x44D7,0x26BC,0x626B,0x135E,0x5789,0x35E2,0x7135,0x09AF,
	0x4D78,0x2F13,0x6BC4,0x1AF1,0x5E26,0x3C4D,0x789A,0x47AC,
};


/**
 * @brief S0盒查找表
 *
 * 该数组定义了ZUC算法中使用的S0非线性替换盒，包含256个8位无符号整数值。
 * S盒是密码学中的核心组件，用于提供非线性混淆特性，增强算法安全性。
 *
 * 每个元素对应一个字节输入到S盒的映射输出：
 * - 输入范围：0x00 到 0xff（即0到255）
 * - 输出范围：经过非线性变换后的8位值
 *
 * 示例：
 * S0[0x00] = 0x3e
 * S0[0x01] = 0x72
 * S0[0x02] = 0x5b
 * ...
 */
static const uint8_t S0[256] = {
	0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
	0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
	0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
	0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
	0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
	0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
	0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
	0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
	0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
	0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
	0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
	0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
	0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
	0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
	0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
	0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60,
};

/**
 * @brief S1盒查找表
 *
 * 该数组定义了ZUC算法中使用的S1非线性替换盒，包含256个8位无符号整数值。
 * S盒是密码学中的核心组件，用于提供非线性混淆特性，增强算法安全性。
 *
 * 每个元素对应一个字节输入到S盒的映射输出：
 * - 输入范围：0x00 到 0xff（即0到255）
 * - 输出范围：经过非线性变换后的8位值
 *
 * 示例：
 *S1[0x00] = 0x55
 */
static const uint8_t S1[256] = {
	0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
	0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
	0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
	0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
	0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
	0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
	0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
	0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
	0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
	0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
	0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
	0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
	0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
	0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
	0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
	0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2,
};


#define ADD31(a,b)	a += (b); a = (a & 0x7fffffff) + (a >> 31)
#define ROT31(a,k)	((((a) << (k)) | ((a) >> (31 - (k)))) & 0x7FFFFFFF)
#define ROT32(a,k)	(((a) << (k)) | ((a) >> (32 - (k))))

#define L1(X)			\
	((X) ^			\
	ROT32((X),  2) ^	\
	ROT32((X), 10) ^	\
	ROT32((X), 18) ^	\
	ROT32((X), 24))

#define L2(X)			\
	((X) ^			\
	ROT32((X),  8) ^	\
	ROT32((X), 14) ^	\
	ROT32((X), 22) ^	\
	ROT32((X), 30))


#define LFSRWithInitialisationMode(u)			\
	V = LFSR[0];					\
	ADD31(V, ROT31(LFSR[ 0],  8));			\
	ADD31(V, ROT31(LFSR[ 4], 20));			\
	ADD31(V, ROT31(LFSR[10], 21));			\
	ADD31(V, ROT31(LFSR[13], 17));			\
	ADD31(V, ROT31(LFSR[15], 15));			\
	ADD31(V, (u));					\
	{int j; for (j=0; j<15;j++) LFSR[j]=LFSR[j+1];}	\
	LFSR[15] = V

#define LFSRWithWorkMode()				\
	{						\
	int j;						\
	uint64_t a = LFSR[0];				\
	a += ((uint64_t)LFSR[ 0]) <<  8;		\
	a += ((uint64_t)LFSR[ 4]) << 20;		\
	a += ((uint64_t)LFSR[10]) << 21;		\
	a += ((uint64_t)LFSR[13]) << 17;		\
	a += ((uint64_t)LFSR[15]) << 15;		\
	a = (a & 0x7fffffff) + (a >> 31);		\
	V = (uint32_t)((a & 0x7fffffff) + (a >> 31));	\
	for (j = 0; j < 15; j++)			\
		LFSR[j] = LFSR[j+1];			\
	LFSR[15] = V;					\
	}

#define BitReconstruction2(X1,X2)					\
	X1 = ((LFSR[11] & 0xFFFF) << 16) | (LFSR[9] >> 15);		\
	X2 = ((LFSR[7] & 0xFFFF) << 16) | (LFSR[5] >> 15)

#define BitReconstruction3(X0,X1,X2)					\
	X0 = ((LFSR[15] & 0x7FFF8000) << 1) | (LFSR[14] & 0xFFFF);	\
	BitReconstruction2(X1,X2)

#define BitReconstruction4(X0,X1,X2,X3)					\
	BitReconstruction3(X0,X1,X2);					\
	X3 = ((LFSR[2] & 0xFFFF) << 16) | (LFSR[0] >> 15)


#define MAKEU31(k,d,iv) 				\
	(((uint32_t)(k) << 23) |			\
	 ((uint32_t)(d) <<  8) |			\
	  (uint32_t)(iv))

#define MAKEU32(a, b, c, d)				\
	(((uint32_t)(a) << 24) |			\
	 ((uint32_t)(b) << 16) | 			\
	 ((uint32_t)(c) <<  8) |			\
	 ((uint32_t)(d)))

#define F_(X1,X2)					\
	W1 = R1 + X1;					\
	W2 = R2 ^ X2;					\
	U = L1((W1 << 16) | (W2 >> 16));		\
	V = L2((W2 << 16) | (W1 >> 16));		\
	R1 = MAKEU32(	S0[U >> 24],			\
			S1[(U >> 16) & 0xFF],		\
			S0[(U >> 8) & 0xFF],		\
			S1[U & 0xFF]);			\
	R2 = MAKEU32(	S0[V >> 24],			\
			S1[(V >> 16) & 0xFF],		\
			S0[(V >> 8) & 0xFF],		\
			S1[V & 0xFF])

#define F(X0,X1,X2)					\
	(X0 ^ R1) + R2;					\
	F_(X1, X2)


/**
 * @brief 初始化ZUC算法状态
 *
 * 该函数使用提供的用户密钥和初始向量(IV)初始化ZUC算法的状态结构体。
 * 它首先设置LFSR寄存器，然后通过一系列变换完成状态初始化。
 *
 * @param state 指向ZUC_STATE结构体的指针，用于存储初始化后的状态
 * @param user_key 指向用户密钥的指针，长度必须为16字节
 * @param iv 指向初始向量的指针，长度必须为16字节
 */
void zuc_init(ZUC_STATE *state, const uint8_t *user_key, const uint8_t *iv)
{
	ZUC_UINT31 *LFSR = state->LFSR;
	uint32_t R1, R2;
	uint32_t X0, X1, X2;
	uint32_t W, W1, W2, U, V;
	int i;

	// 使用用户密钥、固定常量KD和初始向量IV初始化LFSR寄存器
	for (i = 0; i < 16; i++) {
		LFSR[i] = MAKEU31(user_key[i], KD[i], iv[i]);
	}

	// 初始化R1和R2寄存器
	R1 = 0;
	R2 = 0;

	// 执行32轮初始化模式变换
	for (i = 0; i < 32; i++) {
		BitReconstruction3(X0, X1, X2);       // 从LFSR生成输入参数X0,X1,X2
		W = F(X0, X1, X2);                    // 计算F函数
		LFSRWithInitialisationMode(W >> 1);   // 使用W右移1位更新LFSR
	}

	// 执行位重建操作
	BitReconstruction2(X1, X2);

	// 执行F_函数变换
	F_(X1, X2);

	// 使用工作模式更新LFSR
	LFSRWithWorkMode();

	// 保存R1和R2到状态结构体
	state->R1 = R1;
	state->R2 = R2;
}

/**
 * @brief 生成ZUC密钥流
 *
 * 该函数生成ZUC密钥流，并返回生成的密钥流。
 *
 * @param state 指向ZUC_STATE结构体的指针，用于存储ZUC算法的状态
 * @return 生成的密钥流
 */
uint32_t zuc_generate_keyword(ZUC_STATE *state)
{
	ZUC_UINT31 *LFSR = state->LFSR;
	uint32_t R1 = state->R1;
	uint32_t R2 = state->R2;
	uint32_t X0, X1, X2, X3;
	uint32_t W1, W2, U, V;
	uint32_t Z;

	BitReconstruction4(X0, X1, X2, X3);
	Z = X3 ^ F(X0, X1, X2);
	LFSRWithWorkMode();

	state->R1 = R1;
	state->R2 = R2;

	return Z;
}


/**
 * @brief 生成ZUC密钥流
 *
 * 该函数生成ZUC密钥流，并返回生成的密钥流。
 *
 * @param state 指向ZUC_STATE结构体的指针，用于存储ZUC算法的状态
 * @param nwords 要生成的密钥流的字数
 * @param keystream 指向存储密钥流的数组的指针
 */
void zuc_generate_keystream(ZUC_STATE *state, size_t nwords, uint32_t *keystream)
{
	ZUC_UINT31 *LFSR = state->LFSR;
	uint32_t R1 = state->R1;
	uint32_t R2 = state->R2;
	uint32_t X0, X1, X2, X3;
	uint32_t W1, W2, U, V;
	size_t i;

	for (i = 0; i < nwords; i ++) {
		/*
		BitReconstruction4(X0, X1, X2, X3);
		keystream[i] = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();
		*/
		uint32_t T0, T1, T2, T3, T4, T5, T6, T7;
		uint64_t a;
		int j;

		// expand BitReconstruction4(X0, X1, X2, X3)
		X0 = ((LFSR[15] & 0x7FFF8000) <<  1) | (LFSR[14] & 0xFFFF);
		X1 = ((LFSR[11] & 0x0000FFFF) << 16) | (LFSR[ 9] >> 15);
		X2 = ((LFSR[ 7] & 0x0000FFFF) << 16) | (LFSR[ 5] >> 15);
		X3 = ((LFSR[ 2] & 0x0000FFFF) << 16) | (LFSR[ 0] >> 15);

		//keystream[i] = X3 ^ F(X0, X1, X2);
		keystream[i] = X3 ^ ((X0 ^ R1) + R2);

		W1 = R1 + X1;
		W2 = R2 ^ X2;
		U = L1((W1 << 16) | (W2 >> 16));
		V = L2((W2 << 16) | (W1 >> 16));

		// table lookup together makes 10% faster
		T0 = S0[(U >> 24)       ];
		T2 = S0[(U >>  8) & 0xFF];
		T4 = S0[(V >> 24)       ];
		T6 = S0[(V >>  8) & 0xFF];

		T1 = S1[(U >> 16) & 0xFF];
		T3 = S1[(U      ) & 0xFF];
		T5 = S1[(V >> 16) & 0xFF];
		T7 = S1[(V      ) & 0xFF];

		R1 = MAKEU32(T0, T1, T2, T3);
		R2 = MAKEU32(T4, T5, T6, T7);

		// expand LFSRWithWorkMode()
		a = LFSR[0];
		a += ((uint64_t)LFSR[ 0]) <<  8;
		a += ((uint64_t)LFSR[ 4]) << 20;
		a += ((uint64_t)LFSR[10]) << 21;
		a += ((uint64_t)LFSR[13]) << 17;
		a += ((uint64_t)LFSR[15]) << 15;
		a = (a & 0x7fffffff) + (a >> 31);
		V = (uint32_t)((a & 0x7fffffff) + (a >> 31));

		for (j = 0; j < 15; j++) {
			LFSR[j] = LFSR[j+1];
		}
		LFSR[15] = V;
	}

	state->R1 = R1;
	state->R2 = R2;
}

/**
 * @brief 加密ZUC数据
 *
 * 该函数使用ZUC算法加密给定的数据，并返回加密后的数据。
 *
 * @param state 指向ZUC_STATE结构体的指针，用于存储ZUC算法的状态
 * @param in 指向待加密数据的指针
 * @param inlen 待加密数据的长度
 * @param out 指向存储加密结果的数组的指针
 */
void zuc_encrypt(ZUC_STATE *state, const uint8_t *in, size_t inlen, uint8_t *out)
{
	ZUC_UINT31 *LFSR = state->LFSR;
	uint32_t R1 = state->R1;
	uint32_t R2 = state->R2;
	uint32_t X0, X1, X2, X3;
	uint32_t W1, W2, U, V;
	uint32_t Z;

	while (inlen) {
		/*
		BitReconstruction4(X0, X1, X2, X3);
		Z = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();
		*/
		uint32_t T0, T1, T2, T3, T4, T5, T6, T7;
		uint64_t a;
		int j;

		// expand BitReconstruction4(X0, X1, X2, X3)
		X0 = ((LFSR[15] & 0x7FFF8000) <<  1) | (LFSR[14] & 0xFFFF);
		X1 = ((LFSR[11] & 0x0000FFFF) << 16) | (LFSR[ 9] >> 15);
		X2 = ((LFSR[ 7] & 0x0000FFFF) << 16) | (LFSR[ 5] >> 15);
		X3 = ((LFSR[ 2] & 0x0000FFFF) << 16) | (LFSR[ 0] >> 15);

		//keystream[i] = X3 ^ F(X0, X1, X2);
		Z = X3 ^ ((X0 ^ R1) + R2);

		W1 = R1 + X1;
		W2 = R2 ^ X2;
		U = L1((W1 << 16) | (W2 >> 16));
		V = L2((W2 << 16) | (W1 >> 16));

		// table lookup together makes 10% faster
		T0 = S0[(U >> 24)       ];
		T2 = S0[(U >>  8) & 0xFF];
		T4 = S0[(V >> 24)       ];
		T6 = S0[(V >>  8) & 0xFF];

		T1 = S1[(U >> 16) & 0xFF];
		T3 = S1[(U      ) & 0xFF];
		T5 = S1[(V >> 16) & 0xFF];
		T7 = S1[(V      ) & 0xFF];

		R1 = MAKEU32(T0, T1, T2, T3);
		R2 = MAKEU32(T4, T5, T6, T7);

		// expand LFSRWithWorkMode()
		a = LFSR[0];
		a += ((uint64_t)LFSR[ 0]) <<  8;
		a += ((uint64_t)LFSR[ 4]) << 20;
		a += ((uint64_t)LFSR[10]) << 21;
		a += ((uint64_t)LFSR[13]) << 17;
		a += ((uint64_t)LFSR[15]) << 15;
		a = (a & 0x7fffffff) + (a >> 31);
		V = (uint32_t)((a & 0x7fffffff) + (a >> 31));

		for (j = 0; j < 15; j++) {
			LFSR[j] = LFSR[j+1];
		}
		LFSR[15] = V;

		// xor with plaintext
		Z ^= GETU32(in);

		// output ciphertext
		if (inlen >= 4) {
			PUTU32(out, Z);
			inlen -= 4;
			in += 4;
			out += 4;
		} else {
			uint8_t word[4];
			size_t i;

			PUTU32(word, Z);
			for (i = 0; i < inlen; i++) {
				out[i] = word[i];
			}
			break;
		}
	}

	state->R1 = R1;
	state->R2 = R2;
}

/**
 * @brief 计算ZUC消息认证码
 *
 * 该函数使用ZUC算法计算给定数据流的消息认证码。
 *
 * @param state 指向ZUC_STATE结构体的指针，用于存储ZUC算法的状态
 * @param in 指向待计算消息认证码的数据的指针
 * @param inlen 待计算消息认证码的数据的长度
 * @param mac 存储计算出的消息认证码的数组
 */
void zuc_mac_init(ZUC_MAC_CTX *ctx, const uint8_t key[16], const uint8_t iv[16])
{
	memset(ctx, 0, sizeof(*ctx));
	zuc_init((ZUC_STATE *)ctx, key, iv);
	ctx->K0 = zuc_generate_keyword((ZUC_STATE *)ctx);
}

/**
 * @brief 更新ZUC消息认证码
 *
 * 该函数使用ZUC算法更新给定数据流的消息认证码。
 *
 * @param ctx 指向ZUC_MAC_CTX结构体的指针，用于存储ZUC算法的状态
 * @param data 指向待更新消息认证码的数据的指针
 * @param len 待更新消息认证码的数据的长度
 */
void zuc_mac_update(ZUC_MAC_CTX *ctx, const uint8_t *data, size_t len)
{
	ZUC_UINT32 T = ctx->T;
	ZUC_UINT32 K0 = ctx->K0;
	ZUC_UINT32 K1, M;
	ZUC_UINT31 *LFSR = ctx->LFSR;
	ZUC_UINT32 R1 = ctx->R1;
	ZUC_UINT32 R2 = ctx->R2;
	ZUC_UINT32 X0, X1, X2, X3;
	ZUC_UINT32 W1, W2, U, V;
	size_t i;

	if (!data || !len) {
		return;
	}

	if (ctx->buflen) {
		size_t num = sizeof(ctx->buf) - ctx->buflen;
		if (len < num) {
			memcpy(ctx->buf + ctx->buflen, data, len);
			ctx->buflen += len;
			return;
		}

		memcpy(ctx->buf + ctx->buflen, data, num);
		M = GETU32(ctx->buf);
		ctx->buflen = 0;

		BitReconstruction4(X0, X1, X2, X3);
		K1 = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();

		for (i = 0; i < 32; i++) {
			if (M & 0x80000000) {
				T ^= K0;
			}
			M <<= 1;
			K0 = (K0 << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += num;
		len -= num;
	}

	while (len >= 4) {
		M = GETU32(data);

		BitReconstruction4(X0, X1, X2, X3);
		K1 = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();

		for (i = 0; i < 32; i++) {
			if (M & 0x80000000) {
				T ^= K0;
			}
			M <<= 1;
			K0 = (K0 << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += 4;
		len -= 4;
	}

	if (len) {
		memcpy(ctx->buf, data, len);
		ctx->buflen = len;
	}
	ctx->R1 = R1;
	ctx->R2 = R2;
	ctx->K0 = K0;
	ctx->T = T;
}

/**
 * @brief 完成ZUC消息认证码计算
 *
 * 该函数使用ZUC算法完成给定数据流的消息认证码计算。
 *
 * @param ctx 指向ZUC_MAC_CTX结构体的指针，用于存储ZUC算法的状态
 * @param data 指向待计算消息认证码的数据的指针
 * @param nbits 待计算消息认证码的数据的长度（以位为单位）
 * @param mac 存储计算出的消息认证码的数组
 */
void zuc_mac_finish(ZUC_MAC_CTX *ctx, const uint8_t *data, size_t nbits, uint8_t mac[4])
{
	ZUC_UINT32 T;
	ZUC_UINT32 K0;
	ZUC_UINT32 K1, M;
	ZUC_UINT31 *LFSR = ctx->LFSR;
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 X0, X1, X2, X3;
	ZUC_UINT32 W1, W2, U, V;
	size_t i;

	if (!data)
		nbits = 0;

	if (nbits >= 8) {
		zuc_mac_update(ctx, data, nbits/8);
		data += nbits/8;
		nbits %= 8;
	}

	T = ctx->T;
	K0 = ctx->K0;
	R1 = ctx->R1;
	R2 = ctx->R2;

	if (nbits)
		ctx->buf[ctx->buflen] = *data;

	if (ctx->buflen || nbits) {
		M = GETU32(ctx->buf);
		BitReconstruction4(X0, X1, X2, X3);
		K1 = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();

		for (i = 0; i < ctx->buflen * 8 + nbits; i++) {
			if (M & 0x80000000) {
				T ^= K0;
			}
			M <<= 1;
			K0 = (K0 << 1) | (K1 >> 31);
			K1 <<= 1;
		}
	}

	T ^= K0;

	BitReconstruction4(X0, X1, X2, X3);
	K1 = X3 ^ F(X0, X1, X2);
	LFSRWithWorkMode();
	T ^= K1;

	ctx->T = T;
	PUTU32(mac, T);

	memset(ctx, 0, sizeof(*ctx));
}

/**
 * @brief ZUC密钥扩展表
 */
typedef uint8_t ZUC_UINT7;

/**
 * @brief ZUC256密钥扩展表
 */
static const ZUC_UINT7 ZUC256_D[][16] = {
	{0x22,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
	{0x22,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
	{0x23,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
	{0x23,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
};

/**
 * @brief 创建ZUC256密钥扩展表
 */
#define ZUC256_MAKEU31(a,b,c,d)				\
	(((uint32_t)(a) << 23) |			\
	 ((uint32_t)(b) << 16) |			\
	 ((uint32_t)(c) <<  8) |			\
	  (uint32_t)(d))


/**
 * @brief 设置ZUC256密钥扩展表
 *
 * 该函数使用给定的密钥和IV来设置ZUC256密钥扩展表。
 *
 * @param key 密钥扩展表指针
 * @param K 密钥数组
 * @param IV IV数组
 * @param macbits 消息认证码位数
 */
static void zuc256_set_mac_key(ZUC_STATE *key, const uint8_t K[32],
	const uint8_t IV[23], int macbits)
{
	ZUC_UINT31 *LFSR = key->LFSR;
	uint32_t R1, R2;
	uint32_t X0, X1, X2;
	uint32_t W, W1, W2, U, V;
	const ZUC_UINT7 *D;
	int i;

	ZUC_UINT6 IV17 = IV[17] >> 2;
	ZUC_UINT6 IV18 = ((IV[17] & 0x3) << 4) | (IV[18] >> 4);
	ZUC_UINT6 IV19 = ((IV[18] & 0xf) << 2) | (IV[19] >> 6);
	ZUC_UINT6 IV20 = IV[19] & 0x3f;
	ZUC_UINT6 IV21 = IV[20] >> 2;
	ZUC_UINT6 IV22 = ((IV[20] & 0x3) << 4) | (IV[21] >> 4);
	ZUC_UINT6 IV23 = ((IV[21] & 0xf) << 2) | (IV[22] >> 6);
	ZUC_UINT6 IV24 = IV[22] & 0x3f;

	D = macbits/32 < 3 ? ZUC256_D[macbits/32] : ZUC256_D[3];
	LFSR[0] = ZUC256_MAKEU31(K[0], D[0], K[21], K[16]);
	LFSR[1] = ZUC256_MAKEU31(K[1], D[1], K[22], K[17]);
	LFSR[2] = ZUC256_MAKEU31(K[2], D[2], K[23], K[18]);
	LFSR[3] = ZUC256_MAKEU31(K[3], D[3], K[24], K[19]);
	LFSR[4] = ZUC256_MAKEU31(K[4], D[4], K[25], K[20]);
	LFSR[5] = ZUC256_MAKEU31(IV[0], (D[5] | IV17), K[5], K[26]);
	LFSR[6] = ZUC256_MAKEU31(IV[1], (D[6] | IV18), K[6], K[27]);
	LFSR[7] = ZUC256_MAKEU31(IV[10], (D[7] | IV19), K[7], IV[2]);
	LFSR[8] = ZUC256_MAKEU31(K[8], (D[8] | IV20), IV[3], IV[11]);
	LFSR[9] = ZUC256_MAKEU31(K[9], (D[9] | IV21), IV[12], IV[4]);
	LFSR[10] = ZUC256_MAKEU31(IV[5], (D[10] | IV22), K[10], K[28]);
	LFSR[11] = ZUC256_MAKEU31(K[11], (D[11] | IV23), IV[6], IV[13]);
	LFSR[12] = ZUC256_MAKEU31(K[12], (D[12] | IV24), IV[7], IV[14]);
	LFSR[13] = ZUC256_MAKEU31(K[13], D[13], IV[15], IV[8]);
	LFSR[14] = ZUC256_MAKEU31(K[14], (D[14] | (K[31] >> 4)), IV[16], IV[9]);
	LFSR[15] = ZUC256_MAKEU31(K[15], (D[15] | (K[31] & 0x0F)), K[30], K[29]);

	R1 = 0;
	R2 = 0;

	for (i = 0; i < 32; i++) {
		BitReconstruction3(X0, X1, X2);
		W = F(X0, X1, X2);
		LFSRWithInitialisationMode(W >> 1);
	}

	BitReconstruction2(X1, X2);
	F_(X1, X2);
	LFSRWithWorkMode();

	key->R1 = R1;
	key->R2 = R2;
}

/**
 * @brief 初始化ZUC256密钥扩展表
 *
 * 该函数使用给定的密钥和IV来初始化ZUC256密钥扩展表。
 *
 * @param key 密钥扩展表指针
 * @param K 密钥数组
 * @param IV IV数组
 */
void zuc256_init(ZUC_STATE *key, const uint8_t K[32],
	const uint8_t IV[23])
{
	zuc256_set_mac_key(key, K, IV, 0);
}

/**
 * @brief 生成ZUC256密钥流
 *
 * 该函数使用给定的ZUC256密钥扩展表和密钥流长度来生成ZUC256密钥流。
 *
 * @param state ZUC256密钥扩展表指针
 * @param nwords 密钥流长度（以32位字为单位）
 * @param keystream 存储生成的密钥流的数组
 */
uint32_t zuc256_generate_keyword(ZUC_STATE *state) {
	return zuc_generate_keyword(state);
}

/**
 * @brief 生成ZUC256密钥流
 *
 * 该函数使用给定的ZUC256密钥扩展表和密钥流长度来生成ZUC256密钥流。
 *
 * @param state ZUC256密钥扩展表指针
 * @param nwords 密钥流长度（以32位字为单位）
 * @param keystream 存储生成的密钥流的数组
 */
void zuc256_generate_keystream(ZUC_STATE *state, size_t nwords, uint32_t *keystream) {
	zuc_generate_keystream(state, nwords, keystream);
}

/**
 * @brief 初始化ZUC256密钥流
 *
 * 该函数使用给定的密钥和IV来初始化ZUC256密钥流。
 *
 * @param ctx 密钥流指针
 * @param key 密钥数组
 * @param iv IV数组
 * @param macbits 消息认证码位数
 */
void zuc256_mac_init(ZUC256_MAC_CTX *ctx, const uint8_t key[32],
	const uint8_t iv[23], int macbits)
{
	if (macbits < 32)
		macbits = 32;
	else if (macbits > 64)
		macbits = 128;
	memset(ctx, 0, sizeof(*ctx));
	zuc256_set_mac_key((ZUC256_STATE *)ctx, key, iv, macbits);
	zuc256_generate_keystream((ZUC256_STATE *)ctx, macbits/32, ctx->T);
	zuc256_generate_keystream((ZUC256_STATE *)ctx, macbits/32, ctx->K0);
	ctx->macbits = (macbits/32) * 32;
}


/**
 * @brief 更新ZUC256消息认证码
 *
 * 该函数使用ZUC256算法更新给定数据流的消息认证码。
 * 它处理部分字节缓冲区的填充，逐字处理数据，并根据MAC位数调整密钥流生成。
 *
 * @param ctx 指向ZUC256_MAC_CTX结构体的指针，用于存储ZUC256算法的状态
 * @param data 指向待更新消息认证码的数据的指针
 * @param len 待更新消息认证码的数据的长度（以字节为单位）
 */
void zuc256_mac_update(ZUC256_MAC_CTX *ctx, const uint8_t *data, size_t len)
{
	ZUC_UINT32 K1, M;
	size_t n = ctx->macbits / 32; // 计算需要处理的密钥流字数
	size_t i, j;

	if (!data || !len) {
		return;
	}

	// 处理缓冲区中残留的数据
	if (ctx->buflen) {
		size_t num = sizeof(ctx->buf) - ctx->buflen;
		if (len < num) {
			memcpy(ctx->buf + ctx->buflen, data, len);
			ctx->buflen += len;
			return;
		}

		memcpy(ctx->buf + ctx->buflen, data, num);
		M = GETU32(ctx->buf);
		ctx->buflen = 0;

		K1 = zuc256_generate_keyword((ZUC256_STATE *)ctx); // 生成新的密钥流

		// 对每个位进行处理
		for (i = 0; i < 32; i++) {
			// 如果当前位为1，则对T数组进行异或操作
			if (M & 0x80000000) {
				for (j = 0; j < n; j++) {
					ctx->T[j] ^= ctx->K0[j];
				}
			}
			M <<= 1;
			// 更新K0数组
			for (j = 0; j < n - 1; j++) {
				ctx->K0[j] = (ctx->K0[j] << 1) | (ctx->K0[j + 1] >> 31);
			}
			ctx->K0[j] = (ctx->K0[j] << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += num;
		len -= num;
	}

	// 处理完整的4字节块
	while (len >= 4) {
		M = GETU32(data);
		K1 = zuc256_generate_keyword((ZUC256_STATE *)ctx); // 生成新的密钥流

		// 对每个位进行处理
		for (i = 0; i < 32; i++) {
			// 如果当前位为1，则对T数组进行异或操作
			if (M & 0x80000000) {
				for (j = 0; j < n; j++) {
					ctx->T[j] ^= ctx->K0[j];
				}
			}
			M <<= 1;
			// 更新K0数组
			for (j = 0; j < n - 1; j++) {
				ctx->K0[j] = (ctx->K0[j] << 1) | (ctx->K0[j + 1] >> 31);
			}
			ctx->K0[j] = (ctx->K0[j] << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += 4;
		len -= 4;
	}

	// 存储剩余的不完整字节到缓冲区
	if (len) {
		memcpy(ctx->buf, data, len);
		ctx->buflen = len;
	}
}
/**
 * @brief ZUC256 MAC计算结束
 * @param ctx ZUC256 MAC上下文
 * @param data 输入数据
 * @param nbits 输入数据长度（字节数）
 * @param mac 输出MAC值（16字节）
 */
void zuc256_mac_finish(ZUC256_MAC_CTX *ctx, const uint8_t *data, size_t nbits, uint8_t *mac)
{
	ZUC_UINT32 K1, M;
	size_t n = ctx->macbits/32;
	size_t i, j;


	if (!data)
		nbits = 0;

	if (nbits >= 8) {
		zuc256_mac_update(ctx, data, nbits/8);
		data += nbits/8;
		nbits %= 8;
	}

	if (nbits)
		ctx->buf[ctx->buflen] = *data;

	if (ctx->buflen || nbits) {
		M = GETU32(ctx->buf);
		K1 = zuc256_generate_keyword((ZUC256_STATE *)ctx);


		for (i = 0; i < ctx->buflen * 8 + nbits; i++) {
			if (M & 0x80000000) {
				for (j = 0; j < n; j++) {
					ctx->T[j] ^= ctx->K0[j];
				}
			}
			M <<= 1;
			for (j = 0; j < n - 1; j++) {
				ctx->K0[j] = (ctx->K0[j] << 1) | (ctx->K0[j + 1] >> 31);
			}
			ctx->K0[j] = (ctx->K0[j] << 1) | (K1 >> 31);
			K1 <<= 1;
		}
	}

	for (j = 0; j < n; j++) {
		ctx->T[j] ^= ctx->K0[j];
		PUTU32(mac, ctx->T[j]);
		mac += 4;
	}

	memset(ctx, 0, sizeof(*ctx));
}

/**
 * @brief 执行ZUC256加密测试（无返回值，直接断言结果）
 * @param key 输入密钥（32字节）
 * @param iv 输入初始向量（23字节）
 * @param expected_ciphertext 预期密文（20个uint32_t）
 */
void test_zuc256_encryption(
	const uint8_t key[32],
	const uint8_t iv[23],
	const uint32_t expected_ciphertext[20])
{
	ZUC_STATE zuc_key;
	uint32_t generated_ciphertext[20] = {0};

	// 1. 初始化（完全保持原测试代码）
	zuc256_init(&zuc_key, key, iv);

	// 2. 生成密钥流（完全保持原测试代码）
	zuc_generate_keystream(&zuc_key, 20, generated_ciphertext);

	// 3. 验证结果（直接断言）
	if (memcmp(generated_ciphertext, expected_ciphertext, sizeof(generated_ciphertext)) != 0) {
		printf("[FAIL] Ciphertext mismatch!\n");

		// 打印差异详情
		for (int j = 0; j < 20; j++) {
			if (generated_ciphertext[j] != expected_ciphertext[j]) {
				printf("  [%2d] Expected: 0x%08X, Actual: 0x%08X\n",
					j, expected_ciphertext[j], generated_ciphertext[j]);
			}
		}
		// 直接终止程序或抛出异常（根据实际需求）
		exit(EXIT_FAILURE);
	}

	printf("[OK] Test passed\n");
}

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
	size_t ciphertext_len)
{

	if (key_len != 32 || iv_len != 23) {
		return; // 或定义错误处理
	}

	/* 实际加密逻辑（完全不变）*/
	ZUC_STATE state;
	zuc256_init(&state, key, iv);

	uint32_t keystream[(plaintext_len + 3)/4];
	zuc_generate_keystream(&state, (plaintext_len + 3)/4, keystream);

	for (size_t i = 0; i < plaintext_len; i++) {
		ciphertext[i] = plaintext[i] ^ ((uint8_t*)keystream)[i];
	}
}

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
	size_t plaintext_len)
{
	/* 解密直接调用加密（流密码特性）*/
	zuc256_encrypt(
		ciphertext, ciphertext_len,
		key, key_len,
		iv, iv_len,
		plaintext, plaintext_len
	);
}