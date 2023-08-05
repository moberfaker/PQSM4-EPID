/*
文件介绍：
	此文件用于定义各种元素类型type
	定义基本元素，基本类型
*/
#ifndef TYPEDEFINE_H
#define TYPEDEFINE_H

#include <stdio.h>
#include <stdint.h>

#define MIN(a,b)            (((a) < (b)) ? (a) : (b))

/* 最大长度（单位bytes) */
#define CHALLENGE_SIZE_BYTE 16	// 生成公钥的明文
#define SM4_SIZE_BYTE 16	
#define	X_EACH_SIZE_BYTE (CHALLENGE_SIZE_BYTE + SM4_SIZE_BYTE)  //X的每一个元素为（pk,c）
#define X_INDEX_BYTE 4											// X索引大小

#define NAME_MAX_BYTES 12				//名字最大长度限制
#define GROUP_ID_BYTES 4				//群组id数据大小

/* 任务报文头 */
#define JOIN1 0
#define JOIN2 1
#define UPDATE 2
#define REVOKEKEY 3
#define SIGN 4

#define REALLOC_UP_BYTE 10				//每次加长内存大小
#define SIGN_SIZE_MAX_BYTE 16			//签名最大长度


/* 最大长度（单位bits) */
#define SM4_SIZE_BIT 128

typedef struct {
	unsigned char date[128 / 8];
}uint128_t;
typedef struct {
	unsigned char date[256 / 8];
}uint256_t;

/* 安全参数 */
#define EPID_L1 128
#define EPID_L3 256
#define EPID_L5 512

/* 消息传递窗口 */
typedef struct {
	uint8_t* message;
	size_t message_len;
}Msgs;

/* 成员承诺列表X */
typedef struct {
	uint8_t* XSig;				/// 群私钥对comlist->X签名
	size_t	 Sig_Size_Bytes;
	uint8_t* X;
}McomList;

/* 私钥 */
typedef struct {
	uint8_t	sk[SM4_SIZE_BYTE];	/// 私钥(随机生成PRF)
}PriKey;

/* 公钥 */
typedef struct {
	uint8_t c[CHALLENGE_SIZE_BYTE]; 	///	挑战
	uint8_t pk[SM4_SIZE_BYTE];			/// 公钥 - > SM4(sk,c)
} PubKey;

/* 成员证书 */
typedef struct {
	PubKey pk;
	McomList ComList;
	uint32_t Index_in_X;
}Cert;

#endif