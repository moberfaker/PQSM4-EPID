/*
�ļ����ܣ�
	���ļ����ڶ������Ԫ������type
	�������Ԫ�أ���������
*/
#ifndef TYPEDEFINE_H
#define TYPEDEFINE_H

#include <stdio.h>
#include <stdint.h>

#define MIN(a,b)            (((a) < (b)) ? (a) : (b))

/* ��󳤶ȣ���λbytes) */
#define CHALLENGE_SIZE_BYTE 16	// ���ɹ�Կ������
#define SM4_SIZE_BYTE 16	
#define	X_EACH_SIZE_BYTE (CHALLENGE_SIZE_BYTE + SM4_SIZE_BYTE)  //X��ÿһ��Ԫ��Ϊ��pk,c��
#define X_INDEX_BYTE 4											// X������С

#define NAME_MAX_BYTES 12				//������󳤶�����
#define GROUP_ID_BYTES 4				//Ⱥ��id���ݴ�С

/* ������ͷ */
#define JOIN1 0
#define JOIN2 1
#define UPDATE 2
#define REVOKEKEY 3
#define SIGN 4

#define REALLOC_UP_BYTE 10				//ÿ�μӳ��ڴ��С
#define SIGN_SIZE_MAX_BYTE 16			//ǩ����󳤶�


/* ��󳤶ȣ���λbits) */
#define SM4_SIZE_BIT 128

typedef struct {
	unsigned char date[128 / 8];
}uint128_t;
typedef struct {
	unsigned char date[256 / 8];
}uint256_t;

/* ��ȫ���� */
#define EPID_L1 128
#define EPID_L3 256
#define EPID_L5 512

/* ��Ϣ���ݴ��� */
typedef struct {
	uint8_t* message;
	size_t message_len;
}Msgs;

/* ��Ա��ŵ�б�X */
typedef struct {
	uint8_t* XSig;				/// Ⱥ˽Կ��comlist->Xǩ��
	size_t	 Sig_Size_Bytes;
	uint8_t* X;
}McomList;

/* ˽Կ */
typedef struct {
	uint8_t	sk[SM4_SIZE_BYTE];	/// ˽Կ(�������PRF)
}PriKey;

/* ��Կ */
typedef struct {
	uint8_t c[CHALLENGE_SIZE_BYTE]; 	///	��ս
	uint8_t pk[SM4_SIZE_BYTE];			/// ��Կ - > SM4(sk,c)
} PubKey;

/* ��Ա֤�� */
typedef struct {
	PubKey pk;
	McomList ComList;
	uint32_t Index_in_X;
}Cert;

#endif