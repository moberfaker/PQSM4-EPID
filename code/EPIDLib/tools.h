#ifndef TOOLS_H
#define TOOLS_H

#include "typeDefine.h"
#include <stdio.h>
#include <Windows.h>
#include <bcrypt.h>
#include <assert.h>
#include "picnic.h"

/* ���������ҪDEBUG��λ����DEBUG */
#define DEBUG
#ifdef DEBUG
#define PRINT_DEBUG(printf_args) printf("%s %s:%d : ", __func__, __FILE__, __LINE__); printf printf_args; fflush(stdout);
#else
#define PRINT_DEBUG(args)   /* Nothing */
#endif

/* �����Ҫ���һЩ�ַ�����SHOW */
#define SHOW

/* ���������Ϣ */
//#define MSGS

/* ������� */
int random_bytes(uint8_t* buf, size_t len);

/* ��Ϣ��� */
void EPIDMessageSend(Msgs* Msgs);

/* ���16���� */
void EPIDprintHex(const char* s, const uint8_t* data, size_t len);

/***************** Key Generator *****************
*   ʹ�÷�����
        KeyGenerator(&pk ,&sk, &challenge)
*
*	����SM4�Ĺ�˽Կ����
*	sk = random(...)
*	plaintext = challenge or random(...)
*	pk = SM4(sk,plaintext)
*   ����ɹ����ɷ��� EXIT_SUCCESS
*   ʧ�ܷ��� EXIT_FAILURE
*/
int keygenerator(PubKey* pk, PriKey* sk, int No_c);

/* Msgs��ʼ�� */
int MsgsInit(Msgs* Msgs, size_t ByteLen);

/* Msgs�洢��Ϣ */
void Msgsmemcpy(Msgs* Msgs, const void* Src, size_t Size);

/* Msgsɾ��ͷ�� */
void Msgsdelfront(Msgs* message, size_t Size);

/* ����Ƿ���X�� */
int find_in_X(PubKey* pk, uint32_t index, uint64_t* X, uint16_t X_len);

#endif
