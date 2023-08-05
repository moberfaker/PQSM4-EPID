#ifndef TOOLS_H
#define TOOLS_H

#include "typeDefine.h"
#include <stdio.h>
#include <Windows.h>
#include <bcrypt.h>
#include <assert.h>
#include "picnic.h"

/* 如果出错需要DEBUG定位则定义DEBUG */
#define DEBUG
#ifdef DEBUG
#define PRINT_DEBUG(printf_args) printf("%s %s:%d : ", __func__, __FILE__, __LINE__); printf printf_args; fflush(stdout);
#else
#define PRINT_DEBUG(args)   /* Nothing */
#endif

/* 如果需要输出一些字符则定义SHOW */
#define SHOW

/* 输出传输消息 */
//#define MSGS

/* 随机函数 */
int random_bytes(uint8_t* buf, size_t len);

/* 消息输出 */
void EPIDMessageSend(Msgs* Msgs);

/* 输出16进制 */
void EPIDprintHex(const char* s, const uint8_t* data, size_t len);

/***************** Key Generator *****************
*   使用方法：
        KeyGenerator(&pk ,&sk, &challenge)
*
*	基于SM4的公私钥生成
*	sk = random(...)
*	plaintext = challenge or random(...)
*	pk = SM4(sk,plaintext)
*   如果成功生成返回 EXIT_SUCCESS
*   失败返回 EXIT_FAILURE
*/
int keygenerator(PubKey* pk, PriKey* sk, int No_c);

/* Msgs初始化 */
int MsgsInit(Msgs* Msgs, size_t ByteLen);

/* Msgs存储消息 */
void Msgsmemcpy(Msgs* Msgs, const void* Src, size_t Size);

/* Msgs删除头部 */
void Msgsdelfront(Msgs* message, size_t Size);

/* 检查是否在X内 */
int find_in_X(PubKey* pk, uint32_t index, uint64_t* X, uint16_t X_len);

#endif
