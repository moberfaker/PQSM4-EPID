#ifndef EPIDMEMBER_H
#define EPIDMEMBER_H

#include "typeDefine.h"
#include <stdio.h>
#include <assert.h>
#include "tools.h"
#include "PicnicSign.h"
/* 成员ctx */
typedef struct {
	uint8_t name[NAME_MAX_BYTES];			//名字 最长20
	int Groupid;			//加入EPID群组id
	PubKey Group_pk;			//EPID群组公钥
	PriKey sk;					//成员私钥
	PubKey pk;					//成员公钥(SM4(sk,c))
	size_t MemSize;				//群成员数量
	Cert Cert;					//成员承诺列表
}GP_MEMBER_CTX;

/* 成员初始化 */
void EPID_Member_Join1(GP_MEMBER_CTX* ctx, const char* name, int Join_group, Msgs* message);

/* 成员回应挑战并生成公私钥 */
void EPID_Member_Join2(Msgs* message, GP_MEMBER_CTX* ctx);

/* 群成员接收Cert，结束Join */
void EPID_Member_Join_finish(Msgs* message, GP_MEMBER_CTX* ctx);

/* 群成员请求新cert */
void EPID_Member_update_cert_call(Msgs* message, GP_MEMBER_CTX* ctx);

/* 群成员更新Cert */
int EPID_Member_update_cert(Msgs* message, GP_MEMBER_CTX* ctx);

/* 群成员主动退出群 */
void EPID_Member_Exit_Group(Msgs* message, GP_MEMBER_CTX* ctx);

/* 群成员签名 */
int EPID_Sign(GP_MEMBER_CTX* ctx, Msgs* message, size_t Member_size, int* PreT, int* OnT);

#endif