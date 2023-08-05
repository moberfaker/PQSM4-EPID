#ifndef EPIDMEMBER_H
#define EPIDMEMBER_H

#include "typeDefine.h"
#include <stdio.h>
#include <assert.h>
#include "tools.h"
#include "PicnicSign.h"
/* ��Աctx */
typedef struct {
	uint8_t name[NAME_MAX_BYTES];			//���� �20
	int Groupid;			//����EPIDȺ��id
	PubKey Group_pk;			//EPIDȺ�鹫Կ
	PriKey sk;					//��Ա˽Կ
	PubKey pk;					//��Ա��Կ(SM4(sk,c))
	size_t MemSize;				//Ⱥ��Ա����
	Cert Cert;					//��Ա��ŵ�б�
}GP_MEMBER_CTX;

/* ��Ա��ʼ�� */
void EPID_Member_Join1(GP_MEMBER_CTX* ctx, const char* name, int Join_group, Msgs* message);

/* ��Ա��Ӧ��ս�����ɹ�˽Կ */
void EPID_Member_Join2(Msgs* message, GP_MEMBER_CTX* ctx);

/* Ⱥ��Ա����Cert������Join */
void EPID_Member_Join_finish(Msgs* message, GP_MEMBER_CTX* ctx);

/* Ⱥ��Ա������cert */
void EPID_Member_update_cert_call(Msgs* message, GP_MEMBER_CTX* ctx);

/* Ⱥ��Ա����Cert */
int EPID_Member_update_cert(Msgs* message, GP_MEMBER_CTX* ctx);

/* Ⱥ��Ա�����˳�Ⱥ */
void EPID_Member_Exit_Group(Msgs* message, GP_MEMBER_CTX* ctx);

/* Ⱥ��Աǩ�� */
int EPID_Sign(GP_MEMBER_CTX* ctx, Msgs* message, size_t Member_size, int* PreT, int* OnT);

#endif