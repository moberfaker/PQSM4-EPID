#ifndef EPIDMANAGER_H
#define EPIDMANAGER_H


#include "typeDefine.h"
#include "tools.h"
#include "EPIDMember.h"
#include <picnic.h>
#include <memory.h>
#include <inttypes.h>

/* ����Աctx */
typedef struct {
	int Groupid;			//����EPIDȺ��id
	PriKey sk;					//EPIDȺ��˽Կ
	PubKey pk;					//EPIDȺ�鹫Կ
	uint16_t MemSize;				//EPIDȺ���Ա����
	size_t MaxSizeNow;			//Ŀǰ��ʼ������
	McomList ComList;			//��Ա��ŵ�б�
}GP_MANAGER_CTX;


/* Ⱥ��ʼ�� */
void EPID_Group_Init(GP_MANAGER_CTX* ctx, const unsigned int Parameter, int* IDPool);

/* ��Ա��Ϣ����Ԥ�������ս�ַ� */
void EPID_Group_Join1(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool);

/* ����Ⱥ�顢ComListǩ�����ַ�֤��*/
int EPID_Group_Join2(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool);

/* ������ */
int EPID_Member_Join_fake(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool);

/* ����Ⱥ��Ա����cert���� */
void EPID_Manager_updaet_cert(Msgs* message, GP_MANAGER_CTX* ctx);

/* ������Ⱥ��Ա���� */
void EPID_Manager_Exit_Group(Msgs* message, GP_MANAGER_CTX* ctx);

/* ǩ����֤ */
int EPID_Verify(uint8_t** text, Msgs* message, size_t Member_size, uint8_t* X);

#endif // !EPIDMANAGER_H