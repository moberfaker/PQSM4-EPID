#include <stdio.h>
#include <assert.h>
#include "EPIDmanager.h"
#include "typeDefine.h"
#include "tools.h"
#include <picnic.h>
#include "KKWsign.h"

//Ⱥ����Աctx��ʼ��
/*
	ͨ������Ⱥ��ȫ������64��128��192��256��(Ĭ��Ϊ128)������Ⱥ��˽Կgsk,gpk
*/
void EPID_Group_Init(GP_MANAGER_CTX* ctx, const unsigned int Parameter, int* IDPool)
{
	memset(ctx, 0x00, sizeof(GP_MANAGER_CTX));

	/// ��ID����ȡ��һ��δ����Ⱥ��ID
	ctx->Groupid = *IDPool;
	*IDPool += 1;
	fprintf(stdout, "\n��ȡEPIDȺID: %d \n", ctx->Groupid);
	fflush(stdout);

	/// Ⱥ����Ա��Կ����
	fprintf(stdout, "����EPIDȺ����Ա��˽Կ... \n");
	fflush(stdout);

	int ret = keygenerator(&ctx->pk, &ctx->sk, 1);
	if (ret != 0) {
		printf("keygen failed\n");
		printf("Group Init failed\n");
		exit(-1);
	}
	printf("Suceess.\n");

	/// Ⱥ��Ϣ��ʼ��
	fprintf(stdout, "��ʼ��Ⱥ��Ϣ... \n");
	fflush(stdout);

	ctx->MemSize = 0;
	ctx->MaxSizeNow = 10;		// ��ʼ��10���ռ�
	ctx->ComList.X = (uint8_t*)malloc(ctx->MaxSizeNow * X_EACH_SIZE_BYTE);
	ctx->ComList.Sig_Size_Bytes = 0;
	if (ctx->ComList.X == NULL) {
		printf("X List malloc failed\n");
		printf("Group Init failed\n");
		exit(-1);
	}
	memset(ctx->ComList.X, 0x00, ctx->MaxSizeNow * X_EACH_SIZE_BYTE);

	printf("Success.\n");
}



/* ��Ա��Ϣ������Ⱥ��������봦�� */
// Ⱥ����Ա����ͷ�����ս
void EPID_Group_Join1(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	//��ȡ��Ϣ
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);


	//��ʼ����Ϣ
	MsgsInit(message, 16 + X_EACH_SIZE_BYTE + CHALLENGE_SIZE_BYTE);
	size_t temp = JOIN1;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//��ȡ��ӦȺ����Ϣ
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;
	printf("����%s����Ⱥ����\n", Name);



	//��ȡȺ�鹫Կ��Ϣ
	Msgsmemcpy(message, ctxgp->pk.c, CHALLENGE_SIZE_BYTE);
	Msgsmemcpy(message, ctxgp->pk.pk, SM4_SIZE_BYTE);
	EPIDprintHex("����Ⱥ��Կ", &ctxgp->pk, X_EACH_SIZE_BYTE);

	//������ս
	if (random_bytes(message->message + message->message_len, CHALLENGE_SIZE_BYTE) != 0) {
		PRINT_DEBUG(("Failed to generate challenge\n"));
		PRINT_DEBUG(("MemberJoin init failed\n"));
		exit(-1);
	}
	EPIDprintHex("������ս", message->message + message->message_len, CHALLENGE_SIZE_BYTE);
	message->message_len += CHALLENGE_SIZE_BYTE;

	//������Ϣ
#ifdef MSGS
	EPIDMessageSend(message);
#endif
}



/* ����Ⱥ�顢ComListǩ�����ַ�֤��*/
// Ⱥ����Ա�ṩJoin���񣬲�����ComList������cert
int EPID_Group_Join2(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	//�����Ϣ����
	printf("����Ա��Ϣ...\n");
	if (message->message_len != NAME_MAX_BYTES + GROUP_ID_BYTES + X_EACH_SIZE_BYTE) {
		printf("No Message from Member yet.\n");
		return -1;
	}


	//��ȡ��Ϣ
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);
	PubKey Memberpk;
	memcpy(&Memberpk, message->message + NAME_MAX_BYTES + GROUP_ID_BYTES, X_EACH_SIZE_BYTE);


	//��ȡ��ӦȺ����Ϣ
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;
	//printf("\n\n-------------------------  GROUP %d Manager  -------------------------\n", Groupid);


	//printf("Deal with Join Request From  %s\n", Name);

	//��ǰ����
	ctxgp->MemSize++;
	if (ctxgp->MemSize + 2 >= ctxgp->MaxSizeNow) {
		ctxgp->MaxSizeNow += REALLOC_UP_BYTE;
		uint8_t* temp = realloc(ctxgp->ComList.X, ctxgp->MaxSizeNow * X_EACH_SIZE_BYTE);
		if (temp == NULL) {
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
			printf("ComList Realloc failed  \n");
			SetConsoleTextAttribute(hConsole, 0x0f);
		}
		else {
			ctxgp->ComList.X = temp;
		}
	}


	//��ӹ�Կ��ŵ
	printf("��Ӹó�Ա��Կ��ŵ...\n");
	memcpy(ctxgp->ComList.X + X_EACH_SIZE_BYTE * (ctxgp->MemSize - 1), &Memberpk, X_EACH_SIZE_BYTE);//���ƹ�Կ

	//��Xǩ��
	size_t signature_len = picnic_signature_size(Picnic2_L1_FS);
	ctxgp->ComList.XSig = (uint8_t*)malloc(signature_len);
	if (ctxgp->ComList.XSig == NULL) {
		printf("failed to allocate signature\n");
		exit(-1);
	}
	int ret = EPID_picnic_sign(&ctxgp->sk, &ctxgp->pk, (const char*)ctxgp->ComList.X, X_EACH_SIZE_BYTE * (size_t)ctxgp->MemSize, ctxgp->ComList.XSig, &signature_len);
	if (ret != 0) {
		printf("picnic_sign failed\n");
		exit(-1);
	}
	/* signature_len has the exact number of bytes used */
	if (signature_len < picnic_signature_size(Picnic2_L1_FS)) {
		uint8_t* newsig = realloc(ctxgp->ComList.XSig, signature_len);
		if (newsig == NULL) {
			printf("failed to re-size signature\n");
			/* Not an error, we can continue with signature */
		}
		else {
			ctxgp->ComList.XSig = newsig;
		}
	}
	ctxgp->ComList.Sig_Size_Bytes = signature_len;
	//��ʼ����Ϣ
	printf("����֤��...\n");
	MsgsInit(message, 16 + X_EACH_SIZE_BYTE + X_INDEX_BYTE + sizeof(signature_len) + signature_len + sizeof(uint32_t) + X_EACH_SIZE_BYTE * ctxgp->MemSize);
	size_t temp = JOIN2;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//����֤��
	printf("����֤��...\n");
	printf("Send MemberPubKey to Member %s(%d Bytes)\n", Name, X_EACH_SIZE_BYTE);
	printf("Send Index-in-X(%u) to Member %s(%d Bytes)\n", ctxgp->MemSize, Name, X_INDEX_BYTE);
	printf("Send Sig_Len to Member %s(%llu Bytes)\n", Name, sizeof(size_t));
	printf("Send X_Sig to Member %s(%llu Bytes)\n", Name, signature_len);
	printf("Send X_Size(%u) to Member %s(%llu Bytes)\n", ctxgp->MemSize, Name, sizeof(uint32_t));
	printf("Send X to Member %s(%d Bytes)\n", Name, X_EACH_SIZE_BYTE * ctxgp->MemSize);
	uint32_t Index_in_X = ctxgp->MemSize - 1;
	Msgsmemcpy(message, &Memberpk, X_EACH_SIZE_BYTE);
	Msgsmemcpy(message, &Index_in_X, X_INDEX_BYTE);
	Msgsmemcpy(message, &signature_len, sizeof(size_t));
	Msgsmemcpy(message, ctxgp->ComList.XSig, signature_len);
	Msgsmemcpy(message, &ctxgp->MemSize, sizeof(uint32_t));
	Msgsmemcpy(message, ctxgp->ComList.X, X_EACH_SIZE_BYTE * ctxgp->MemSize);

	//������Ϣ
#ifdef MSGS
	EPIDMessageSend(message);

#endif
	//printf("----------------------------------------------------------------------\n\n");

	return 1;
}


/* ������ӳ�Ա�� */
int EPID_Member_Join_fake(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	//��ȡ��Ϣ
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);
	PubKey Memberpk;
	memcpy(&Memberpk, message->message + NAME_MAX_BYTES + GROUP_ID_BYTES, X_EACH_SIZE_BYTE);


	//��ȡ��ӦȺ����Ϣ
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;

	//��ǰ����
	ctxgp->MemSize++;
	if (ctxgp->MemSize + 2 >= ctxgp->MaxSizeNow) {
		ctxgp->MaxSizeNow += REALLOC_UP_BYTE;
		uint8_t* temp = realloc(ctxgp->ComList.X, ctxgp->MaxSizeNow * X_EACH_SIZE_BYTE);
		if (temp == NULL) {
			printf("ComList Realloc failed  \n");
		}
		else {
			ctxgp->ComList.X = temp;
		}
	}

	memcpy(ctxgp->ComList.X + X_EACH_SIZE_BYTE * (ctxgp->MemSize - 1), Memberpk.c, CHALLENGE_SIZE_BYTE);//������ս
	memcpy(ctxgp->ComList.X + X_EACH_SIZE_BYTE * (ctxgp->MemSize - 1) + CHALLENGE_SIZE_BYTE, Memberpk.pk, SM4_SIZE_BYTE);//���ƹ�Կ

	//��Xǩ��
	size_t signature_len = picnic_signature_size(Picnic2_L1_FS);
	ctxgp->ComList.XSig = (uint8_t*)malloc(signature_len);
	if (ctxgp->ComList.XSig == NULL) {
		printf("failed to allocate signature\n");
		exit(-1);
	}

	int ret = EPID_picnic_sign(&ctxgp->sk, &ctxgp->pk, (const char*)ctxgp->ComList.X, X_EACH_SIZE_BYTE * (size_t)ctxgp->MemSize, ctxgp->ComList.XSig, &signature_len);
	if (ret != 0) {
		printf("picnic_sign failed\n");
		exit(-1);
	}

	/* signature_len has the exact number of bytes used */
	if (signature_len < picnic_signature_size(Picnic2_L1_FS)) {
		uint8_t* newsig = realloc(ctxgp->ComList.XSig, signature_len);
		if (newsig == NULL) {
			printf("failed to re-size signature\n");
			/* Not an error, we can continue with signature */
		}
		else {
			ctxgp->ComList.XSig = newsig;
		}
	}

	ctxgp->ComList.Sig_Size_Bytes = signature_len;


	//��ʼ����Ϣ
	ret = MsgsInit(message, X_EACH_SIZE_BYTE + X_INDEX_BYTE + sizeof(signature_len) + signature_len + sizeof(uint32_t) + X_EACH_SIZE_BYTE * ctxgp->MemSize);
	if (ret == -1) {
		printf("MemberJoin failed\n");
		exit(-1);
	}

	uint32_t Index_in_X = ctxgp->MemSize - 1;
	Msgsmemcpy(message, &Memberpk, X_EACH_SIZE_BYTE);
	Msgsmemcpy(message, &Index_in_X, X_INDEX_BYTE);
	Msgsmemcpy(message, &signature_len, sizeof(size_t));
	Msgsmemcpy(message, ctxgp->ComList.XSig, signature_len);
	Msgsmemcpy(message, &ctxgp->MemSize, sizeof(uint32_t));
	Msgsmemcpy(message, ctxgp->ComList.X, X_EACH_SIZE_BYTE * ctxgp->MemSize);

	return 1;
}



void EPID_Manager_updaet_cert(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool) {
	//�����Ϣ����
	printf("����Ա��Ϣ...\n");
	if (message->message_len != NAME_MAX_BYTES + GROUP_ID_BYTES + X_EACH_SIZE_BYTE) {
		printf("No Message from Member yet.\n");
		return;
	}


	//��ȡ��Ϣ
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);
	PubKey Memberpk;
	memcpy(&Memberpk, message->message + NAME_MAX_BYTES + GROUP_ID_BYTES, X_EACH_SIZE_BYTE);


	//��ȡ��ӦȺ����Ϣ
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;

	//����Ƿ�ΪȺ��Ա
	uint32_t Index_in_X = find_in_X(&Memberpk, 0, ctxgp->ComList.X, ctxgp->MemSize);
	if (Index_in_X == -1) {
		printf("\033[32m Not a Member in Group!\n");
		return;
	}

	//��ʼ����Ϣ
	printf("����֤��...\n");
	MsgsInit(message, 16 + X_INDEX_BYTE + sizeof(ctxgp->ComList.Sig_Size_Bytes) + ctxgp->ComList.Sig_Size_Bytes + sizeof(uint32_t) + X_EACH_SIZE_BYTE * ctxgp->MemSize);
	size_t temp = UPDATE;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//����֤��
	printf("����֤��...\n");
	printf("Send Index-in-X(%u) to Member %s(%d Bytes)\n", ctxgp->MemSize, Name, X_INDEX_BYTE);
	printf("Send Sig_Len to Member %s(%llu Bytes)\n", Name, sizeof(size_t));
	printf("Send X_Sig to Member %s(%llu Bytes)\n", Name, ctxgp->ComList.Sig_Size_Bytes);
	printf("Send X_Size(%u) to Member %s(%llu Bytes)\n", ctxgp->MemSize, Name, sizeof(uint32_t));
	printf("Send X to Member %s(%d Bytes)\n", Name, X_EACH_SIZE_BYTE * ctxgp->MemSize);

	Msgsmemcpy(message, &Index_in_X, X_INDEX_BYTE);
	Msgsmemcpy(message, &ctxgp->ComList.Sig_Size_Bytes, sizeof(size_t));
	Msgsmemcpy(message, ctxgp->ComList.XSig, ctxgp->ComList.Sig_Size_Bytes);
	Msgsmemcpy(message, &ctxgp->MemSize, sizeof(uint32_t));
	Msgsmemcpy(message, ctxgp->ComList.X, X_EACH_SIZE_BYTE * ctxgp->MemSize);

	//������Ϣ
#ifdef MSGS
	EPIDMessageSend(message);
#endif
	//printf("----------------------------------------------------------------------\n\n");
}




/* ������Ⱥ��Ա���� */
void EPID_Manager_Exit_Group(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	// �����Ϣ
	if (message->message_len != GROUP_ID_BYTES + SM4_SIZE_BYTE + X_EACH_SIZE_BYTE + X_INDEX_BYTE) {
		printf("No message from member...\n");
		return;
	}

	//��ȡ��Ϣ
	uint8_t* temp = message->message;
	int Groupid = *(message->message);
	temp += GROUP_ID_BYTES;
	PubKey Memberpk;
	PriKey Membersk;
	memcpy(&Membersk, temp, SM4_SIZE_BYTE);
	temp += SM4_SIZE_BYTE;
	memcpy(&Memberpk, temp, X_EACH_SIZE_BYTE);
	temp += X_EACH_SIZE_BYTE;
	uint32_t old_Index = *(uint32_t*)(temp);

	// ��ȡ��ӦȺ����Ϣ
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;

	// �����Ϣ�Ϸ���
	printf("����Ƿ�ΪȺ��Ա...\n");
	uint32_t now_Index = find_in_X(&Memberpk, old_Index, ctxgp->ComList.X, ctxgp->MemSize);

	// �޸�Comlist
	printf("�޸�ComList...\n");
	if (now_Index == -1) {
		printf("�Ǳ�Ⱥ��Ա��\n");
		return;
	}
	else {
		if (now_Index == ctxgp->MemSize - 1) //��������һ����
			memset(ctxgp->ComList.X + now_Index * X_EACH_SIZE_BYTE, 0x00, X_EACH_SIZE_BYTE);
		else {
			memcpy(ctxgp->ComList.X + now_Index * X_EACH_SIZE_BYTE, ctxgp->ComList.X + (ctxgp->MemSize - 1) * X_EACH_SIZE_BYTE, X_EACH_SIZE_BYTE);
			memset(ctxgp->ComList.X + (ctxgp->MemSize - 1) * X_EACH_SIZE_BYTE, 0x00, X_EACH_SIZE_BYTE);
		}
		ctxgp->MemSize--;
	}

	printf("��Xǩ��...\n");
	//��Xǩ��
	size_t signature_len = picnic_signature_size(Picnic2_L1_FS);
	ctxgp->ComList.XSig = (uint8_t*)malloc(signature_len);
	if (ctxgp->ComList.XSig == NULL) {
		printf("failed to allocate signature\n");
		exit(-1);
	}

	int ret = EPID_picnic_sign(&ctxgp->sk, &ctxgp->pk, (const char*)ctxgp->ComList.X, X_EACH_SIZE_BYTE * (size_t)ctxgp->MemSize, ctxgp->ComList.XSig, &signature_len);
	if (ret != 0) {
		printf("picnic_sign failed\n");
		exit(-1);
	}

	/* signature_len has the exact number of bytes used */
	if (signature_len < picnic_signature_size(Picnic2_L1_FS)) {
		uint8_t* newsig = realloc(ctxgp->ComList.XSig, signature_len);
		if (newsig == NULL) {
			printf("failed to re-size signature\n");
			/* Not an error, we can continue with signature */
		}
		else {
			ctxgp->ComList.XSig = newsig;
		}
	}
	ctxgp->ComList.Sig_Size_Bytes = signature_len;
	printf("������Ա�ɹ�\n");
}


int EPID_Verify(PubKey PKgroup, Msgs* message)
{
	if (message->message_len > 0x20)
		return 0;
	else
		return -1;
}