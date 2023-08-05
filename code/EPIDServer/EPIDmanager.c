#include <stdio.h>
#include <assert.h>
#include "EPIDmanager.h"
#include "typeDefine.h"
#include "tools.h"
#include <picnic.h>
#include "KKWsign.h"

//群管理员ctx初始化
/*
	通过设置群安全参数：64、128、192、256等(默认为128)，生成群公私钥gsk,gpk
*/
void EPID_Group_Init(GP_MANAGER_CTX* ctx, const unsigned int Parameter, int* IDPool)
{
	memset(ctx, 0x00, sizeof(GP_MANAGER_CTX));

	/// 从ID池中取出一个未分配群组ID
	ctx->Groupid = *IDPool;
	*IDPool += 1;
	fprintf(stdout, "\n获取EPID群ID: %d \n", ctx->Groupid);
	fflush(stdout);

	/// 群管理员秘钥生成
	fprintf(stdout, "生成EPID群管理员公私钥... \n");
	fflush(stdout);

	int ret = keygenerator(&ctx->pk, &ctx->sk, 1);
	if (ret != 0) {
		printf("keygen failed\n");
		printf("Group Init failed\n");
		exit(-1);
	}
	printf("Suceess.\n");

	/// 群信息初始化
	fprintf(stdout, "初始化群信息... \n");
	fflush(stdout);

	ctx->MemSize = 0;
	ctx->MaxSizeNow = 10;		// 初始化10个空间
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



/* 成员信息建立和群组加入申请处理 */
// 群管理员处理和发送挑战
void EPID_Group_Join1(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	//提取消息
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);


	//初始化消息
	MsgsInit(message, 16 + X_EACH_SIZE_BYTE + CHALLENGE_SIZE_BYTE);
	size_t temp = JOIN1;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//获取对应群组信息
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;
	printf("接收%s的入群请求\n", Name);



	//获取群组公钥信息
	Msgsmemcpy(message, ctxgp->pk.c, CHALLENGE_SIZE_BYTE);
	Msgsmemcpy(message, ctxgp->pk.pk, SM4_SIZE_BYTE);
	EPIDprintHex("发送群公钥", &ctxgp->pk, X_EACH_SIZE_BYTE);

	//生成挑战
	if (random_bytes(message->message + message->message_len, CHALLENGE_SIZE_BYTE) != 0) {
		PRINT_DEBUG(("Failed to generate challenge\n"));
		PRINT_DEBUG(("MemberJoin init failed\n"));
		exit(-1);
	}
	EPIDprintHex("发送挑战", message->message + message->message_len, CHALLENGE_SIZE_BYTE);
	message->message_len += CHALLENGE_SIZE_BYTE;

	//发送消息
#ifdef MSGS
	EPIDMessageSend(message);
#endif
}



/* 加入群组、ComList签名，分发证书*/
// 群管理员提供Join服务，并更新ComList，返回cert
int EPID_Group_Join2(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	//检查消息长度
	printf("检查成员信息...\n");
	if (message->message_len != NAME_MAX_BYTES + GROUP_ID_BYTES + X_EACH_SIZE_BYTE) {
		printf("No Message from Member yet.\n");
		return -1;
	}


	//提取消息
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);
	PubKey Memberpk;
	memcpy(&Memberpk, message->message + NAME_MAX_BYTES + GROUP_ID_BYTES, X_EACH_SIZE_BYTE);


	//获取对应群组信息
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;
	//printf("\n\n-------------------------  GROUP %d Manager  -------------------------\n", Groupid);


	//printf("Deal with Join Request From  %s\n", Name);

	//提前扩容
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


	//添加公钥承诺
	printf("添加该成员公钥承诺...\n");
	memcpy(ctxgp->ComList.X + X_EACH_SIZE_BYTE * (ctxgp->MemSize - 1), &Memberpk, X_EACH_SIZE_BYTE);//复制公钥

	//对X签名
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
	//初始化消息
	printf("生成证书...\n");
	MsgsInit(message, 16 + X_EACH_SIZE_BYTE + X_INDEX_BYTE + sizeof(signature_len) + signature_len + sizeof(uint32_t) + X_EACH_SIZE_BYTE * ctxgp->MemSize);
	size_t temp = JOIN2;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//发送证书
	printf("发送证书...\n");
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

	//发送消息
#ifdef MSGS
	EPIDMessageSend(message);

#endif
	//printf("----------------------------------------------------------------------\n\n");

	return 1;
}


/* 调试添加成员用 */
int EPID_Member_Join_fake(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	//提取消息
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);
	PubKey Memberpk;
	memcpy(&Memberpk, message->message + NAME_MAX_BYTES + GROUP_ID_BYTES, X_EACH_SIZE_BYTE);


	//获取对应群组信息
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;

	//提前扩容
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

	memcpy(ctxgp->ComList.X + X_EACH_SIZE_BYTE * (ctxgp->MemSize - 1), Memberpk.c, CHALLENGE_SIZE_BYTE);//复制挑战
	memcpy(ctxgp->ComList.X + X_EACH_SIZE_BYTE * (ctxgp->MemSize - 1) + CHALLENGE_SIZE_BYTE, Memberpk.pk, SM4_SIZE_BYTE);//复制公钥

	//对X签名
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


	//初始化消息
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
	//检查消息长度
	printf("检查成员信息...\n");
	if (message->message_len != NAME_MAX_BYTES + GROUP_ID_BYTES + X_EACH_SIZE_BYTE) {
		printf("No Message from Member yet.\n");
		return;
	}


	//提取消息
	char Name[NAME_MAX_BYTES];
	memcpy(Name, message->message, NAME_MAX_BYTES);
	int Groupid = *(message->message + NAME_MAX_BYTES);
	PubKey Memberpk;
	memcpy(&Memberpk, message->message + NAME_MAX_BYTES + GROUP_ID_BYTES, X_EACH_SIZE_BYTE);


	//获取对应群组信息
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;

	//检查是否为群成员
	uint32_t Index_in_X = find_in_X(&Memberpk, 0, ctxgp->ComList.X, ctxgp->MemSize);
	if (Index_in_X == -1) {
		printf("\033[32m Not a Member in Group!\n");
		return;
	}

	//初始化消息
	printf("生成证书...\n");
	MsgsInit(message, 16 + X_INDEX_BYTE + sizeof(ctxgp->ComList.Sig_Size_Bytes) + ctxgp->ComList.Sig_Size_Bytes + sizeof(uint32_t) + X_EACH_SIZE_BYTE * ctxgp->MemSize);
	size_t temp = UPDATE;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//发送证书
	printf("发送证书...\n");
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

	//发送消息
#ifdef MSGS
	EPIDMessageSend(message);
#endif
	//printf("----------------------------------------------------------------------\n\n");
}




/* 处理退群成员请求 */
void EPID_Manager_Exit_Group(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool)
{
	// 检查消息
	if (message->message_len != GROUP_ID_BYTES + SM4_SIZE_BYTE + X_EACH_SIZE_BYTE + X_INDEX_BYTE) {
		printf("No message from member...\n");
		return;
	}

	//提取消息
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

	// 获取对应群组信息
	GP_MANAGER_CTX* ctxgp = ctxgp_Pool + Groupid;

	// 检查消息合法性
	printf("检查是否为群成员...\n");
	uint32_t now_Index = find_in_X(&Memberpk, old_Index, ctxgp->ComList.X, ctxgp->MemSize);

	// 修改Comlist
	printf("修改ComList...\n");
	if (now_Index == -1) {
		printf("非本群成员！\n");
		return;
	}
	else {
		if (now_Index == ctxgp->MemSize - 1) //如果是最后一个人
			memset(ctxgp->ComList.X + now_Index * X_EACH_SIZE_BYTE, 0x00, X_EACH_SIZE_BYTE);
		else {
			memcpy(ctxgp->ComList.X + now_Index * X_EACH_SIZE_BYTE, ctxgp->ComList.X + (ctxgp->MemSize - 1) * X_EACH_SIZE_BYTE, X_EACH_SIZE_BYTE);
			memset(ctxgp->ComList.X + (ctxgp->MemSize - 1) * X_EACH_SIZE_BYTE, 0x00, X_EACH_SIZE_BYTE);
		}
		ctxgp->MemSize--;
	}

	printf("对X签名...\n");
	//对X签名
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
	printf("撤销成员成功\n");
}


int EPID_Verify(PubKey PKgroup, Msgs* message)
{
	if (message->message_len > 0x20)
		return 0;
	else
		return -1;
}