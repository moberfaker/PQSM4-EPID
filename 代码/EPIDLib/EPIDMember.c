#include "EPIDMember.h"
#include "KKWsign.h"
#include <MemberProof.h>

/* 成员初始化 */
void EPID_Member_Join1(GP_MEMBER_CTX* ctx, const char* name, int Join_group, Msgs* message)
{
	printf("\n成员%s信息初始化 ...\n", name);

	if (ctx == NULL) {
		printf("Member ctx is NULL\n");
		exit(-1);
	}

	//初始化
	memset(ctx, 0x00, sizeof(GP_MEMBER_CTX));
	if (message->message == NULL)
		free(message->message);
	MsgsInit(message, 16 + NAME_MAX_BYTES + sizeof(Join_group));
	//设置报文头
	size_t temp = JOIN1;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;
	//检查信息长度
	if (strlen(name) > NAME_MAX_BYTES) {
		printf("Setup name is Lager than %d letter", NAME_MAX_BYTES - 2);
		exit(-1);
	}
	memcpy(ctx->name, name, strlen(name) + 1);
	Msgsmemcpy(message, ctx->name, NAME_MAX_BYTES);
	//申请加群
	ctx->Groupid = Join_group;
	Msgsmemcpy(message, &Join_group, sizeof(Join_group));
	//发送消息
	printf("发送成员信息加入群组%d(%d Bytes)\n", ctx->Groupid, GROUP_ID_BYTES);

	memcpy(message->message + 8, &message->message_len, sizeof(size_t));
#ifdef MSGS
	EPIDMessageSend(message);
#endif 
}



/* 成员回应挑战并生成公私钥 */
void EPID_Member_Join2(Msgs* message, GP_MEMBER_CTX* ctx)
{
	/// 检查消息长度
	if (message->message_len != X_EACH_SIZE_BYTE + CHALLENGE_SIZE_BYTE) {
		printf("No Message from Manager yet.\n");
		return;
	}
	/// 提取群组挑战，群组公钥、Join挑战
	printf("获取群组公钥...\n");
	printf("接收群组挑战...\n");
	memcpy(&ctx->Group_pk, message->message, X_EACH_SIZE_BYTE);
	memcpy(ctx->pk.c, message->message + X_EACH_SIZE_BYTE, CHALLENGE_SIZE_BYTE);
	/// 初始化消息
	MsgsInit(message, 16 + NAME_MAX_BYTES + GROUP_ID_BYTES + X_EACH_SIZE_BYTE);
	/// 设置报文头任务段
	size_t temp = JOIN2;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;
	/// 回应挑战并生成相应公私钥
	fprintf(stdout, "基于挑战生成成员公钥... \n");
	fflush(stdout);
	int ret = keygenerator(&ctx->pk, &ctx->sk, 0);
	if (ret != 0) {
		printf("keygen failed\n");
		printf("Group Init failed\n");
		exit(-1);
	}
	printf("Suceess.\n");
	/// 发送成员啊信息和公钥
	printf("发送成员信息(%d Bytes)\n", NAME_MAX_BYTES + GROUP_ID_BYTES);
	EPIDprintHex("发送成员公钥（基于给定挑战）", &ctx->pk, X_EACH_SIZE_BYTE);
	Msgsmemcpy(message, ctx->name, NAME_MAX_BYTES);
	Msgsmemcpy(message, &ctx->Groupid, GROUP_ID_BYTES);
	Msgsmemcpy(message, &ctx->pk, X_EACH_SIZE_BYTE);


	/// 发送消息
#ifdef MSGS
	EPIDMessageSend(message);
#endif // MSGS
}



/* 群成员接收Cert，结束Join */
void EPID_Member_Join_finish(Msgs* message, GP_MEMBER_CTX* ctx)
{
	//printf("\n\n-------------------------     Member %s     -------------------------\n", ctx->name);

	// 检查消息
	//printf("Check the Message...\n");
	PubKey publicKey;
	memcpy(&publicKey, message->message, X_EACH_SIZE_BYTE);
	if (memcmp(&publicKey, &ctx->pk, X_EACH_SIZE_BYTE) != 0) {
		printf("Not a Cert for Member %s\n", ctx->name);
		return;
	}
	printf("Success.\n");


	// 提取Cert信息(pk,index_in_X,X)
	printf("提取cert信息...\n");
	uint8_t* temp = message->message + X_EACH_SIZE_BYTE;
	memcpy(&ctx->Cert.pk, &publicKey, X_EACH_SIZE_BYTE);	// pk

	memcpy(&ctx->Cert.Index_in_X, temp, sizeof(uint32_t));	// index_in_X
	temp += sizeof(uint32_t);

	memcpy(&ctx->Cert.ComList.Sig_Size_Bytes, temp, sizeof(size_t));// sigX
	temp += sizeof(size_t);

	if (ctx->Cert.ComList.XSig != NULL && ctx->Cert.ComList.XSig != 0xCCCCCCCCCCCCCCCC)
		free(ctx->Cert.ComList.XSig);
	ctx->Cert.ComList.XSig = malloc(ctx->Cert.ComList.Sig_Size_Bytes);
	if (ctx->Cert.ComList.XSig == NULL) {
		printf("XSig Malloc failed\n");
		exit(-1);
	}
	memcpy(ctx->Cert.ComList.XSig, temp, ctx->Cert.ComList.Sig_Size_Bytes);
	temp += ctx->Cert.ComList.Sig_Size_Bytes;

	uint32_t Xlen;				// X
	Xlen = *(uint32_t*)temp;

	ctx->MemSize = Xlen;
	temp += sizeof(uint32_t);	if (ctx->Cert.ComList.X != NULL && ctx->Cert.ComList.X != 0xCCCCCCCCCCCCCCCC)
		free(ctx->Cert.ComList.X);
	ctx->Cert.ComList.X = malloc(Xlen * X_EACH_SIZE_BYTE);
	if (ctx->Cert.ComList.X == NULL) {
		printf("X Malloc failed\n");
		exit(-1);
	}
	memcpy(ctx->Cert.ComList.X, temp, Xlen * X_EACH_SIZE_BYTE);


	// 检查签名Xsig
	printf("检查Xsig签名...\n");
	int ret = EPID_picnic_verify(&ctx->Group_pk, ctx->Cert.ComList.X, Xlen * X_EACH_SIZE_BYTE, ctx->Cert.ComList.XSig, ctx->Cert.ComList.Sig_Size_Bytes);
	if (ret != 0) {
		printf("picnic_verify failed\n");
		exit(-1);
	}
	printf("Success.\n");


	//printf("----------------------------------------------------------------------\n\n");
}



/* 群成员请求新cert */
void EPID_Member_update_cert_call(Msgs* message, GP_MEMBER_CTX* ctx)
{
	printf("======请求新cert进行更新=======\n");
	MsgsInit(message, 16 + NAME_MAX_BYTES + GROUP_ID_BYTES + X_EACH_SIZE_BYTE);
	size_t temp = UPDATE;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	/// 发送名称和公钥
	printf("发送成员信息(%d Bytes)\n", NAME_MAX_BYTES + GROUP_ID_BYTES);
	EPIDprintHex("发送成员公钥", &ctx->pk, X_EACH_SIZE_BYTE);
	Msgsmemcpy(message, ctx->name, NAME_MAX_BYTES);
	Msgsmemcpy(message, &ctx->Groupid, GROUP_ID_BYTES);
	Msgsmemcpy(message, &ctx->pk, X_EACH_SIZE_BYTE);

	/// 发送消息
#ifdef MSGS
	EPIDMessageSend(message);
#endif // MSGS
}



/* 群成员更新Cert */
int EPID_Member_update_cert(Msgs* message, GP_MEMBER_CTX* ctx)
{

	// 检查消息长度
	if (message->message_len == 0) {
		printf("No X in\n");
		printf("Update cert failed\n");
		return -1;
	}

	// 提取信息
	uint8_t* temp = message->message;
	memcpy(&ctx->Cert.Index_in_X, temp, X_INDEX_BYTE);						//索引
	temp += X_INDEX_BYTE;
	memcpy(&ctx->Cert.ComList.Sig_Size_Bytes, temp, sizeof(size_t));	//签名大小
	temp += sizeof(size_t);

	if (ctx->Cert.ComList.XSig != NULL && ctx->Cert.ComList.XSig != 0xCCCCCCCCCCCCCCCC)
		free(ctx->Cert.ComList.XSig);
	ctx->Cert.ComList.XSig = malloc(ctx->Cert.ComList.Sig_Size_Bytes);
	if (ctx->Cert.ComList.XSig == NULL) {
		printf("Cert malloc failed\n");
		return -1;
	}
	memcpy(ctx->Cert.ComList.XSig, temp, ctx->Cert.ComList.Sig_Size_Bytes);//提取签名
	temp += ctx->Cert.ComList.Sig_Size_Bytes;

	uint32_t X_Size;														//提取X大小
	memcpy(&X_Size, temp, sizeof(uint32_t));
	temp += sizeof(uint32_t);
	ctx->MemSize = X_Size;

	if (ctx->Cert.ComList.X != NULL && ctx->Cert.ComList.X != 0xCCCCCCCCCCCCCCCC)
		free(ctx->Cert.ComList.X);											//提取X
	ctx->Cert.ComList.X = malloc(X_Size * X_EACH_SIZE_BYTE);
	if (ctx->Cert.ComList.X == NULL) {
		printf("Cert malloc failed\n");
		return -1;
	}
	memcpy(ctx->Cert.ComList.X, temp, X_Size * X_EACH_SIZE_BYTE);
	return 1;
}



void EPID_Member_Exit_Group(Msgs* message, GP_MEMBER_CTX* ctx)
{
	//printf("\n\n\033[33m-------------------------     Member %s     -------------------------\n", ctx->name);
	printf("退出群组 %d\n", ctx->Groupid);
	printf("发送公私钥\n");
	printf("发送X索引\n");

	//初始化消息
	MsgsInit(message, 16 + GROUP_ID_BYTES + SM4_SIZE_BYTE + X_EACH_SIZE_BYTE + X_INDEX_BYTE);
	size_t temp = REVOKEKEY;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	Msgsmemcpy(message, &ctx->Groupid, GROUP_ID_BYTES);
	Msgsmemcpy(message, ctx->sk.sk, SM4_SIZE_BYTE);
	Msgsmemcpy(message, &ctx->pk, X_EACH_SIZE_BYTE);
	Msgsmemcpy(message, &ctx->Cert.Index_in_X, X_INDEX_BYTE);

	printf("清空数据\n");
	free(ctx->Cert.ComList.X);
	free(ctx->Cert.ComList.XSig);
	memset(ctx, 0x00, sizeof(ctx));
	/// 发送消息
#ifdef MSGS
	EPIDMessageSend(message);
#endif // MSGS
}

int EPID_Sign(GP_MEMBER_CTX* ctx, Msgs* message, size_t Member_size, int* PreT, int* OnT)
{
	printf("发送%lluBytes消息\n", message->message_len);

	//提取信息
	uint8_t* text = (uint8_t*)malloc(message->message_len);
	memcpy(text, message->message, message->message_len);
	size_t text_len = message->message_len;

	size_t signature_len;
	uint8_t* signature = EPID_MemberProof_sign(&ctx->sk, &ctx->pk, &signature_len, text, text_len, Member_size, ctx->Cert.ComList.X, ctx->Cert.Index_in_X, PreT, OnT);
	if (signature_len == 0) {
		return -1;
	}

	//设置报文头
	MsgsInit(message, 16 + 2 * sizeof(size_t) + text_len + signature_len);
	size_t temp = SIGN;
	memcpy(message->message, &temp, 8);
	message->message_len = 16;

	//发送信息
	Msgsmemcpy(message, &text_len, sizeof(size_t));
	Msgsmemcpy(message, text, text_len);
	Msgsmemcpy(message, &signature_len, sizeof(size_t));
	Msgsmemcpy(message, signature, signature_len);
	free(text);
	free(signature);
#ifdef MSGS
	//EPIDMessageSend(message);
#endif // MSGS

	return signature_len;
}