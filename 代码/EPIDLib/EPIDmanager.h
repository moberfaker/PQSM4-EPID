#ifndef EPIDMANAGER_H
#define EPIDMANAGER_H


#include "typeDefine.h"
#include "tools.h"
#include "EPIDMember.h"
#include <picnic.h>
#include <memory.h>
#include <inttypes.h>

/* 管理员ctx */
typedef struct {
	int Groupid;			//管理EPID群组id
	PriKey sk;					//EPID群组私钥
	PubKey pk;					//EPID群组公钥
	uint16_t MemSize;				//EPID群组成员个数
	size_t MaxSizeNow;			//目前初始化个数
	McomList ComList;			//成员承诺列表
}GP_MANAGER_CTX;


/* 群初始化 */
void EPID_Group_Init(GP_MANAGER_CTX* ctx, const unsigned int Parameter, int* IDPool);

/* 成员信息建立预处理和挑战分发 */
void EPID_Group_Join1(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool);

/* 加入群组、ComList签名，分发证书*/
int EPID_Group_Join2(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool);

/* 调试用 */
int EPID_Member_Join_fake(Msgs* message, GP_MANAGER_CTX* ctxgp_Pool);

/* 处理群成员更新cert请求 */
void EPID_Manager_updaet_cert(Msgs* message, GP_MANAGER_CTX* ctx);

/* 处理退群成员请求 */
void EPID_Manager_Exit_Group(Msgs* message, GP_MANAGER_CTX* ctx);

/* 签名验证 */
int EPID_Verify(uint8_t** text, Msgs* message, size_t Member_size, uint8_t* X);

#endif // !EPIDMANAGER_H