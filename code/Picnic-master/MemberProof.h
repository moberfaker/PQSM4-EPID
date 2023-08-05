#ifndef MEMBERPROOF_H
#define MEMBERPROOF_H

#include "picnic_impl.h"
#include <stdint.h>
#include "tree.h"
#define WORD_SIZE_BITS 32

#define MEMBERPROOF_MAX_SIGNATURE_SIZE 100000//最大签名大小Bytes
#define RESUMABLE_FUNC_F_ROUNDS 4	//SM4可恢复轮数
#define SM4_SIZE_BYTE 16
#define CHALLENGE_SIZE_BYTE 16
#define X_SIZE_BYTE (SM4_SIZE_BYTE + CHALLENGE_SIZE_BYTE)
#define REMASK_SZIE_BYTE (16+4) //state + k32

#define RESUMABLE_PART 1
#define ONETIMES_PART 0

typedef tree_t** MemTree_t;

typedef uint8_t** challengelist_t;

typedef struct RemaskTape_t {
    uint8_t** tape;
    size_t MemberSize;
} RemaskTape_t;

//公私钥格式改变
typedef struct {
    uint8_t c[CHALLENGE_SIZE_BYTE]; 	///	挑战
    uint8_t pk[SM4_SIZE_BYTE];			/// 公钥 - > SM4(sk,c)
    uint8_t	sk[SM4_SIZE_BYTE];
}MemKey;

//MemberProof的参数设置
typedef struct Memparamset_t {
    uint32_t numRounds;
    uint32_t numSboxes;
    uint32_t stateSizeBits;         // 128
    uint32_t stateSizeBytes;
    uint32_t stateSizeWords;
    uint32_t andSizeBytes;
    uint32_t numMPCRounds;          // T
    uint32_t numOpenedRounds;       // u
    uint32_t numMPCParties;         // N
    uint32_t seedSizeBytes;
    uint32_t saltSizeBytes;
    uint32_t digestSizeBytes;
    uint32_t tempSizeBits;
    uint32_t tempSizeBytes;
    uint32_t tempSizeWords;
    uint32_t resumeRounds;          //SM4可恢复轮数
    uint32_t ReAndSizeBytes;        //SM4可恢复轮与门数量
    uint32_t oneTimeRounds;         //SM4固定轮轮数
    uint32_t OmAndSizeBytes;        //SM4固定轮与门数量
    uint32_t memberSize;            //成员个数
    transform_t transform;
} Memparamset_t;

//Resumable part
typedef struct ReproofMem_t {
    uint8_t** seedInfo;          // Information required to compute the tree with seeds of of all opened parties
    size_t* seedInfoLen;         // Length of seedInfo buffer
    uint8_t** aux;               // Last party's correction bits; NULL if P[t] == N-1
    uint8_t** maskfix;
    uint8_t** C;                 // Commitment to preprocessing step of unopened party
    uint8_t** msgs;              // Broadcast messages of unopened party P[t]
} ReproofMem_t;

//Onetime part
typedef struct OmproofMem_t {
    uint8_t* seedInfo;          // Information required to compute the tree with seeds of of all opened parties
    size_t seedInfoLen;         // Length of seedInfo buffer
    uint8_t* aux;               // Last party's correction bits; NULL if P[t] == N-1
    uint8_t* C;                 // Commitment to preprocessing step of unopened party
    uint8_t* input;             // Masked input used in online execution
    uint8_t* msgs;              // Broadcast messages of unopened party P[t]
} OmproofMem_t;

typedef struct signatureMem_t {
    uint8_t* salt;
    uint8_t* RemaskRootSeed;    // info required to recompute the random mask for resume part
    uint8_t* iRootSeedInfo;        // Info required to recompute the tree of all initial seeds
    size_t iRootSeedInfoLen;
    uint8_t* cvInfo;            // Info required to check commitments to views (reconstruct Merkle tree)
    size_t cvInfoLen;
    uint16_t* challengeC;
    uint16_t* challengeP;
    uint8_t** Plist;
    uint8_t** inter_mask;
    OmproofMem_t* Omproof;            // 1 proofs for the part which computes z_inter for N re-part
    ReproofMem_t* Reproofs;           // N proofs for each online execution for each member the verifier checks
}signatureMem_t;

void allocateSignatureMem(signatureMem_t* sig, Memparamset_t* params);
void freeSignatureMem(signatureMem_t* sig, Memparamset_t* params);

int serializeSignatureMem(const signatureMem_t* sig, uint8_t* sigBytes, size_t sigBytesLen, Memparamset_t* params);

int Memget_param_set(Memparamset_t* paramset, int MemberSize);
size_t MemberProof_size(int MemberSize);
int MemProof_keygen(Memparamset_t* paremset, MemKey* key);

int MemberProof_sign(Memparamset_t* paramset, MemKey* Key, const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len, uint8_t* Xlist, size_t X_index, int* PreT, int* OnT);
int MemberProof_verify(Memparamset_t* paramset, const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len, uint8_t* Xlist);

int sign_memberpf(Memparamset_t* params, uint32_t* sk, uint32_t* pk, uint32_t* plaintext,
    const uint8_t* message, size_t message_len, signatureMem_t* sig, uint8_t* Xlist, size_t X_index, int* PreT, int* OnT);

#endif // !MEMBERPROOF_H