#include "MemberProof.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "picnic.h"
#include "picnic_impl.h"
#include "hash.h"
#include "tree.h"
#include "picnic_types.h"
#include <assert.h>
#include <omp.h>
#define _CRTDBG_MAP_ALLOC
#include<stdlib.h>
#include<crtdbg.h>
#include <time.h>


#pragma warning(disable:6386)
#pragma warning(disable:6385)
#pragma warning(disable:6011)

#define MIN(a,b)            (((a) < (b)) ? (a) : (b))
#define RE_SM4_MAX_AND_GATES (64*4*4)	
#define OM_SM4_MAX_AND_GATES (64*4*28)	
#define SM4_KEY_BITS 128
#define PK_BYTES 16
#define X_BYTES 32
#define RE_MAX_AUX_BYTES ((RE_SM4_MAX_AND_GATES + SM4_KEY_BITS) / 8 + 1)
#define OM_MAX_AUX_BYTES ((OM_SM4_MAX_AND_GATES + SM4_KEY_BITS) / 8 + 1)
#define NOCHALLENGE 0xff
//from picnic.c
int Memget_param_set(Memparamset_t* paramset, int MemberSize)
{
    uint32_t pqSecurityLevel;
    pqSecurityLevel = 64;
    paramset->numRounds = 32;           // 32
    paramset->numSboxes = 4;            // 4
    paramset->stateSizeBytes = 16;
    paramset->stateSizeBits = paramset->stateSizeBytes * 8;
    paramset->stateSizeWords = paramset->stateSizeBits / WORD_SIZE_BITS;
    paramset->numMPCRounds = 343;
    paramset->numOpenedRounds = 27;
    paramset->numMPCParties = 64;
    paramset->seedSizeBytes = numBytes(2 * pqSecurityLevel);
    paramset->saltSizeBytes = 32; /* same for all parameter sets */
    paramset->digestSizeBytes = 32;
    paramset->tempSizeBits = 32;
    paramset->tempSizeBytes = 8;
    paramset->tempSizeWords = paramset->tempSizeBits / WORD_SIZE_BITS;
    paramset->transform = TRANSFORM_FS;
    paramset->andSizeBytes = numBytes(paramset->numSboxes * 64 * paramset->numRounds);
    paramset->resumeRounds = 4;
    paramset->ReAndSizeBytes = numBytes(paramset->numSboxes * 64 * paramset->resumeRounds); // *32 <- KeyGen Rounds has been included in OnetimeRound
    paramset->oneTimeRounds = 28;           // keyGen Rounds = 32
    paramset->OmAndSizeBytes = numBytes(paramset->numSboxes * 64 * paramset->oneTimeRounds);   // 28 Rounds Enc + 32 Rounds KeyGen
    paramset->memberSize = MemberSize;
    return EXIT_SUCCESS;
}

size_t MemberProof_size(int MemberSize)
{
    Memparamset_t paramset;
    int ret = Memget_param_set(&paramset, MemberSize);

    if (ret != EXIT_SUCCESS) {
        return MemberSize * MEMBERPROOF_MAX_SIGNATURE_SIZE;
    }

    /* parameter sets */
    size_t N = paramset.memberSize;
    size_t u = paramset.numOpenedRounds;
    size_t T = paramset.numMPCRounds;
    size_t numTreeValues = u * ceil_log2((T + (u - 1)) / u);                        // u*ceil(log2(ceil(T/u)))

    size_t OmproofSize = paramset.seedSizeBytes * (ceil_log2(paramset.numMPCParties) + 1) // Info to recompute seeds(and 1 more seed for N's resume part mask )
        + paramset.OmAndSizeBytes                                       // msgs -> [s] of unopened party  no output_masks
        + paramset.digestSizeBytes                                      // size of commitment of unopened party
        + paramset.stateSizeBytes * 2                                   // masked input
        + paramset.OmAndSizeBytes;                                      // aux

    size_t ReproofSize = paramset.seedSizeBytes * ceil_log2(paramset.numMPCParties) // Info to recompute seeds
        + paramset.ReAndSizeBytes + paramset.stateSizeBytes             // msgs -> [s] of unopened party + output_masks
        + paramset.digestSizeBytes                                      // size of commitment of unopened party
        + paramset.ReAndSizeBytes                                       // aux
        + paramset.stateSizeBytes * 2;                                  // maskfix   

    size_t signatureSize = paramset.digestSizeBytes                     // h*
        + paramset.saltSizeBytes + paramset.seedSizeBytes               // salt and seed_<>
        + numTreeValues * paramset.seedSizeBytes * paramset.memberSize  // Seed*j (not challenge)
        + numTreeValues * paramset.digestSizeBytes * paramset.memberSize// h'j (not challenge)
        + sizeof(uint16_t) * u                                          // challengeC
        + sizeof(uint16_t) * u * paramset.memberSize                    // u N-sizelists challengeP
        + ReproofSize * u * paramset.memberSize                         // proof for each (resumable part)
        + OmproofSize * u;                                              // proof (onetimes part)

    return signatureSize;
}

int MemProof_keygen(Memparamset_t* paramset, MemKey* key)
{
    memset(key, 0x00, sizeof(MemKey));

    /* Generate a private key */
    if (random_bytes_default(key->sk, paramset->stateSizeBytes) != 0) {
        printf("Failed to generate private key\n");
        return -1;
    }
    /* Generate a random plaintext block */
    if (random_bytes_default(key->c, paramset->stateSizeBytes) != 0) {
        printf("Failed to generate private key\n");
        return -1;
    }

    //memset(key->sk, 0x61, paramset->stateSizeBytes);
    //memset(key->c, 0x61, paramset->stateSizeBytes);

    /* Compute the ciphertext */
    SM4Enc((uint32_t*)key->c, (uint32_t*)key->pk, (uint32_t*)key->sk);
    return 0;
}

static uint8_t** allocateInterMask(Memparamset_t* params) {

    uint8_t* slab = malloc(params->numMPCRounds * (params->stateSizeBytes * 2 + sizeof(uint8_t*)));

    uint8_t** InterMask = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*);

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        InterMask[i] = (uint8_t*)slab;
        slab += params->stateSizeBytes * 2;
    }
    return InterMask;
}

void allocateSignatureMem(signatureMem_t* sig, Memparamset_t* params)
{
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
    sig->RemaskRootSeed = (uint8_t*)malloc(params->seedSizeBytes);
    sig->iRootSeedInfo = NULL;
    sig->iRootSeedInfoLen = 0;
    sig->cvInfo = NULL;       // Sign/verify code sets it
    sig->cvInfoLen = 0;
    sig->challengeC = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeP = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->Plist = NULL;
    sig->Omproof = calloc(params->numMPCRounds, sizeof(OmproofMem_t));
    sig->Reproofs = calloc(params->numMPCRounds, sizeof(ReproofMem_t));
}

static challengelist_t* allocateChallengePlist(Memparamset_t* params) {

    uint8_t* slab = calloc(1, params->numMPCRounds * (params->memberSize * sizeof(uint8_t) + sizeof(uint8_t*)));

    challengelist_t* list = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*);

    random_bytes_default(slab, params->numMPCRounds * params->memberSize * sizeof(uint8_t));//随机数，取一字节的后6bit (&0x3f)

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        list[i] = (uint8_t*)slab;
        slab += params->memberSize * sizeof(uint8_t);
        for (uint32_t j = 0; j < params->memberSize * sizeof(uint8_t); j++) {
            ((uint8_t*)list[i])[j] &= 0x3f;//3f
        }
    }
    return list;
}

static uint8_t** allocatePlist(Memparamset_t* params) {

    uint8_t* slab = calloc(1, params->numOpenedRounds * (params->memberSize * sizeof(uint8_t) + sizeof(uint8_t*)));

    challengelist_t* list = (uint8_t**)slab;

    slab += params->numOpenedRounds * sizeof(uint8_t*);

    for (uint32_t i = 0; i < params->numOpenedRounds; i++) {
        list[i] = (uint8_t*)slab;
        slab += params->memberSize * sizeof(uint8_t);
    }
    return list;
}

static void allocateOmProof(OmproofMem_t* proof, Memparamset_t* params) {
    memset(proof, 0, sizeof(OmproofMem_t));

    proof->seedInfo = NULL;     // Sign/verify code sets it
    proof->seedInfoLen = 0;
    proof->aux = malloc(params->OmAndSizeBytes);
    proof->C = malloc(params->digestSizeBytes);
    proof->input = malloc(params->stateSizeBytes * 2);
    proof->msgs = malloc(params->OmAndSizeBytes);
}

static void allocateReProof(ReproofMem_t* proof, Memparamset_t* params) {
    memset(proof, 0, sizeof(ReproofMem_t));

    proof->seedInfo = calloc(1, params->memberSize * sizeof(uint8_t*));     // Sign/verify code sets it
    proof->seedInfoLen = calloc(1, params->memberSize * sizeof(size_t));

    uint8_t* slab;

    slab = calloc(1, params->memberSize * (params->digestSizeBytes + sizeof(uint8_t*)));
    proof->C = (uint8_t**)slab;
    slab += params->memberSize * sizeof(uint8_t*);
    for (size_t N = 0; N < params->memberSize; N++) {
        proof->C[N] = (uint8_t*)slab;
        slab += params->digestSizeBytes;
    }

    slab = calloc(1, params->memberSize * (params->ReAndSizeBytes + sizeof(uint8_t*)));
    proof->aux = (uint8_t**)slab;
    slab += params->memberSize * sizeof(uint8_t*);
    for (size_t N = 0; N < params->memberSize; N++) {
        proof->aux[N] = (uint8_t*)slab;
        slab += params->ReAndSizeBytes;
    }

    slab = calloc(1, params->memberSize * (params->stateSizeBytes * 2 + sizeof(uint8_t*)));
    proof->maskfix = (uint8_t**)slab;
    slab += params->memberSize * sizeof(uint8_t*);
    for (size_t N = 0; N < params->memberSize; N++) {
        proof->maskfix[N] = (uint8_t*)slab;
        slab += params->stateSizeBytes * 2;
    }

    slab = calloc(1, params->memberSize * (params->ReAndSizeBytes + params->stateSizeBytes + sizeof(uint8_t*)));
    proof->msgs = (uint8_t**)slab;
    slab += params->memberSize * sizeof(uint8_t*);
    for (size_t N = 0; N < params->memberSize; N++) {
        proof->msgs[N] = (uint8_t*)slab;
        slab += params->ReAndSizeBytes + params->stateSizeBytes;
    }
}

static void freeOmProof(OmproofMem_t* proof, Memparamset_t* params) {
    free(proof->seedInfo);
    free(proof->C);
    free(proof->input);
    free(proof->aux);
    free(proof->msgs);
}

static void freeReProof(ReproofMem_t* proof, Memparamset_t* params) {
    if (proof->seedInfo != NULL) {
        for (size_t N = 0; N < params->memberSize; N++) {
            free(proof->seedInfo[N]);
        }
        free(proof->seedInfo);
    }
    free(proof->seedInfoLen);
    free(proof->C);
    free(proof->aux);
    free(proof->maskfix);
    free(proof->msgs);
}

void freeSignatureMem(signatureMem_t* sig, Memparamset_t* params)
{
    free(sig->salt);
    free(sig->RemaskRootSeed);
    free(sig->iRootSeedInfo);
    free(sig->cvInfo);
    free(sig->challengeC);
    free(sig->challengeP);
    free(sig->Plist);
#pragma omp parallel
    {
        int i;
#pragma omp for schedule(guided)
        for (i = 0; i < params->numMPCRounds; i++) {
            freeOmProof(&sig->Omproof[i], params);
            freeReProof(&sig->Reproofs[i], params);
        }
    }
    free(sig->Omproof);
    free(sig->Reproofs);
}



static commitments_t* allocateCommitmentsMem(Memparamset_t* params, size_t numCommitments)
{
    commitments_t* commitments = malloc(params->numMPCRounds * sizeof(commitments_t));

    commitments->nCommitments = (numCommitments) ? numCommitments : params->numMPCParties;

    uint8_t* slab = malloc(params->numMPCRounds * (commitments->nCommitments * params->digestSizeBytes +
        commitments->nCommitments * sizeof(uint8_t*)));

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        commitments[i].hashes = (uint8_t**)slab;
        slab += commitments->nCommitments * sizeof(uint8_t*);

        for (uint32_t j = 0; j < commitments->nCommitments; j++) {
            commitments[i].hashes[j] = slab;
            slab += params->digestSizeBytes;
        }
    }
    return commitments;
}

static void allocateCommitments2Mem(commitments_t* commitments, Memparamset_t* params, size_t numCommitments)
{
    commitments->nCommitments = numCommitments;

    uint8_t* slab = malloc(numCommitments * params->digestSizeBytes + numCommitments * sizeof(uint8_t*));

    commitments->hashes = (uint8_t**)slab;
    slab += numCommitments * sizeof(uint8_t*);

    for (size_t i = 0; i < numCommitments; i++) {
        commitments->hashes[i] = slab;
        slab += params->digestSizeBytes;
    }
}

static void commitMem(uint8_t* digest, uint8_t* seed, uint8_t* aux, uint8_t* salt, size_t t, size_t j, Memparamset_t* params,size_t ReorOm)
{
    /* Compute C[t][j];  as digest = H(seed||[aux]) aux is optional —————— Com承诺  */
    HashInstance ctx;

    HashInitMem(&ctx, HASH_PREFIX_NONE);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    if (aux != NULL) {
        size_t tapeLenBytes = (ReorOm) ? (params->ReAndSizeBytes) : (params->OmAndSizeBytes);
        HashUpdate(&ctx, aux, tapeLenBytes);
    }
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, t);       // HashUpdateIntLE：HashUpdate(ctx, (uint_8*)&toLittleEndian(t), sizeof(uint16_t))???
    HashUpdateIntLE(&ctx, j);       // HashUpdateIntLE：HashUpdate(ctx, (uint_8*)&toLittleEndian(j), sizeof(uint16_t))???
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);         // digest = hash(seed || aux || salt || t || j)
}

static void getAuxBitsMem(uint8_t* output, randomTape_t* tapes, Memparamset_t* params, int ReorOm)    // 由名称：获取Aux
{
    // size_t，即 unsigned int
    size_t firstAuxIndex = params->stateSizeBits * 2 + 1;
    size_t last = params->numMPCParties - 1;
    size_t pos = 0;
    size_t andSizeByte = (ReorOm) ? (params->ReAndSizeBytes) : (params->OmAndSizeBytes);
    size_t numRounds = (ReorOm) ? (params->resumeRounds) : (params->oneTimeRounds);

    memset(output, 0, andSizeByte);        // 将output指向的字符串，的前andSizeBytes个字符，设为0
    size_t andSizeBits = 64 * numRounds * params->numSboxes;     // andSizeBits = 3 * 轮数(r) * S盒数(m)，LowMC参数
    for (size_t i = 0; i < andSizeBits * 2; i += 2) {
        uint8_t auxBit = getBit(tapes->tape[last], firstAuxIndex + i);  // auxBit = tape[last][firstAuxIndex + i]???
        setBit(output, pos, auxBit);                                    // output[pos] = auxBit
        pos++;                                                          // pos++
    }
}

static void setAuxBitsMem(randomTape_t* tapes, uint8_t* input, Memparamset_t* params, size_t ReorOm)     // 由名称：设置Aux
{
    size_t firstAuxIndex = params->stateSizeBits * 2 + 1;
    size_t last = params->numMPCParties - 1;
    size_t pos = 0;
    size_t andSizeByte = (ReorOm) ? (params->ReAndSizeBytes) : (params->OmAndSizeBytes);

    for (size_t i = 0; i < andSizeByte * 2 * 8; i += 2) {
        uint8_t auxBit = getBit(input, pos);
        setBit(tapes->tape[last], firstAuxIndex + i, auxBit);
        pos++;
    }
}

static void getMaskfix(uint8_t* output, randomTape_t* tapes, Memparamset_t* params) 
{
    size_t last = params->numMPCParties - 1;
    size_t pos = 0;
    memset(output, 0, params->stateSizeBytes * 2);

    for (size_t i = 0; i < params->stateSizeBits * 2; i++) {
        uint8_t fixBit = getBit(tapes->tape[last], i);
        setBit(output, pos, fixBit);
        pos++;
    }
}

static void setMaskfix(randomTape_t* tapes, uint8_t* input, Memparamset_t* params)
{
    size_t last = params->numMPCParties - 1;
    size_t pos = 0;

    for (size_t i = 0; i < params->stateSizeBits * 2; i++) {
        uint8_t fixBit = getBit(input, pos);
        setBit(tapes->tape[last], i, fixBit);
        pos++;
    }
}


static void computeSaltAndSeed(uint8_t* saltAndSeed, size_t saltAndSeedLength, uint32_t* privateKey, uint32_t* pubKey,
    uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, const uint8_t* Xlist, Memparamset_t* params)
{
    HashInstance ctx;

    HashInitMem(&ctx, HASH_PREFIX_NONE);
    HashUpdate(&ctx, (uint8_t*)privateKey, params->stateSizeBytes);
    HashUpdate(&ctx, message, messageByteLength);
    HashUpdate(&ctx, Xlist, params->memberSize * X_SIZE_BYTE);
    HashUpdate(&ctx, (uint8_t*)pubKey, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);
    HashUpdateIntLE(&ctx, params->stateSizeBits);
    HashFinal(&ctx);
    HashSqueeze(&ctx, saltAndSeed, saltAndSeedLength);
}

static randomTape_t** allocateTape_Pointer(Memparamset_t* params) {

    uint8_t* slab = calloc(1, params->numMPCRounds * ((params->memberSize + 1) * sizeof(randomTape_t) + sizeof(randomTape_t*)));

    randomTape_t** tapes = (randomTape_t**)slab;

    slab += params->numMPCRounds * sizeof(randomTape_t*);

    for (size_t t = 0; t < params->numMPCRounds; t++) {
        tapes[t] = (randomTape_t*)slab;
        slab += (params->memberSize + 1) * sizeof(randomTape_t);
    }
    return tapes;
}

static void allocateRandomTapeMem(randomTape_t* tape, Memparamset_t* params, int REorOm)
{
    tape->nTapes = params->numMPCParties;
    tape->tape = malloc(tape->nTapes * sizeof(uint8_t*));
    size_t tapeSizeBytes = (REorOm) ? (2 * params->ReAndSizeBytes + params->stateSizeBytes * 2) : (2 * params->OmAndSizeBytes + params->stateSizeBytes * 2);

    uint8_t* slab = calloc(1, tape->nTapes * tapeSizeBytes);
    for (uint8_t i = 0; i < tape->nTapes; i++) {
        tape->tape[i] = slab;
        slab += tapeSizeBytes;
    }
    tape->pos = 0;
}

static void allocateRandomRemaskTapeMem(RemaskTape_t* tape, Memparamset_t* params)
{
    size_t Count = params->memberSize + 1;
    size_t tapeSizeBytes = params->stateSizeBytes * 2;

    uint8_t* slab = calloc(1, Count * (tapeSizeBytes+ sizeof(uint8_t*)));

    tape->tape = (uint8_t**)slab;
    slab += Count * sizeof(uint8_t*);

    for (uint8_t i = 0; i < Count; i++) {
        tape->tape[i] = slab;
        slab += tapeSizeBytes;
    }
}

static inputs_t allocateInputsMem(Memparamset_t* params)
{
    uint8_t* slab = calloc(1, params->numMPCRounds * (params->stateSizeBytes * 2 + sizeof(uint8_t*)));

    inputs_t inputs = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*);

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        inputs[i] = (uint8_t*)slab;
        slab += params->stateSizeBytes * 2;
    }

    return inputs;
}

static Zinter_t allocateZinter(Memparamset_t* params) {
    uint8_t* slab = calloc(1, params->numMPCRounds * (params->stateSizeBytes * 2 + sizeof(uint8_t*)));

    Zinter_t Zinter = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*);

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        Zinter[i] = (uint8_t*)slab;
        slab += params->stateSizeBytes * 2;
    }

    return Zinter;
}

static MemTree_t* allocateMemTree(Memparamset_t* params) {
    uint8_t* slab = calloc(1, params->numMPCRounds * ((params->memberSize + 1) * sizeof(tree_t*) + sizeof(MemTree_t)));
    
    MemTree_t* temp = (MemTree_t*)slab;

    slab += params->numMPCRounds * sizeof(MemTree_t);

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        temp[i] = (tree_t**)slab;
        slab += (params->memberSize + 1) * sizeof(tree_t*);
    }
    return temp;
}

msgs_t* allocateMsgsMem(Memparamset_t* params,int ReorOm)
{
    size_t Msgs_Size;
    if (ReorOm == 0) {//one time part
        Msgs_Size = params->OmAndSizeBytes;
    }
    else {
        Msgs_Size = params->ReAndSizeBytes + params->stateSizeBytes;
    }

    msgs_t* msgs = malloc(params->numMPCRounds * sizeof(msgs_t));

    uint8_t* slab = calloc(1, params->numMPCRounds * (params->numMPCParties * Msgs_Size +
        params->numMPCParties * sizeof(uint8_t*)));

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        msgs[i].pos = 0;
        msgs[i].unopened = -1;
        msgs[i].msgs = (uint8_t**)slab;
        slab += params->numMPCParties * sizeof(uint8_t*);

        for (uint32_t j = 0; j < params->numMPCParties; j++) {
            msgs[i].msgs[j] = slab;
            slab += Msgs_Size;
        }
    }
    return msgs;
}

static void reconstructShares(uint32_t* output, shares_t* shares)   // 猜测：用于重构第n方的share值???
{
    for (size_t i = 0; i < shares->numWords; i++) {
        setBitInWordArray(output, i, parity64(shares->shares[i]));  // output[i] = parity64(shares->shares[i])，i∈[shares->numWords]
    }
}

static void createRandomTapesMem(randomTape_t* tapes, uint8_t** seeds, uint8_t* salt, size_t t, Memparamset_t* params,int REorOm)    // 生成随机数
{
    HashInstance ctx;                                                               // 上下文
    size_t tapeSizeBytes = (REorOm) ? (2 * params->ReAndSizeBytes + params->stateSizeBytes * 2) : (2 * params->OmAndSizeBytes + params->stateSizeBytes * 2);

    allocateRandomTapeMem(tapes, params, REorOm);
    
    for (size_t i = 0; i < params->numMPCParties; i++) {                            // 哈希主seed, salt, t, i得到tape[i]
        HashInitMem(&ctx, HASH_PREFIX_NONE);
        HashUpdate(&ctx, seeds[i], params->seedSizeBytes);
        HashUpdate(&ctx, salt, params->saltSizeBytes);
        HashUpdateIntLE(&ctx, t);                                                   // 
        HashUpdateIntLE(&ctx, i);
        HashFinal(&ctx);

        HashSqueeze(&ctx, tapes->tape[i], tapeSizeBytes);
    }
}

static void createRandomRemaskTapesMem(RemaskTape_t* tapes, uint8_t** seeds, uint8_t* salt, size_t t, Memparamset_t* params)    // 生成随机数
{
    HashInstance ctx;                                                               // 上下文
    size_t tapeSizeBytes = params->stateSizeBytes * 2;  //明文 + 秘钥

    allocateRandomRemaskTapeMem(tapes, params);

    for (size_t i = 0; i < params->memberSize; i++) {                            // 哈希主seed, salt, t, i得到tape[i]
        HashInitMem(&ctx, HASH_PREFIX_NONE);
        HashUpdate(&ctx, seeds[i], params->seedSizeBytes);
        HashUpdate(&ctx, salt, params->saltSizeBytes);
        HashUpdateIntLE(&ctx, t);                                                   // 
        HashUpdateIntLE(&ctx, i);
        HashFinal(&ctx);

        HashSqueeze(&ctx, tapes->tape[i], tapeSizeBytes);
    }
}

static void hashSeedMem(uint8_t* digest, const uint8_t* inputSeed, uint8_t* salt, uint8_t hashPrefix, size_t repIndex, size_t nodeIndex, Memparamset_t* params)
{
    HashInstance ctx;

    HashInitMem(&ctx, hashPrefix);
    HashUpdate(&ctx, inputSeed, params->seedSizeBytes);
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, (uint16_t)repIndex);
    HashUpdateIntLE(&ctx, (uint16_t)nodeIndex);
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, 2 * params->seedSizeBytes);       // digest = H(inputSeed || salt || repIndex || nodeIndex)
}

static int exists(tree_t* tree, size_t i)
{
    if (i >= tree->numNodes) {
        return 0;
    }
    if (tree->exists[i]) {
        return 1;
    }
    return 0;
}

static void expandSeedsMem(tree_t* tree, uint8_t* salt, size_t repIndex, Memparamset_t* params)
{
    uint8_t tmp[2 * MAX_SEED_SIZE_BYTES];

    /* Walk the tree, expanding seeds where possible. Compute children of
     * non-leaf nodes. */
    size_t lastNonLeaf = getParent(tree->numNodes - 1);         // 最后一个非叶结点

    for (size_t i = 0; i <= lastNonLeaf; i++) {                 // 拓展所有已知的结点的子结点（所有）
        if (!tree->haveNode[i]) {
            continue;
        }

        hashSeedMem(tmp, tree->nodes[i], salt, HASH_PREFIX_1, repIndex, i, params);        // tmp = H(nodes[i] || salt || repIndex || nodeIndex)

        if (!tree->haveNode[2 * i + 1]) {
            /* left child = H_left(seed_i || salt || t || i) */
            memcpy(tree->nodes[2 * i + 1], tmp, params->seedSizeBytes);
            tree->haveNode[2 * i + 1] = 1;
        }

        /* The last non-leaf node will only have a left child when there are an odd number of leaves */
        if (exists(tree, 2 * i + 2) && !tree->haveNode[2 * i + 2]) {
            /* right child = H_right(seed_i || salt || t || i)  */
            memcpy(tree->nodes[2 * i + 2], tmp + params->seedSizeBytes, params->seedSizeBytes);
            tree->haveNode[2 * i + 2] = 1;
        }
    }
}

static void wordToMsgs(uint64_t w, msgs_t* msgs, Memparamset_t* params)// 广播
{
    for (size_t i = 0; i < params->numMPCParties; i++) {
        uint8_t w_i = getBit((uint8_t*)&w, i);                      // s_shares[i]
        setBit(msgs->msgs[i], msgs->pos, w_i);                      // msgs[i][pos] = s_shares[i]，i∈[n]
    }
    msgs->pos++;                                                    // pos++
}

static tree_t* generateSeedsMem(size_t nSeeds, uint8_t* rootSeed, uint8_t* salt, size_t repIndex, Memparamset_t* params)
{
    tree_t* tree = createTree(nSeeds, params->seedSizeBytes);

    memcpy(tree->nodes[0], rootSeed, params->seedSizeBytes);    // tree->nodes[0] = rootSeed, Bytesize = seedSizeBytes
    tree->haveNode[0] = 1;                                      // 拥有根结点的值
    expandSeedsMem(tree, salt, repIndex, params);                  // 拓展所有已知的结点的子结点（所有）

    return tree;
}

static uint64_t tapesToWord(randomTape_t* tapes)            // 从16个tapes中获取pos处的比特值组成返回值share，pos++
{
    uint64_t shares;                                        // 份额

    for (size_t i = 0; i < 64; i++) {
        uint8_t bit = getBit(tapes->tape[i], tapes->pos);   //getBit：Get one bit from a byte array
        setBit((uint8_t*)&shares, i, bit);                  //setBit：Set a specific bit in a byte array to a given value
    }
    tapes->pos++;
    return shares;
}

/* 从每盘磁带中读出一位，并将它们组合成一个单词。
 * 磁带形成一个z × N矩阵，我们将它转置，然后第一个“计数”N位行形成一个输出字。
 * 在当前的实现中N是16，所以字是uint16_t。返回值必须通过freeShares()释放。
 */
static void tapesToWords(shares_t* shares, randomTape_t* tapes)     // 通过tapes，赋值每个shares[w]
{
    for (size_t w = 0; w < shares->numWords; w++) {
        shares->shares[w] = tapesToWord(tapes);
    }
}

static void copyShares(shares_t* dst, shares_t* src)                // 复制share值
{
    assert(dst->numWords == src->numWords);
    memcpy(dst->shares, src->shares, dst->numWords * sizeof(dst->shares[0]));   // memcpy(dst, src, size)
}

static uint64_t extend(uint8_t bit)     // 带掩码的值
{
    return ~(bit - 1);
}

static void commitMem_h(uint8_t* digest, commitments_t** C, size_t rep, Memparamset_t* params)
{
    HashInstance ctx;

    HashInitMem(&ctx, HASH_PREFIX_NONE);
    for (size_t N = 0; N < params->memberSize + 1; N++) {
        for (size_t i = 0; i < params->numMPCParties; i++) {
            HashUpdate(&ctx, C[N][rep].hashes[i], params->digestSizeBytes);    // digest = H(C->hashes[i])
        }
    }
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);             // h_j = H(com_{j,1} ,...,com_{j,n},...,com_{j,1}^(N) ,...,com_{j,n}^(N))
}

// Commit to the views for one parallel rep，向视图提交一个平行代表？？？
static void commitMem_v(uint8_t* digest, uint8_t* input, msgs_t** msgs, size_t rep, Memparamset_t* params)
{
    HashInstance ctx;

    HashInitMem(&ctx, HASH_PREFIX_NONE);
    HashUpdate(&ctx, input, params->stateSizeBytes);        // H(input)
    for (size_t N = 0; N < params->memberSize + 1; N++) {
        for (size_t i = 0; i < params->numMPCParties; i++) {
            size_t msgs_size = numBytes(msgs[N][rep].pos);
            HashUpdate(&ctx, msgs[N][rep].msgs[i], msgs_size);         // H(msgs->msgs[i])
        }
    }
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);     // h_j^` = H({z_{j,α}},msgs_{j,1} ,..., msgs_{j,n},...,msgs_{j,1}^(N) ,..., msgs_{j,n}^(N))
}

static int hasRightChild(tree_t* tree, size_t node)
{
    return(2 * node + 2 < tree->numNodes && exists(tree, node));
}

static void computeParentHashMem(tree_t* tree, size_t child, uint8_t* salt, Memparamset_t* params)
{
    if (!exists(tree, child)) {
        return;
    }

    size_t parent = getParent(child);

    if (tree->haveNode[parent]) {
        return;
    }

    /* Compute the hash for parent, if we have everything */
    if (!tree->haveNode[2 * parent + 1]) {
        return;
    }

    if (exists(tree, 2 * parent + 2) && !tree->haveNode[2 * parent + 2]) {
        return;
    }

    /* Compute parent data = H(left child data || [right child data] || salt || parent idx) */
    HashInstance ctx;

    HashInitMem(&ctx, HASH_PREFIX_3);
    HashUpdate(&ctx, tree->nodes[2 * parent + 1], params->digestSizeBytes);
    if (hasRightChild(tree, parent)) {
        /* One node may not have a right child when there's an odd number of leaves */
        HashUpdate(&ctx, tree->nodes[2 * parent + 2], params->digestSizeBytes);
    }

    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, (uint16_t)parent);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tree->nodes[parent], params->digestSizeBytes);
    tree->haveNode[parent] = 1;
}

static void buildMerkleTreeMem(tree_t* tree, uint8_t** leafData, uint8_t* salt, Memparamset_t* params)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;

    /* Copy data to the leaves. The actual data being committed to has already been
     * hashed, according to the spec. */
    for (size_t i = 0; i < tree->numLeaves; i++) {
        if (leafData[i] != NULL) {
            memcpy(tree->nodes[firstLeaf + i], leafData[i], tree->dataSize);
            tree->haveNode[firstLeaf + i] = 1;
        }
    }
    /* Starting at the leaves, work up the tree, computing the hashes for intermediate nodes */
    for (int i = (int)tree->numNodes; i > 0; i--) {
        computeParentHashMem(tree, i, salt, params);
    }
}


static size_t bitsToChunksMem(size_t chunkLenBits, const uint8_t* input, size_t inputLen, uint16_t* chunks)
{
    // bit输入转为块
    if (chunkLenBits > inputLen * 8) {
        assert(!"Invalid input to bitsToChunks: not enough input");
        return 0;
    }
    size_t chunkCount = ((inputLen * 8) / chunkLenBits);

    for (size_t i = 0; i < chunkCount; i++) {
        chunks[i] = 0;
        for (size_t j = 0; j < chunkLenBits; j++) {
            chunks[i] += getBit(input, i * chunkLenBits + j) << j;
            assert(chunks[i] < (1 << chunkLenBits));
        }
        chunks[i] = fromLittleEndian(chunks[i]);
    }

    return chunkCount;
}

static size_t appendUniqueMem(uint16_t* list, uint16_t value, size_t position)
{
    // 已阅
    if (position == 0) {
        list[position] = value;
        return position + 1;
    }

    for (size_t i = 0; i < position; i++) {
        if (list[i] == value) {
            return position;
        }
    }
    list[position] = value;
    return position + 1;
}
#
static void HCPMem(uint16_t* challengeC, uint16_t* challengeP, commitments_t* Ch,
    uint8_t* hCv, uint8_t* salt, uint8_t* Xlist, const uint8_t* message,
    size_t messageByteLength, Memparamset_t* params)
{
    HashInstance ctx;
    uint8_t h[MAX_DIGEST_SIZE] = { 0 };

    assert(params->numOpenedRounds < params->numMPCRounds);

#if 0  // Print out inputs when debugging
    printf("\n");
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        printf("%s Ch[%lu]", __func__, t);
        printHex("", Ch->hashes[t], params->digestSizeBytes);

    }
    printHex("hCv", hCv, params->digestSizeBytes);

    printf("%s salt", __func__);
    printHex("", salt, params->saltSizeBytes);
    printf("%s Xlist", __func__);
    printHex("", Xlist, params->stateSizeBytes * 2 * params->memberSize);

#endif

    HashInitMem(&ctx, HASH_PREFIX_NONE);
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        HashUpdate(&ctx, Ch->hashes[t], params->digestSizeBytes);       // H(Ch->hashes)_承诺Com
    }

    HashUpdate(&ctx, hCv, params->digestSizeBytes);                     // H(hCv)
    HashUpdate(&ctx, salt, params->saltSizeBytes);                      // H(salt)
    HashUpdate(&ctx, Xlist, params->stateSizeBytes * 2 * params->memberSize);      // H(Xlist)
    HashUpdate(&ctx, message, messageByteLength);                       // H(message)
    HashFinal(&ctx);
    HashSqueeze(&ctx, h, params->digestSizeBytes);

    // Populate C       填充
    uint32_t bitsPerChunkC = ceil_log2(params->numMPCRounds);           // ceil_log2(M):轮数的有效位数
    uint32_t bitsPerChunkP = ceil_log2(params->numMPCParties);          // ceil_log2(n):协议参与方数量的有效位数
    uint16_t* chunks = calloc(params->digestSizeBytes * 8 / MIN(bitsPerChunkC, bitsPerChunkP), sizeof(uint16_t));

    size_t countC = 0;                                                  // 获取挑战C
    while (countC < params->numOpenedRounds) {
        // bitsToChunks(size_t chunkLenBits, const uint8_t* input, size_t inputLen, uint16_t* chunks)
        size_t numChunks = bitsToChunksMem(bitsPerChunkC, h, params->digestSizeBytes, chunks);
        for (size_t i = 0; i < numChunks; i++) {
            if (chunks[i] < params->numMPCRounds) {
                countC = appendUniqueMem(challengeC, chunks[i], countC);
            }
            if (countC == params->numOpenedRounds) {
                break;
            }
        }

        HashInitMem(&ctx, HASH_PREFIX_1);
        HashUpdate(&ctx, h, params->digestSizeBytes);
        HashFinal(&ctx);
        HashSqueeze(&ctx, h, params->digestSizeBytes);                  // h = H(h)
    }

    // Note that we always compute h = H(h) after setting C
    size_t countP = 0;

    while (countP < params->numOpenedRounds) {                          // 获取挑战P
        size_t numChunks = bitsToChunksMem(bitsPerChunkP, h, params->digestSizeBytes, chunks);
        for (size_t i = 0; i < numChunks; i++) {
            if (chunks[i] < params->numMPCParties) {
                challengeP[countP] = chunks[i];
                countP++;
            }
            if (countP == params->numOpenedRounds) {
                break;
            }
        }

        HashInitMem(&ctx, HASH_PREFIX_1);
        HashUpdate(&ctx, h, params->digestSizeBytes);
        HashFinal(&ctx);
        HashSqueeze(&ctx, h, params->digestSizeBytes);                  // h = H(h)
    }

#if 0   // Print challenge when debugging
    printf("C = ");
    for (size_t i = 0; i < countC; i++) {
        printf("%u, ", challengeC[i]);
    }
    printf("\n");

    printf("P = ");
    for (size_t i = 0; i < countP; i++) {
        printf("%u, ", challengeP[i]);
    }
    printf("\n");
#endif

    free(chunks);

}

static uint8_t** FIX_PLIST(uint16_t* challengeC, uint16_t* challengeP, uint8_t** Plist,uint8_t X_index, Memparamset_t* params) {

    uint8_t* slab = calloc(1, params->numOpenedRounds * (params->memberSize * sizeof(uint8_t) + sizeof(uint8_t*)));

    uint8_t** newPlist = (uint8_t**)slab;

    slab += params->numOpenedRounds * sizeof(uint8_t*);

    for (size_t i = 0; i < params->numOpenedRounds; i++) {
        newPlist[i] = (uint8_t*)slab;
        memcpy(newPlist[i], Plist[challengeC[i]], params->memberSize * sizeof(uint8_t));
        uint8_t FS_Challenge = challengeP[i] ^ slab[X_index-1];
        for (size_t j = 0; j < params->memberSize; j++) {
            FS_Challenge ^= slab[j];
        }
        slab[X_index-1] = FS_Challenge;
        slab += params->memberSize * sizeof(uint8_t);
    }
    return newPlist;
}

static int contains(uint16_t* list, size_t len, size_t value)   // 如果list中包含value，返回1，否则返回0
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] == value) {
            return 1;
        }
    }
    return 0;
}

static int contains_size_t(size_t* list, size_t len, size_t value)
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] == value) {
            return 1;
        }
    }
    return 0;
}

static uint16_t* getMissingLeavesListMem(uint16_t* challengeC, Memparamset_t* params)     // Merkle哈希结构
{
    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = calloc(missingLeavesSize, sizeof(uint16_t));
    size_t pos = 0;

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        if (!contains(challengeC, params->numOpenedRounds, i)) {                    // 如果ChallengeC中包含i，跳过，否则进入if函数体
            missingLeaves[pos] = i;
            pos++;
        }
    }

    return missingLeaves;
}


static size_t revealSeedsMem(tree_t* tree, uint16_t* hideList, size_t hideListSize, uint8_t* output, size_t outputSize, Memparamset_t* params)
{
    uint8_t* outputBase = output;
    size_t revealedSize = 0;

    if (outputSize > INT_MAX) {
        return -1;
    }
    int outLen = (int)outputSize;

    size_t* revealed = getRevealedNodes(tree, hideList, hideListSize, &revealedSize);
    for (size_t i = 0; i < revealedSize; i++) {
        outLen -= params->seedSizeBytes;
        if (outLen < 0) {
            assert(!"Insufficient sized buffer provided to revealSeeds");
            free(revealed);
            return 0;
        }
        memcpy(output, tree->nodes[revealed[i]], params->seedSizeBytes);
        output += params->seedSizeBytes;
    }

    free(revealed);
    return output - outputBase;
}

static int indexOf(uint16_t* list, size_t len, size_t value)    // 如果list中包含value，返回下标，否则返回-1
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] == value) {
            return i;
        }
    }
    assert(!"indexOf called on list where value is not found. (caller bug)");
    return -1;
}


/*======================================================================================================================================================================*/

static void Aux_Xor1(shares_t* state, shares_t* Key, uint64_t i, Memparamset_t* params) {		// int
    for (uint64_t j = 0; j < params->tempSizeBits; j++) {
        state->shares[(j + i * 32) % 128] = Key->shares[(j + 96 + i * 32) % 128] ^ Key->shares[(j + 32 + i * 32) % 128] ^ Key->shares[(j + 64 + i * 32) % 128];
    }
}

static void Aux_Xor2(shares_t* state, uint64_t r, Memparamset_t* params)
{
    for (int i = 0; i < params->tempSizeBits; i++)
    {
        state->shares[(r * 32 + i) % 128] ^= state->shares[(r * 32 + i + 32) % 128] ^ state->shares[(r * 32 + i + 64) % 128] ^ state->shares[(r * 32 + i + 96) % 128];
    }
}

static uint64_t Aux_AND(uint64_t a, uint64_t b, randomTape_t* tapes, Memparamset_t* params)
{
    uint64_t mask_a = parity64(a);
    uint64_t mask_b = parity64(b);
    uint64_t fresh_output_mask = tapesToWord(tapes);    // tapesToWord：从64个tapes中获取pos处的比特值组成返回值64bit的share，pos++
    uint64_t and_helper = tapesToWord(tapes);

    /* 将最后一方的helper值份额归零，根据输入掩码计算它；然后更新磁带 */
    setBit((uint8_t*)&and_helper, params->numMPCParties - 1, 0);
    uint64_t aux_bit = (mask_a & mask_b) ^ parity64(and_helper);        // aux = (a & b) ^ parity(and_helper)

    int lastParty = tapes->nTapes - 1;                                  // 修改最后一方
    setBit(tapes->tape[lastParty], tapes->pos - 1, (uint8_t)aux_bit);   // 将最后一方存放and_helper的值改为aux

    return fresh_output_mask;                                           // 返回从16个tapes中获取pos处的比特值组成的share
}

static void Aux_Sbox(shares_t* state_masks, randomTape_t* tapes, uint64_t r, Memparamset_t* params) {
    for (uint64_t i = 0; i < params->numSboxes * 8; i += 8)
    {
        uint64_t a_mask = state_masks->shares[(i + 0 + r * 32) % 128];
        uint64_t b_mask = state_masks->shares[(i + 1 + r * 32) % 128];
        uint64_t c_mask = state_masks->shares[(i + 2 + r * 32) % 128];
        uint64_t d_mask = state_masks->shares[(i + 3 + r * 32) % 128];
        uint64_t e_mask = state_masks->shares[(i + 4 + r * 32) % 128];
        uint64_t f_mask = state_masks->shares[(i + 5 + r * 32) % 128];
        uint64_t g_mask = state_masks->shares[(i + 6 + r * 32) % 128];
        uint64_t h_mask = state_masks->shares[(i + 7 + r * 32) % 128];

        uint64_t y0_mask, y1_mask, y2_mask, y3_mask, y4_mask, y5_mask, y6_mask, y7_mask, y8_mask, y9_mask, y10_mask, y11_mask, y12_mask, y13_mask, y14_mask, y15_mask, y16_mask, y17_mask, y18_mask, y19_mask, y20_mask, y21_mask, y22_mask;
        uint64_t t2_mask, t3_mask, t4_mask, t5_mask, t6_mask, t7_mask, t8_mask, t9_mask, t10_mask, t11_mask, t12_mask, t13_mask, t14_mask, t15_mask, t16_mask, t17_mask, t18_mask, t19_mask, t20_mask, t21_mask, t22_mask, t23_mask, t24_mask, t25_mask, t26_mask, t27_mask, t28_mask, t29_mask, t30_mask, t31_mask, t32_mask, t33_mask, t34_mask, t35_mask, t36_mask, t37_mask, t38_mask, t39_mask, t40_mask, t41_mask, t42_mask, t43_mask, t44_mask, t45_mask;
        uint64_t z0_mask, z1_mask, z2_mask, z3_mask, z4_mask, z5_mask, z6_mask, z7_mask, z8_mask, z9_mask, z10_mask, z11_mask, z12_mask, z13_mask, z14_mask, z15_mask, z16_mask, z17_mask, z18_mask;
        uint64_t u0_mask, u1_mask, u2_mask, u3_mask, u4_mask, u5_mask, u6_mask, u7_mask, u8_mask, u9_mask, u10_mask, u11_mask, u12_mask, u13_mask, u14_mask, u15_mask, u16_mask, u17_mask, u18_mask, u19_mask, u20_mask, u21_mask, u22_mask, u23_mask, u24_mask, u25_mask, u26_mask, u27_mask, u28_mask, u29_mask;
        uint64_t s0_mask, s1_mask, s2_mask, s3_mask, s4_mask, s5_mask, s6_mask, s7_mask;

        y1_mask = e_mask ^ h_mask;
        y11_mask = b_mask ^ d_mask;
        y14_mask = e_mask ^ y11_mask;
        y19_mask = a_mask ^ f_mask;
        y21_mask = b_mask ^ y19_mask;
        y22_mask = c_mask ^ g_mask;
        y12_mask = b_mask ^ y22_mask;
        y13_mask = y14_mask ^ y12_mask;
        y16_mask = y21_mask ^ y13_mask;
        y6_mask = a_mask ^ y16_mask;
        y7_mask = y1_mask ^ y16_mask;
        y0_mask = y11_mask ^ y7_mask;
        y5_mask = g_mask ^ y0_mask;
        y2_mask = y13_mask ^ y5_mask;
        y8_mask = f_mask ^ y7_mask;
        y3_mask = y5_mask ^ y8_mask;
        y4_mask = y12_mask ^ y3_mask;
        y9_mask = y2_mask ^ y4_mask;
        y10_mask = y19_mask ^ y8_mask;
        y15_mask = y6_mask ^ y0_mask;
        y17_mask = y16_mask ^ y15_mask;
        y18_mask = y7_mask ^ y2_mask;
        y20_mask = y22_mask ^ y15_mask;
        y0_mask = y0_mask ^ extend(1);
        y1_mask = y1_mask ^ extend(1);
        y2_mask = y2_mask ^ extend(1);
        y3_mask = y3_mask ^ extend(1);
        y4_mask = y4_mask ^ extend(1);
        y5_mask = y5_mask ^ extend(1);
        y7_mask = y7_mask ^ extend(1);
        y10_mask = y10_mask ^ extend(1);
        y15_mask = y15_mask ^ extend(1);
        y17_mask = y17_mask ^ extend(1);
        y19_mask = y19_mask ^ extend(1);
        t2_mask = Aux_AND(y12_mask, y15_mask, tapes, params);
        t3_mask = Aux_AND(y3_mask, y6_mask, tapes, params);
        t4_mask = t3_mask ^ t2_mask;
        t5_mask = Aux_AND(y4_mask, y0_mask, tapes, params);
        t6_mask = t5_mask ^ t2_mask;
        t7_mask = Aux_AND(y13_mask, y16_mask, tapes, params);
        t8_mask = Aux_AND(y5_mask, y1_mask, tapes, params);
        t9_mask = t8_mask ^ t7_mask;
        t10_mask = Aux_AND(y2_mask, y7_mask, tapes, params);
        t11_mask = t10_mask ^ t7_mask;
        t12_mask = Aux_AND(y9_mask, y11_mask, tapes, params);
        t13_mask = Aux_AND(y14_mask, y17_mask, tapes, params);
        t14_mask = t13_mask ^ t12_mask;
        t15_mask = Aux_AND(y8_mask, y10_mask, tapes, params);
        t16_mask = t15_mask ^ t12_mask;
        t17_mask = t4_mask ^ t14_mask;
        t18_mask = t6_mask ^ t16_mask;
        t19_mask = t9_mask ^ t14_mask;
        t20_mask = t11_mask ^ t16_mask;
        t21_mask = t17_mask ^ y20_mask;
        t22_mask = t18_mask ^ y19_mask;
        t23_mask = t19_mask ^ y21_mask;
        t24_mask = t20_mask ^ y18_mask;
        t25_mask = t21_mask ^ t22_mask;
        t26_mask = Aux_AND(t21_mask, t23_mask, tapes, params);
        t27_mask = t24_mask ^ t26_mask;
        t28_mask = Aux_AND(t25_mask, t27_mask, tapes, params);
        t29_mask = t28_mask ^ t22_mask;
        t30_mask = t23_mask ^ t24_mask;
        t31_mask = t22_mask ^ t26_mask;
        t32_mask = Aux_AND(t31_mask, t30_mask, tapes, params);
        t33_mask = t32_mask ^ t24_mask;
        t34_mask = t23_mask ^ t33_mask;
        t35_mask = t27_mask ^ t33_mask;
        t36_mask = Aux_AND(t24_mask, t35_mask, tapes, params);
        t37_mask = t36_mask ^ t34_mask;
        t38_mask = t27_mask ^ t36_mask;
        t39_mask = Aux_AND(t29_mask, t38_mask, tapes, params);
        t40_mask = t25_mask ^ t39_mask;
        t41_mask = t40_mask ^ t37_mask;
        t42_mask = t29_mask ^ t33_mask;
        t43_mask = t29_mask ^ t40_mask;
        t44_mask = t33_mask ^ t37_mask;
        t45_mask = t42_mask ^ t41_mask;
        z0_mask = Aux_AND(t44_mask, y15_mask, tapes, params);
        z1_mask = Aux_AND(t37_mask, y6_mask, tapes, params);
        z2_mask = Aux_AND(t33_mask, y0_mask, tapes, params);
        z3_mask = Aux_AND(t43_mask, y16_mask, tapes, params);
        z4_mask = Aux_AND(t40_mask, y1_mask, tapes, params);
        z5_mask = Aux_AND(t29_mask, y7_mask, tapes, params);
        z6_mask = Aux_AND(t42_mask, y11_mask, tapes, params);
        z7_mask = Aux_AND(t45_mask, y17_mask, tapes, params);
        z8_mask = Aux_AND(t41_mask, y10_mask, tapes, params);
        z9_mask = Aux_AND(t44_mask, y12_mask, tapes, params);
        z10_mask = Aux_AND(t37_mask, y3_mask, tapes, params);
        z11_mask = Aux_AND(t33_mask, y4_mask, tapes, params);
        z12_mask = Aux_AND(t43_mask, y13_mask, tapes, params);
        z13_mask = Aux_AND(t40_mask, y5_mask, tapes, params);
        z14_mask = Aux_AND(t29_mask, y2_mask, tapes, params);
        z15_mask = Aux_AND(t42_mask, y9_mask, tapes, params);
        z16_mask = Aux_AND(t45_mask, y14_mask, tapes, params);
        z17_mask = Aux_AND(t41_mask, y8_mask, tapes, params);
        u0_mask = z1_mask ^ z13_mask;
        u1_mask = z2_mask ^ u0_mask;
        u2_mask = z12_mask ^ u1_mask;
        u3_mask = z7_mask ^ z10_mask;
        u4_mask = z5_mask ^ u2_mask;
        u5_mask = z0_mask ^ z16_mask;
        u6_mask = z1_mask ^ z3_mask;
        u7_mask = z15_mask ^ u4_mask;
        u8_mask = u5_mask ^ u6_mask;
        s6_mask = u7_mask ^ u8_mask;
        u10_mask = z8_mask ^ u3_mask;
        u11_mask = z4_mask ^ z16_mask;
        s7_mask = u7_mask ^ u11_mask;
        u13_mask = z11_mask ^ u8_mask;
        u14_mask = z17_mask ^ u13_mask;
        u15_mask = z9_mask ^ u4_mask;
        u16_mask = z10_mask ^ u14_mask;
        s2_mask = z4_mask ^ u16_mask;
        u18_mask = s7_mask ^ u14_mask;
        s1_mask = u15_mask ^ u18_mask;
        u20_mask = u10_mask ^ u15_mask;
        s3_mask = z5_mask ^ u20_mask;
        u22_mask = z6_mask ^ u3_mask;
        u23_mask = z3_mask ^ u22_mask;
        s4_mask = u15_mask ^ u23_mask;
        u25_mask = z11_mask ^ z14_mask;
        u26_mask = u10_mask ^ u25_mask;
        s5_mask = u1_mask ^ u26_mask;
        u28_mask = u23_mask ^ u25_mask;
        u29_mask = u16_mask ^ u28_mask;
        s0_mask = z13_mask ^ u29_mask;
        s0_mask = s0_mask ^ extend(1);
        s1_mask = s1_mask ^ extend(1);
        s3_mask = s3_mask ^ extend(1);
        s6_mask = s6_mask ^ extend(1);
        s7_mask = s7_mask ^ extend(1);

        state_masks->shares[(i + 0 + r * 32) % 128] = s0_mask;
        state_masks->shares[(i + 1 + r * 32) % 128] = s1_mask;
        state_masks->shares[(i + 2 + r * 32) % 128] = s2_mask;
        state_masks->shares[(i + 3 + r * 32) % 128] = s3_mask;
        state_masks->shares[(i + 4 + r * 32) % 128] = s4_mask;
        state_masks->shares[(i + 5 + r * 32) % 128] = s5_mask;
        state_masks->shares[(i + 6 + r * 32) % 128] = s6_mask;
        state_masks->shares[(i + 7 + r * 32) % 128] = s7_mask;
    }
}

static void Aux_L1(shares_t* state_masks, uint32_t r) {
    uint64_t temp[32];
    temp[24] = state_masks->shares[(r * 32 + 24) % 128] ^ state_masks->shares[(r * 32 + 26) % 128] ^ state_masks->shares[(r * 32 + 18) % 128] ^ state_masks->shares[(r * 32 + 10) % 128] ^ state_masks->shares[(r * 32 + 0) % 128];
    temp[25] = state_masks->shares[(r * 32 + 25) % 128] ^ state_masks->shares[(r * 32 + 27) % 128] ^ state_masks->shares[(r * 32 + 19) % 128] ^ state_masks->shares[(r * 32 + 11) % 128] ^ state_masks->shares[(r * 32 + 1) % 128];
    temp[26] = state_masks->shares[(r * 32 + 26) % 128] ^ state_masks->shares[(r * 32 + 28) % 128] ^ state_masks->shares[(r * 32 + 20) % 128] ^ state_masks->shares[(r * 32 + 12) % 128] ^ state_masks->shares[(r * 32 + 2) % 128];
    temp[27] = state_masks->shares[(r * 32 + 27) % 128] ^ state_masks->shares[(r * 32 + 29) % 128] ^ state_masks->shares[(r * 32 + 21) % 128] ^ state_masks->shares[(r * 32 + 13) % 128] ^ state_masks->shares[(r * 32 + 3) % 128];
    temp[28] = state_masks->shares[(r * 32 + 28) % 128] ^ state_masks->shares[(r * 32 + 30) % 128] ^ state_masks->shares[(r * 32 + 22) % 128] ^ state_masks->shares[(r * 32 + 14) % 128] ^ state_masks->shares[(r * 32 + 4) % 128];
    temp[29] = state_masks->shares[(r * 32 + 29) % 128] ^ state_masks->shares[(r * 32 + 31) % 128] ^ state_masks->shares[(r * 32 + 23) % 128] ^ state_masks->shares[(r * 32 + 15) % 128] ^ state_masks->shares[(r * 32 + 5) % 128];
    temp[30] = state_masks->shares[(r * 32 + 30) % 128] ^ state_masks->shares[(r * 32 + 16) % 128] ^ state_masks->shares[(r * 32 + 8) % 128] ^ state_masks->shares[(r * 32 + 0) % 128] ^ state_masks->shares[(r * 32 + 6) % 128];
    temp[31] = state_masks->shares[(r * 32 + 31) % 128] ^ state_masks->shares[(r * 32 + 17) % 128] ^ state_masks->shares[(r * 32 + 9) % 128] ^ state_masks->shares[(r * 32 + 1) % 128] ^ state_masks->shares[(r * 32 + 7) % 128];
    temp[16] = state_masks->shares[(r * 32 + 16) % 128] ^ state_masks->shares[(r * 32 + 18) % 128] ^ state_masks->shares[(r * 32 + 10) % 128] ^ state_masks->shares[(r * 32 + 2) % 128] ^ state_masks->shares[(r * 32 + 24) % 128];
    temp[17] = state_masks->shares[(r * 32 + 17) % 128] ^ state_masks->shares[(r * 32 + 19) % 128] ^ state_masks->shares[(r * 32 + 11) % 128] ^ state_masks->shares[(r * 32 + 3) % 128] ^ state_masks->shares[(r * 32 + 25) % 128];
    temp[18] = state_masks->shares[(r * 32 + 18) % 128] ^ state_masks->shares[(r * 32 + 20) % 128] ^ state_masks->shares[(r * 32 + 12) % 128] ^ state_masks->shares[(r * 32 + 4) % 128] ^ state_masks->shares[(r * 32 + 26) % 128];
    temp[19] = state_masks->shares[(r * 32 + 19) % 128] ^ state_masks->shares[(r * 32 + 21) % 128] ^ state_masks->shares[(r * 32 + 13) % 128] ^ state_masks->shares[(r * 32 + 5) % 128] ^ state_masks->shares[(r * 32 + 27) % 128];
    temp[20] = state_masks->shares[(r * 32 + 20) % 128] ^ state_masks->shares[(r * 32 + 22) % 128] ^ state_masks->shares[(r * 32 + 14) % 128] ^ state_masks->shares[(r * 32 + 6) % 128] ^ state_masks->shares[(r * 32 + 28) % 128];
    temp[21] = state_masks->shares[(r * 32 + 21) % 128] ^ state_masks->shares[(r * 32 + 23) % 128] ^ state_masks->shares[(r * 32 + 15) % 128] ^ state_masks->shares[(r * 32 + 7) % 128] ^ state_masks->shares[(r * 32 + 29) % 128];
    temp[22] = state_masks->shares[(r * 32 + 22) % 128] ^ state_masks->shares[(r * 32 + 8) % 128] ^ state_masks->shares[(r * 32 + 0) % 128] ^ state_masks->shares[(r * 32 + 24) % 128] ^ state_masks->shares[(r * 32 + 30) % 128];
    temp[23] = state_masks->shares[(r * 32 + 23) % 128] ^ state_masks->shares[(r * 32 + 9) % 128] ^ state_masks->shares[(r * 32 + 1) % 128] ^ state_masks->shares[(r * 32 + 25) % 128] ^ state_masks->shares[(r * 32 + 31) % 128];
    temp[8] = state_masks->shares[(r * 32 + 8) % 128] ^ state_masks->shares[(r * 32 + 10) % 128] ^ state_masks->shares[(r * 32 + 2) % 128] ^ state_masks->shares[(r * 32 + 26) % 128] ^ state_masks->shares[(r * 32 + 16) % 128];
    temp[9] = state_masks->shares[(r * 32 + 9) % 128] ^ state_masks->shares[(r * 32 + 11) % 128] ^ state_masks->shares[(r * 32 + 3) % 128] ^ state_masks->shares[(r * 32 + 27) % 128] ^ state_masks->shares[(r * 32 + 17) % 128];
    temp[10] = state_masks->shares[(r * 32 + 10) % 128] ^ state_masks->shares[(r * 32 + 12) % 128] ^ state_masks->shares[(r * 32 + 4) % 128] ^ state_masks->shares[(r * 32 + 28) % 128] ^ state_masks->shares[(r * 32 + 18) % 128];
    temp[11] = state_masks->shares[(r * 32 + 11) % 128] ^ state_masks->shares[(r * 32 + 13) % 128] ^ state_masks->shares[(r * 32 + 5) % 128] ^ state_masks->shares[(r * 32 + 29) % 128] ^ state_masks->shares[(r * 32 + 19) % 128];
    temp[12] = state_masks->shares[(r * 32 + 12) % 128] ^ state_masks->shares[(r * 32 + 14) % 128] ^ state_masks->shares[(r * 32 + 6) % 128] ^ state_masks->shares[(r * 32 + 30) % 128] ^ state_masks->shares[(r * 32 + 20) % 128];
    temp[13] = state_masks->shares[(r * 32 + 13) % 128] ^ state_masks->shares[(r * 32 + 15) % 128] ^ state_masks->shares[(r * 32 + 7) % 128] ^ state_masks->shares[(r * 32 + 31) % 128] ^ state_masks->shares[(r * 32 + 21) % 128];
    temp[14] = state_masks->shares[(r * 32 + 14) % 128] ^ state_masks->shares[(r * 32 + 0) % 128] ^ state_masks->shares[(r * 32 + 24) % 128] ^ state_masks->shares[(r * 32 + 16) % 128] ^ state_masks->shares[(r * 32 + 22) % 128];
    temp[15] = state_masks->shares[(r * 32 + 15) % 128] ^ state_masks->shares[(r * 32 + 1) % 128] ^ state_masks->shares[(r * 32 + 25) % 128] ^ state_masks->shares[(r * 32 + 17) % 128] ^ state_masks->shares[(r * 32 + 23) % 128];
    temp[0] = state_masks->shares[(r * 32 + 0) % 128] ^ state_masks->shares[(r * 32 + 2) % 128] ^ state_masks->shares[(r * 32 + 26) % 128] ^ state_masks->shares[(r * 32 + 18) % 128] ^ state_masks->shares[(r * 32 + 8) % 128];
    temp[1] = state_masks->shares[(r * 32 + 1) % 128] ^ state_masks->shares[(r * 32 + 3) % 128] ^ state_masks->shares[(r * 32 + 27) % 128] ^ state_masks->shares[(r * 32 + 19) % 128] ^ state_masks->shares[(r * 32 + 9) % 128];
    temp[2] = state_masks->shares[(r * 32 + 2) % 128] ^ state_masks->shares[(r * 32 + 4) % 128] ^ state_masks->shares[(r * 32 + 28) % 128] ^ state_masks->shares[(r * 32 + 20) % 128] ^ state_masks->shares[(r * 32 + 10) % 128];
    temp[3] = state_masks->shares[(r * 32 + 3) % 128] ^ state_masks->shares[(r * 32 + 5) % 128] ^ state_masks->shares[(r * 32 + 29) % 128] ^ state_masks->shares[(r * 32 + 21) % 128] ^ state_masks->shares[(r * 32 + 11) % 128];
    temp[4] = state_masks->shares[(r * 32 + 4) % 128] ^ state_masks->shares[(r * 32 + 6) % 128] ^ state_masks->shares[(r * 32 + 30) % 128] ^ state_masks->shares[(r * 32 + 22) % 128] ^ state_masks->shares[(r * 32 + 12) % 128];
    temp[5] = state_masks->shares[(r * 32 + 5) % 128] ^ state_masks->shares[(r * 32 + 7) % 128] ^ state_masks->shares[(r * 32 + 31) % 128] ^ state_masks->shares[(r * 32 + 23) % 128] ^ state_masks->shares[(r * 32 + 13) % 128];
    temp[6] = state_masks->shares[(r * 32 + 6) % 128] ^ state_masks->shares[(r * 32 + 24) % 128] ^ state_masks->shares[(r * 32 + 16) % 128] ^ state_masks->shares[(r * 32 + 8) % 128] ^ state_masks->shares[(r * 32 + 14) % 128];
    temp[7] = state_masks->shares[(r * 32 + 7) % 128] ^ state_masks->shares[(r * 32 + 25) % 128] ^ state_masks->shares[(r * 32 + 17) % 128] ^ state_masks->shares[(r * 32 + 9) % 128] ^ state_masks->shares[(r * 32 + 15) % 128];
    for (int i = 0; i < 32; i++)
    {
        state_masks->shares[(r * 32 + i) % 128] = temp[i];
    }
}

static void Aux_L2(shares_t* state_masks, uint32_t r) {
    uint64_t temp[32];
    temp[24] = state_masks->shares[(r * 32 + 24) % 128] ^ state_masks->shares[(r * 32 + 21) % 128] ^ state_masks->shares[(r * 32 + 15) % 128];
    temp[25] = state_masks->shares[(r * 32 + 25) % 128] ^ state_masks->shares[(r * 32 + 22) % 128] ^ state_masks->shares[(r * 32 + 0) % 128];
    temp[26] = state_masks->shares[(r * 32 + 26) % 128] ^ state_masks->shares[(r * 32 + 23) % 128] ^ state_masks->shares[(r * 32 + 1) % 128];
    temp[27] = state_masks->shares[(r * 32 + 27) % 128] ^ state_masks->shares[(r * 32 + 8) % 128] ^ state_masks->shares[(r * 32 + 2) % 128];
    temp[28] = state_masks->shares[(r * 32 + 28) % 128] ^ state_masks->shares[(r * 32 + 9) % 128] ^ state_masks->shares[(r * 32 + 3) % 128];
    temp[29] = state_masks->shares[(r * 32 + 29) % 128] ^ state_masks->shares[(r * 32 + 10) % 128] ^ state_masks->shares[(r * 32 + 4) % 128];
    temp[30] = state_masks->shares[(r * 32 + 30) % 128] ^ state_masks->shares[(r * 32 + 11) % 128] ^ state_masks->shares[(r * 32 + 5) % 128];
    temp[31] = state_masks->shares[(r * 32 + 31) % 128] ^ state_masks->shares[(r * 32 + 12) % 128] ^ state_masks->shares[(r * 32 + 6) % 128];
    temp[16] = state_masks->shares[(r * 32 + 16) % 128] ^ state_masks->shares[(r * 32 + 13) % 128] ^ state_masks->shares[(r * 32 + 7) % 128];
    temp[17] = state_masks->shares[(r * 32 + 17) % 128] ^ state_masks->shares[(r * 32 + 14) % 128] ^ state_masks->shares[(r * 32 + 24) % 128];
    temp[18] = state_masks->shares[(r * 32 + 18) % 128] ^ state_masks->shares[(r * 32 + 15) % 128] ^ state_masks->shares[(r * 32 + 25) % 128];
    temp[19] = state_masks->shares[(r * 32 + 19) % 128] ^ state_masks->shares[(r * 32 + 0) % 128] ^ state_masks->shares[(r * 32 + 26) % 128];
    temp[20] = state_masks->shares[(r * 32 + 20) % 128] ^ state_masks->shares[(r * 32 + 1) % 128] ^ state_masks->shares[(r * 32 + 27) % 128];
    temp[21] = state_masks->shares[(r * 32 + 21) % 128] ^ state_masks->shares[(r * 32 + 2) % 128] ^ state_masks->shares[(r * 32 + 28) % 128];
    temp[22] = state_masks->shares[(r * 32 + 22) % 128] ^ state_masks->shares[(r * 32 + 3) % 128] ^ state_masks->shares[(r * 32 + 29) % 128];
    temp[23] = state_masks->shares[(r * 32 + 23) % 128] ^ state_masks->shares[(r * 32 + 4) % 128] ^ state_masks->shares[(r * 32 + 30) % 128];
    temp[8] = state_masks->shares[(r * 32 + 8) % 128] ^ state_masks->shares[(r * 32 + 5) % 128] ^ state_masks->shares[(r * 32 + 31) % 128];
    temp[9] = state_masks->shares[(r * 32 + 9) % 128] ^ state_masks->shares[(r * 32 + 6) % 128] ^ state_masks->shares[(r * 32 + 16) % 128];
    temp[10] = state_masks->shares[(r * 32 + 10) % 128] ^ state_masks->shares[(r * 32 + 7) % 128] ^ state_masks->shares[(r * 32 + 17) % 128];
    temp[11] = state_masks->shares[(r * 32 + 11) % 128] ^ state_masks->shares[(r * 32 + 24) % 128] ^ state_masks->shares[(r * 32 + 18) % 128];
    temp[12] = state_masks->shares[(r * 32 + 12) % 128] ^ state_masks->shares[(r * 32 + 25) % 128] ^ state_masks->shares[(r * 32 + 19) % 128];
    temp[13] = state_masks->shares[(r * 32 + 13) % 128] ^ state_masks->shares[(r * 32 + 26) % 128] ^ state_masks->shares[(r * 32 + 20) % 128];
    temp[14] = state_masks->shares[(r * 32 + 14) % 128] ^ state_masks->shares[(r * 32 + 27) % 128] ^ state_masks->shares[(r * 32 + 21) % 128];
    temp[15] = state_masks->shares[(r * 32 + 15) % 128] ^ state_masks->shares[(r * 32 + 28) % 128] ^ state_masks->shares[(r * 32 + 22) % 128];
    temp[0] = state_masks->shares[(r * 32 + 0) % 128] ^ state_masks->shares[(r * 32 + 29) % 128] ^ state_masks->shares[(r * 32 + 23) % 128];
    temp[1] = state_masks->shares[(r * 32 + 1) % 128] ^ state_masks->shares[(r * 32 + 30) % 128] ^ state_masks->shares[(r * 32 + 8) % 128];
    temp[2] = state_masks->shares[(r * 32 + 2) % 128] ^ state_masks->shares[(r * 32 + 31) % 128] ^ state_masks->shares[(r * 32 + 9) % 128];
    temp[3] = state_masks->shares[(r * 32 + 3) % 128] ^ state_masks->shares[(r * 32 + 16) % 128] ^ state_masks->shares[(r * 32 + 10) % 128];
    temp[4] = state_masks->shares[(r * 32 + 4) % 128] ^ state_masks->shares[(r * 32 + 17) % 128] ^ state_masks->shares[(r * 32 + 11) % 128];
    temp[5] = state_masks->shares[(r * 32 + 5) % 128] ^ state_masks->shares[(r * 32 + 18) % 128] ^ state_masks->shares[(r * 32 + 12) % 128];
    temp[6] = state_masks->shares[(r * 32 + 6) % 128] ^ state_masks->shares[(r * 32 + 19) % 128] ^ state_masks->shares[(r * 32 + 13) % 128];
    temp[7] = state_masks->shares[(r * 32 + 7) % 128] ^ state_masks->shares[(r * 32 + 20) % 128] ^ state_masks->shares[(r * 32 + 14) % 128];
    for (int i = 0; i < 32; i++)
    {
        state_masks->shares[(r * 32 + i) % 128] = temp[i];
    }

}

// state = Key[0]^L2(state)
static void Aux_L22(shares_t* state, shares_t* Key, uint64_t i, Memparamset_t* params) {
    Aux_L2(state, i);
    for (int k = 0; k < params->tempSizeBits; k++) {
        Key->shares[(i * 32 + k) % 128] ^= state->shares[(i * 32 + k) % 128];
        state->shares[(i * 32 + k) % 128] = Key->shares[(i * 32 + k) % 128];
    }
}

static void Aux_L11(shares_t* state, shares_t* temp, uint64_t r, Memparamset_t* params) {
    Aux_L1(state, r);
    for (int i = 0; i < params->tempSizeBits; i++)
    {
        state->shares[(r * 32 + i) % 128] ^= temp->shares[i];
    }
}

/* 输入为1次并行重复的随即磁带，如tapes[t]
 * 用与门输出的掩码值更新所有随机磁带的成员,
 * 并计算第n方的份额，使与门的不变量带有掩码值
 */
static void computeAuxTapeMem(randomTape_t* tapes, uint32_t* inter_mask, Memparamset_t* params, size_t REorOm)
{
    shares_t* state = allocateShares(params->stateSizeBits);
    shares_t* key = allocateShares(params->stateSizeBits);
    shares_t* temp = allocateShares(params->tempSizeBits);
    uint32_t xx[4];

    uint32_t NumRounds;
    if (REorOm != 0) {
        tapesToWords(key, tapes);
        tapesToWords(state, tapes);
        NumRounds = params->resumeRounds;
    }
    else {
        tapesToWords(key, tapes);
        tapesToWords(state, tapes);
        NumRounds = params->oneTimeRounds;
    }
    //printf("AUX\n");
    //reconstructShares((uint32_t*)xx, key);
    //printHex("keyMask", xx, params->stateSizeBytes);
    //reconstructShares((uint32_t*)xx, state);
    //printHex("textMask", xx, params->stateSizeBytes);
    //printf("\n");

    // 下一行是两个操作的组合，它进行了简化，因为 XORs 除以常数在预处理期间是一个NOP（空指令）。
     //roundKey = key * KMatrix[0]
     //state = roundKey + plaintext
    //aux_matrix_mul(state, key, KMatrix(0, params), tmp1, params);

    for (uint32_t r = 0; r < NumRounds; r++) {
        for (int i = 0; i < params->tempSizeBits; i++)              // temp = state
        {
            temp->shares[i] = state->shares[(r * 32 + i) % 128];
        }
        Aux_Xor1(state, key, r, params);						    // state = Key[1] ^ Key[2] ^ Key[3]
        Aux_Sbox(state, tapes, r, params);							// state = S(state)
        Aux_L22(state, key, r, params);			                    // state = Key[0] ^ L2(state)       此时state为轮密钥

        Aux_Xor2(state, r, params);                                 // state = plaintext[1/2/3] ^ state
        Aux_Sbox(state, tapes, r, params);							// state = S(state)
        Aux_L11(state, temp, r, params);			                // state = L1(state)^temp
    }
    
    // 重置随机磁带计数器，使在线执行使用与计算辅助共享时相同的随机位
    tapes->pos = 0;

    if (REorOm == 0) {
        reconstructShares((uint32_t*)inter_mask, key);
        //printHex("AUXkeyMask", xx, params->stateSizeBytes);
        reconstructShares(inter_mask + params->stateSizeWords, state);
        //printHex("AUXtextMask", xx, params->stateSizeBytes);
    }
    //free(roundKey);
    freeShares(key);
    freeShares(state);
    freeShares(temp);
}

/* 对每个share中的word ; 写玩家i的share到他们的msgs流中 */
static void broadcast(shares_t* shares, msgs_t* msgs, Memparamset_t* params)   // 广播
{
    for (size_t w = 0; w < shares->numWords; w++) {
        wordToMsgs(shares->shares[w], msgs, params);        //msgs[player][pos] = shares[player][i]，i∈[n], pos++
    }
}
/*=======================================================================================================================================================================*/

static void MPC_Init(uint32_t* plaintext, uint32_t* Temp_plaintext, uint32_t* maskedKey, uint32_t* Temp_maskedKey, Memparamset_t* params)
{
    for (int i = 0; i < params->stateSizeWords; i++)
    {
        Temp_plaintext[i] = plaintext[i];
        Temp_maskedKey[i] = maskedKey[i];
    }
    //(uint8_t*)Temp_plaintext = "\x60";
}

// maskedKey = maskedKey ^ FK				Key_mask = Key_mask ^ FK
static void MPC_InitKey(uint32_t* maskedKey, shares_t* Key_mask, Memparamset_t* params) {
    for (int i = 0; i < params->stateSizeWords; i++)
        maskedKey[i] ^= FK[i];
    for (int i = 0; i < params->stateSizeBits; i++) {
        int m = i / 32;
        int n = i % 32;
        uint8_t bit = (FK[m] >> (n - 31)) & 0x01;
        Key_mask->shares[i] ^= extend(bit);
    }
}

// state = maskedKey[1/2/3] ^ CK[i]			Key_mask = maskedKey[1/2/3]
static void MPC_Xor1(uint32_t* state, shares_t* state_masks, uint32_t* maskedKey, shares_t* Key_mask, uint32_t r, Memparamset_t* params,size_t ReorOm) {
    size_t ck_index = (ReorOm) ? (params->oneTimeRounds + r) : r;

    state[r % 4] = maskedKey[(r + 1) % 4] ^ maskedKey[(r + 2) % 4] ^ maskedKey[(r + 3) % 4] ^ CK[ck_index];

    for (int i = 0; i < params->tempSizeBits; i++) {
        state_masks->shares[(i + r * 32) % 128] = Key_mask->shares[(i + 96 + r * 32) % 128] ^ Key_mask->shares[(i + 32 + r * 32) % 128] ^ Key_mask->shares[(i + 64 + r * 32) % 128];
    }
}

// state = plaintext[1/2/3] ^ state
static void MPC_Xor2(uint32_t* state, shares_t* state_masks, uint32_t* plaintext, uint32_t r)
{
    state[r % 4] = state[r % 4] ^ plaintext[(r + 1) % 4] ^ plaintext[(r + 2) % 4] ^ plaintext[(r + 3) % 4];
    for (int i = 0; i < 32; i++)
    {
        state_masks->shares[(r * 32 + i) % 128] ^= state_masks->shares[(r * 32 + i + 32) % 128] ^ state_masks->shares[(r * 32 + i + 64) % 128] ^ state_masks->shares[(r * 32 + i + 96) % 128];
    }
}

static uint8_t MPC_AND(uint8_t a, uint8_t b, uint64_t mask_a, uint64_t mask_b, randomTape_t* tapes, msgs_t* msgs, uint64_t* out, Memparamset_t* params)
{
    uint64_t output_mask = tapesToWord(tapes);  // 输出掩码，即[λ_{γ}]

    *out = output_mask;
    uint64_t and_helper = tapesToWord(tapes);   // 在预处理过程中为每个与门设置特殊的掩码值，即[λ_{α,β}]
    uint64_t s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ output_mask;
    // [s]计算：s_shares = (带掩码的真实值a & 掩码份额b) ^ (带掩码的真实值b & 掩码份额a) ^ and_helper ^ output_mask

    //printf("\n%d", a ^ parity64(mask_a));                                           // a的真实值
    //printf("%d", b ^ parity64(mask_b));                                             // b的真实值
    //printf("\n%d", parity64(mask_a)&0x01);                                           // a的掩码
    //printf("%d", parity64(mask_b)&0x01);                                             // b的掩码

    if (msgs->unopened >= 0) {                                                      // 存在没有打开的一方
        // printf("---unopened:%d---pos:%d", msgs->unopened, msgs->pos);
        uint8_t unopenedPartyBit = getBit(msgs->msgs[msgs->unopened], msgs->pos);   // unopenedPartyBit = msgs[unopened][pos]
        setBit((uint8_t*)&s_shares, msgs->unopened, unopenedPartyBit);              // s_shares[unopened] = unopenedPartyBit
    }

    // 广播每一个share的s
    wordToMsgs(s_shares, msgs, params);

    //printf("%d", parity64(output_mask)^ parity64(s_shares) ^ (a & b));              // ab的真实值

    return (uint8_t)(parity64(s_shares) ^ (a & b));                                 // 返回带掩码的输出值
}

// state = S(state)							state_masks = S(state_masks)
static void MPC_Sbox(uint32_t* state, shares_t* state_masks, randomTape_t* tapes, msgs_t* msgs, uint32_t r, Memparamset_t* params) {
    for (int i = 0; i < params->numSboxes * 8; i += 8) {
        uint8_t a = getBitFromWordArray(state, (i + 0 + r * 32) % 128);
        uint8_t b = getBitFromWordArray(state, (i + 1 + r * 32) % 128);
        uint8_t c = getBitFromWordArray(state, (i + 2 + r * 32) % 128);
        uint8_t d = getBitFromWordArray(state, (i + 3 + r * 32) % 128);
        uint8_t e = getBitFromWordArray(state, (i + 4 + r * 32) % 128);
        uint8_t f = getBitFromWordArray(state, (i + 5 + r * 32) % 128);
        uint8_t g = getBitFromWordArray(state, (i + 6 + r * 32) % 128);
        uint8_t h = getBitFromWordArray(state, (i + 7 + r * 32) % 128);

        uint64_t a_mask = state_masks->shares[(i + 0 + r * 32) % 128];
        uint64_t b_mask = state_masks->shares[(i + 1 + r * 32) % 128];
        uint64_t c_mask = state_masks->shares[(i + 2 + r * 32) % 128];
        uint64_t d_mask = state_masks->shares[(i + 3 + r * 32) % 128];
        uint64_t e_mask = state_masks->shares[(i + 4 + r * 32) % 128];
        uint64_t f_mask = state_masks->shares[(i + 5 + r * 32) % 128];
        uint64_t g_mask = state_masks->shares[(i + 6 + r * 32) % 128];
        uint64_t h_mask = state_masks->shares[(i + 7 + r * 32) % 128];

        uint8_t y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21, y22;
        uint8_t t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23, t24, t25, t26, t27, t28, t29, t30, t31, t32, t33, t34, t35, t36, t37, t38, t39, t40, t41, t42, t43, t44, t45;
        uint8_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17, z18;
        uint8_t u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, u10, u11, u12, u13, u14, u15, u16, u17, u18, u19, u20, u21, u22, u23, u24, u25, u26, u27, u28, u29;
        uint8_t s0, s1, s2, s3, s4, s5, s6, s7;

        uint64_t y0_mask, y1_mask, y2_mask, y3_mask, y4_mask, y5_mask, y6_mask, y7_mask, y8_mask, y9_mask, y10_mask, y11_mask, y12_mask, y13_mask, y14_mask, y15_mask, y16_mask, y17_mask, y18_mask, y19_mask, y20_mask, y21_mask, y22_mask;
        uint64_t t2_mask, t3_mask, t4_mask, t5_mask, t6_mask, t7_mask, t8_mask, t9_mask, t10_mask, t11_mask, t12_mask, t13_mask, t14_mask, t15_mask, t16_mask, t17_mask, t18_mask, t19_mask, t20_mask, t21_mask, t22_mask, t23_mask, t24_mask, t25_mask, t26_mask, t27_mask, t28_mask, t29_mask, t30_mask, t31_mask, t32_mask, t33_mask, t34_mask, t35_mask, t36_mask, t37_mask, t38_mask, t39_mask, t40_mask, t41_mask, t42_mask, t43_mask, t44_mask, t45_mask;
        uint64_t z0_mask, z1_mask, z2_mask, z3_mask, z4_mask, z5_mask, z6_mask, z7_mask, z8_mask, z9_mask, z10_mask, z11_mask, z12_mask, z13_mask, z14_mask, z15_mask, z16_mask, z17_mask, z18_mask;
        uint64_t u0_mask, u1_mask, u2_mask, u3_mask, u4_mask, u5_mask, u6_mask, u7_mask, u8_mask, u9_mask, u10_mask, u11_mask, u12_mask, u13_mask, u14_mask, u15_mask, u16_mask, u17_mask, u18_mask, u19_mask, u20_mask, u21_mask, u22_mask, u23_mask, u24_mask, u25_mask, u26_mask, u27_mask, u28_mask, u29_mask;
        uint64_t s0_mask, s1_mask, s2_mask, s3_mask, s4_mask, s5_mask, s6_mask, s7_mask;

        y1 = e ^ h;
        y1_mask = e_mask ^ h_mask;
        y11 = b ^ d;
        y11_mask = b_mask ^ d_mask;
        y14 = e ^ y11;
        y14_mask = e_mask ^ y11_mask;
        y19 = a ^ f;
        y19_mask = a_mask ^ f_mask;
        y21 = b ^ y19;
        y21_mask = b_mask ^ y19_mask;
        y22 = c ^ g;
        y22_mask = c_mask ^ g_mask;
        y12 = b ^ y22;
        y12_mask = b_mask ^ y22_mask;
        y13 = y14 ^ y12;
        y13_mask = y14_mask ^ y12_mask;
        y16 = y21 ^ y13;
        y16_mask = y21_mask ^ y13_mask;
        y6 = a ^ y16;
        y6_mask = a_mask ^ y16_mask;
        y7 = y1 ^ y16;
        y7_mask = y1_mask ^ y16_mask;
        y0 = y11 ^ y7;
        y0_mask = y11_mask ^ y7_mask;
        y5 = g ^ y0;
        y5_mask = g_mask ^ y0_mask;
        y2 = y13 ^ y5;
        y2_mask = y13_mask ^ y5_mask;
        y8 = f ^ y7;
        y8_mask = f_mask ^ y7_mask;
        y3 = y5 ^ y8;
        y3_mask = y5_mask ^ y8_mask;
        y4 = y12 ^ y3;
        y4_mask = y12_mask ^ y3_mask;
        y9 = y2 ^ y4;
        y9_mask = y2_mask ^ y4_mask;
        y10 = y19 ^ y8;
        y10_mask = y19_mask ^ y8_mask;
        y15 = y6 ^ y0;
        y15_mask = y6_mask ^ y0_mask;
        y17 = y16 ^ y15;
        y17_mask = y16_mask ^ y15_mask;
        y18 = y7 ^ y2;
        y18_mask = y7_mask ^ y2_mask;
        y20 = y22 ^ y15;
        y20_mask = y22_mask ^ y15_mask;
        y0 = y0 ^ 1;
        y0_mask = y0_mask ^ extend(1);
        y1 = y1 ^ 1;
        y1_mask = y1_mask ^ extend(1);
        y2 = y2 ^ 1;
        y2_mask = y2_mask ^ extend(1);
        y3 = y3 ^ 1;
        y3_mask = y3_mask ^ extend(1);
        y4 = y4 ^ 1;
        y4_mask = y4_mask ^ extend(1);
        y5 = y5 ^ 1;
        y5_mask = y5_mask ^ extend(1);
        y7 = y7 ^ 1;
        y7_mask = y7_mask ^ extend(1);
        y10 = y10 ^ 1;
        y10_mask = y10_mask ^ extend(1);
        y15 = y15 ^ 1;
        y15_mask = y15_mask ^ extend(1);
        y17 = y17 ^ 1;
        y17_mask = y17_mask ^ extend(1);
        y19 = y19 ^ 1;
        y19_mask = y19_mask ^ extend(1);
        t2 = MPC_AND(y12, y15, y12_mask, y15_mask, tapes, msgs, &t2_mask, params);
        t3 = MPC_AND(y3, y6, y3_mask, y6_mask, tapes, msgs, &t3_mask, params);
        t4 = t3 ^ t2;
        t4_mask = t3_mask ^ t2_mask;
        t5 = MPC_AND(y4, y0, y4_mask, y0_mask, tapes, msgs, &t5_mask, params);
        t6 = t5 ^ t2;
        t6_mask = t5_mask ^ t2_mask;
        t7 = MPC_AND(y13, y16, y13_mask, y16_mask, tapes, msgs, &t7_mask, params);
        t8 = MPC_AND(y5, y1, y5_mask, y1_mask, tapes, msgs, &t8_mask, params);
        t9 = t8 ^ t7;
        t9_mask = t8_mask ^ t7_mask;
        t10 = MPC_AND(y2, y7, y2_mask, y7_mask, tapes, msgs, &t10_mask, params);
        t11 = t10 ^ t7;
        t11_mask = t10_mask ^ t7_mask;
        t12 = MPC_AND(y9, y11, y9_mask, y11_mask, tapes, msgs, &t12_mask, params);
        t13 = MPC_AND(y14, y17, y14_mask, y17_mask, tapes, msgs, &t13_mask, params);
        t14 = t13 ^ t12;
        t14_mask = t13_mask ^ t12_mask;
        t15 = MPC_AND(y8, y10, y8_mask, y10_mask, tapes, msgs, &t15_mask, params);
        t16 = t15 ^ t12;
        t16_mask = t15_mask ^ t12_mask;
        t17 = t4 ^ t14;
        t17_mask = t4_mask ^ t14_mask;
        t18 = t6 ^ t16;
        t18_mask = t6_mask ^ t16_mask;
        t19 = t9 ^ t14;
        t19_mask = t9_mask ^ t14_mask;
        t20 = t11 ^ t16;
        t20_mask = t11_mask ^ t16_mask;
        t21 = t17 ^ y20;
        t21_mask = t17_mask ^ y20_mask;
        t22 = t18 ^ y19;
        t22_mask = t18_mask ^ y19_mask;
        t23 = t19 ^ y21;
        t23_mask = t19_mask ^ y21_mask;
        t24 = t20 ^ y18;
        t24_mask = t20_mask ^ y18_mask;
        t25 = t21 ^ t22;
        t25_mask = t21_mask ^ t22_mask;
        t26 = MPC_AND(t21, t23, t21_mask, t23_mask, tapes, msgs, &t26_mask, params);
        t27 = t24 ^ t26;
        t27_mask = t24_mask ^ t26_mask;
        t28 = MPC_AND(t25, t27, t25_mask, t27_mask, tapes, msgs, &t28_mask, params);
        t29 = t28 ^ t22;
        t29_mask = t28_mask ^ t22_mask;
        t30 = t23 ^ t24;
        t30_mask = t23_mask ^ t24_mask;
        t31 = t22 ^ t26;
        t31_mask = t22_mask ^ t26_mask;
        t32 = MPC_AND(t31, t30, t31_mask, t30_mask, tapes, msgs, &t32_mask, params);
        t33 = t32 ^ t24;
        t33_mask = t32_mask ^ t24_mask;
        t34 = t23 ^ t33;
        t34_mask = t23_mask ^ t33_mask;
        t35 = t27 ^ t33;
        t35_mask = t27_mask ^ t33_mask;
        t36 = MPC_AND(t24, t35, t24_mask, t35_mask, tapes, msgs, &t36_mask, params);
        t37 = t36 ^ t34;
        t37_mask = t36_mask ^ t34_mask;
        t38 = t27 ^ t36;
        t38_mask = t27_mask ^ t36_mask;
        t39 = MPC_AND(t29, t38, t29_mask, t38_mask, tapes, msgs, &t39_mask, params);
        t40 = t25 ^ t39;
        t40_mask = t25_mask ^ t39_mask;
        t41 = t40 ^ t37;
        t41_mask = t40_mask ^ t37_mask;
        t42 = t29 ^ t33;
        t42_mask = t29_mask ^ t33_mask;
        t43 = t29 ^ t40;
        t43_mask = t29_mask ^ t40_mask;
        t44 = t33 ^ t37;
        t44_mask = t33_mask ^ t37_mask;
        t45 = t42 ^ t41;
        t45_mask = t42_mask ^ t41_mask;
        z0 = MPC_AND(t44, y15, t44_mask, y15_mask, tapes, msgs, &z0_mask, params);
        z1 = MPC_AND(t37, y6, t37_mask, y6_mask, tapes, msgs, &z1_mask, params);
        z2 = MPC_AND(t33, y0, t33_mask, y0_mask, tapes, msgs, &z2_mask, params);
        z3 = MPC_AND(t43, y16, t43_mask, y16_mask, tapes, msgs, &z3_mask, params);
        z4 = MPC_AND(t40, y1, t40_mask, y1_mask, tapes, msgs, &z4_mask, params);
        z5 = MPC_AND(t29, y7, t29_mask, y7_mask, tapes, msgs, &z5_mask, params);
        z6 = MPC_AND(t42, y11, t42_mask, y11_mask, tapes, msgs, &z6_mask, params);
        z7 = MPC_AND(t45, y17, t45_mask, y17_mask, tapes, msgs, &z7_mask, params);
        z8 = MPC_AND(t41, y10, t41_mask, y10_mask, tapes, msgs, &z8_mask, params);
        z9 = MPC_AND(t44, y12, t44_mask, y12_mask, tapes, msgs, &z9_mask, params);
        z10 = MPC_AND(t37, y3, t37_mask, y3_mask, tapes, msgs, &z10_mask, params);
        z11 = MPC_AND(t33, y4, t33_mask, y4_mask, tapes, msgs, &z11_mask, params);
        z12 = MPC_AND(t43, y13, t43_mask, y13_mask, tapes, msgs, &z12_mask, params);
        z13 = MPC_AND(t40, y5, t40_mask, y5_mask, tapes, msgs, &z13_mask, params);
        z14 = MPC_AND(t29, y2, t29_mask, y2_mask, tapes, msgs, &z14_mask, params);
        z15 = MPC_AND(t42, y9, t42_mask, y9_mask, tapes, msgs, &z15_mask, params);
        z16 = MPC_AND(t45, y14, t45_mask, y14_mask, tapes, msgs, &z16_mask, params);
        z17 = MPC_AND(t41, y8, t41_mask, y8_mask, tapes, msgs, &z17_mask, params);
        u0 = z1 ^ z13;
        u0_mask = z1_mask ^ z13_mask;
        u1 = z2 ^ u0;
        u1_mask = z2_mask ^ u0_mask;
        u2 = z12 ^ u1;
        u2_mask = z12_mask ^ u1_mask;
        u3 = z7 ^ z10;
        u3_mask = z7_mask ^ z10_mask;
        u4 = z5 ^ u2;
        u4_mask = z5_mask ^ u2_mask;
        u5 = z0 ^ z16;
        u5_mask = z0_mask ^ z16_mask;
        u6 = z1 ^ z3;
        u6_mask = z1_mask ^ z3_mask;
        u7 = z15 ^ u4;
        u7_mask = z15_mask ^ u4_mask;
        u8 = u5 ^ u6;
        u8_mask = u5_mask ^ u6_mask;
        s6 = u7 ^ u8;
        s6_mask = u7_mask ^ u8_mask;
        u10 = z8 ^ u3;
        u10_mask = z8_mask ^ u3_mask;
        u11 = z4 ^ z16;
        u11_mask = z4_mask ^ z16_mask;
        s7 = u7 ^ u11;
        s7_mask = u7_mask ^ u11_mask;
        u13 = z11 ^ u8;
        u13_mask = z11_mask ^ u8_mask;
        u14 = z17 ^ u13;
        u14_mask = z17_mask ^ u13_mask;
        u15 = z9 ^ u4;
        u15_mask = z9_mask ^ u4_mask;
        u16 = z10 ^ u14;
        u16_mask = z10_mask ^ u14_mask;
        s2 = z4 ^ u16;
        s2_mask = z4_mask ^ u16_mask;
        u18 = s7 ^ u14;
        u18_mask = s7_mask ^ u14_mask;
        s1 = u15 ^ u18;
        s1_mask = u15_mask ^ u18_mask;
        u20 = u10 ^ u15;
        u20_mask = u10_mask ^ u15_mask;
        s3 = z5 ^ u20;
        s3_mask = z5_mask ^ u20_mask;
        u22 = z6 ^ u3;
        u22_mask = z6_mask ^ u3_mask;
        u23 = z3 ^ u22;
        u23_mask = z3_mask ^ u22_mask;
        s4 = u15 ^ u23;
        s4_mask = u15_mask ^ u23_mask;
        u25 = z11 ^ z14;
        u25_mask = z11_mask ^ z14_mask;
        u26 = u10 ^ u25;
        u26_mask = u10_mask ^ u25_mask;
        s5 = u1 ^ u26;
        s5_mask = u1_mask ^ u26_mask;
        u28 = u23 ^ u25;
        u28_mask = u23_mask ^ u25_mask;
        u29 = u16 ^ u28;
        u29_mask = u16_mask ^ u28_mask;
        s0 = z13 ^ u29;
        s0_mask = z13_mask ^ u29_mask;
        s0 = s0 ^ 1;
        s0_mask = s0_mask ^ extend(1);
        s1 = s1 ^ 1;
        s1_mask = s1_mask ^ extend(1);
        s3 = s3 ^ 1;
        s3_mask = s3_mask ^ extend(1);
        s6 = s6 ^ 1;
        s6_mask = s6_mask ^ extend(1);
        s7 = s7 ^ 1;
        s7_mask = s7_mask ^ extend(1);

        state_masks->shares[(i + 0 + r * 32) % 128] = s0_mask;
        state_masks->shares[(i + 1 + r * 32) % 128] = s1_mask;
        state_masks->shares[(i + 2 + r * 32) % 128] = s2_mask;
        state_masks->shares[(i + 3 + r * 32) % 128] = s3_mask;
        state_masks->shares[(i + 4 + r * 32) % 128] = s4_mask;
        state_masks->shares[(i + 5 + r * 32) % 128] = s5_mask;
        state_masks->shares[(i + 6 + r * 32) % 128] = s6_mask;
        state_masks->shares[(i + 7 + r * 32) % 128] = s7_mask;

        setBitInWordArray(state, (i + 0 + r * 32) % 128, s0);
        setBitInWordArray(state, (i + 1 + r * 32) % 128, s1);
        setBitInWordArray(state, (i + 2 + r * 32) % 128, s2);
        setBitInWordArray(state, (i + 3 + r * 32) % 128, s3);
        setBitInWordArray(state, (i + 4 + r * 32) % 128, s4);
        setBitInWordArray(state, (i + 5 + r * 32) % 128, s5);
        setBitInWordArray(state, (i + 6 + r * 32) % 128, s6);
        setBitInWordArray(state, (i + 7 + r * 32) % 128, s7);
    }
}

// state = Key[r % 4] ^ L2(state)			state_masks = Key_mask[r % 4] ^ L2(state_masks)
static void MPC_L22(uint32_t* state, shares_t* state_masks, uint32_t* maskedKey, shares_t* Key_mask, uint32_t r, Memparamset_t* params) {
    //uint32_t xx[4];
    //printf("\nstate:%08x", state[0]);

    state[r % 4] = L2(state[r % 4]);

    //printf("\nstate:%08x\n", state[0]);
    //for (int i = 0; i < 32; i++) {
    //    printf("%d\t%d\t", i, parity64(state_masks->shares[i]) & 0x01);
    //    printHex("", &state_masks->shares[i], 8);
    //}
    //reconstructShares(xx, state_masks);
    //printHex("掩码", xx, 4);
    //xor_array(xx, xx, state, 4);
    //printf("\n%s 康康%d的L2---state(不带掩码) ", __func__, r);
    //printHex("", xx, 4);

    Aux_L2(state_masks, r);

    //for (int i = 0; i < 32; i++) {
    //    printf("%d\t%d\t", i, parity64(state_masks->shares[i])&0x01);
    //    printHex("", &state_masks->shares[i], 8);
    //}
    //reconstructShares(xx, state_masks);
    //printHex("xx", xx, 4);
    //xor_array(xx, xx, state, 4);
    //printf("\n%s 康康%d的L2---state(不带掩码) ", __func__, r);
    //printHex("", xx, 4);


    state[r % 4] ^= maskedKey[r % 4];
    maskedKey[r % 4] = state[r % 4];
    for (int k = 0; k < params->tempSizeBits; k++) {
        state_masks->shares[(r * 32 + k) % 128] = Key_mask->shares[(r * 32 + k) % 128] ^ state_masks->shares[(r * 32 + k) % 128];
        Key_mask->shares[(r * 32 + k) % 128] = state_masks->shares[(r * 32 + k) % 128];
    }
}

// plaintext[r % 4] = plaintext[r % 4] ^ L1(state)
static void MPC_L11(uint32_t* state, shares_t* state_masks, uint32_t* plaintext, shares_t* temp_masks, uint32_t r, Memparamset_t* params) {
    // state = L1(state)		Key_mask = L1(Key_mask)
    state[r % 4] = L1(state[r % 4]);
    Aux_L1(state_masks, r);

    //uint32_t xx[4];
    //printf("\n%s 康康%d的L1---state(带掩码) ", __func__, r);
    //printHex("", state, 16);
    //reconstructShares(xx, state_masks);
    //printf("\n%s 康康%d的L1---state(掩码) ", __func__, r);
    //printHex("", xx, 16);
    //xor_array(xx, xx, state, 4);
    //printf("\n%s 康康%d的L1---state(不带掩码) ", __func__, r);
    //printHex("", xx, 16);

    state[r % 4] = plaintext[r % 4] ^ state[r % 4];
    plaintext[r % 4] = state[r % 4];
    for (int i = 0; i < params->tempSizeBits; i++)
    {
        state_masks->shares[(r * 32 + i) % 128] ^= temp_masks->shares[i];
    }
}

// temp = state         temp_masks = state_masks
static void MPC_Init_temp(shares_t* state_masks, shares_t* temp_masks, uint64_t r, Memparamset_t* params) {
    for (int i = 0; i < params->tempSizeBits; i++)
        temp_masks->shares[i] = state_masks->shares[(r * 32 + i) % 128];
}

static void MPC_Reverse(uint32_t* state, shares_t* state_masks) {
    uint32_t temp;
    for (int i = 0; i < 2; i++) {
        temp = state[i];
        state[i] = state[3 - i];
        state[3 - i] = temp;
    }
    uint64_t temp_masks;
    for (int i = 0; i < 32; i++) {
        temp_masks = state_masks->shares[i];
        state_masks->shares[i] = state_masks->shares[i + 96];
        state_masks->shares[i + 96] = temp_masks;
    }
    for (int i = 32; i < 64; i++) {
        temp_masks = state_masks->shares[i];
        state_masks->shares[i] = state_masks->shares[i + 32];
        state_masks->shares[i + 32] = temp_masks;
    }
}

void showBit(uint8_t* temp, size_t bitlen) {
    for (int i = 0; i < bitlen; i++) {
        printf("%d", getBit(temp, i));
        if (i != 0 && i % 8 == 0)printf(" ");
    }printf("\n");
}

// output^output_mask(63)^challenge_mask(1) = pubkey
// challenge_mask = pubkey^output^output_mask(63)
static void simulator_fixMsgs(msgs_t* msgs, uint32_t* pubkey, uint32_t* old_output, shares_t* output_mask, uint8_t Pre_Challenge, Memparamset_t* params) {
    
    uint32_t temp[4];
    xor_array(temp, old_output, pubkey, params->stateSizeWords);

    uint64_t maskparity63, fix_bit;
    for (size_t i = 0; i < params->stateSizeBits; i++) {
        maskparity63 = (uint64_t)getBit((uint8_t*)&output_mask->shares[i], Pre_Challenge);
        maskparity63 ^= parity64(output_mask->shares[i]);
        fix_bit = (uint64_t)getBit((uint8_t*)temp, i);
        fix_bit ^= maskparity63;
        setBit((uint8_t*)&output_mask->shares[i], Pre_Challenge, fix_bit);
        setBit((uint8_t*)msgs->msgs[Pre_Challenge], msgs->pos + i, fix_bit);
    }
}

// 模拟在线阶段：参数列表(掩码密钥，掩码份额，随机磁带，广播信息，明文，公钥)
static int simulateOnline_SM4(uint32_t* maskedKey, uint32_t* maskedplaintext, shares_t* Key_mask, shares_t* Plaintext_mask,
    randomTape_t* tapes, msgs_t* msgs, Memparamset_t* params, size_t ReorOm, uint32_t* Zinter,uint32_t* pubkey,uint8_t Pre_Challenge)
{
    int ret = 0;

    if (ReorOm != 0 && pubkey == NULL) {
        ret = -1;
        printf("illegal use!\n");
        printf("ret:%d", ret);
        goto Exit;
    }


    uint32_t* Temp_maskedKey = (uint32_t*)calloc(params->stateSizeWords, sizeof(uint32_t)); // 4
    uint32_t* Temp_plaintext = (uint32_t*)calloc(params->stateSizeWords, sizeof(uint32_t)); // 4
    uint32_t* state = (uint32_t*)malloc(params->stateSizeBytes);							// 4
    shares_t* temp_masks = allocateShares(params->tempSizeBits);
    uint32_t xx[4];

    //printf("MPC\n");
    //reconstructShares((uint32_t*)xx, Key_mask);
    //printHex("keyMask", xx, params->stateSizeBytes);
    //reconstructShares((uint32_t*)xx, Plaintext_mask);
    //printHex("textMask", xx, params->stateSizeBytes);
    //printf("\n");
    size_t NumRounds;
    if (ReorOm == 0) {
        NumRounds = params->oneTimeRounds;
    }
    else {
        NumRounds = params->resumeRounds;

    }

    MPC_Init(maskedplaintext, Temp_plaintext, maskedKey, Temp_maskedKey, params);
    if (ReorOm == 0) {
        MPC_InitKey(Temp_maskedKey, Key_mask, params);					         // maskedKey = maskedKey ^ FK
    }
    for (uint32_t r = 0; r < NumRounds; r++) {
        MPC_Init_temp(Plaintext_mask, temp_masks, r, params);                 // temp_masks = Plaintext_mask

        //reconstructShares((uint32_t*)xx, Key_mask);
        //xor_array((uint32_t*)xx, (uint32_t*)xx, Temp_maskedKey, 4);
        ////printHex("Key", (uint8_t*)xx, params->stateSizeBytes);

        //reconstructShares(xx, Plaintext_mask);
        //xor_array(xx, Temp_plaintext, xx, params->stateSizeWords);
        ////printHex("text", (uint8_t*)xx, params->stateSizeBytes);

        MPC_Xor1(state, Plaintext_mask, Temp_maskedKey, Key_mask, r, params, ReorOm); // state = maskedKey[1/2/3] ^ CK[i]                       // Plaintext_mask = Key_mask[1/2/3]
        MPC_Sbox(state, Plaintext_mask, tapes, msgs, r, params);			  // state = S(state) // Plaintext_mask = S(Plaintext_mask)
        MPC_L22(state, Plaintext_mask, Temp_maskedKey, Key_mask, r, params);  // Key[r % 4] = state = Key[r % 4] ^ L2(state)            // Key_mask[r % 4] = Plaintext_mask = Key_mask[r % 4] ^ L2(Plaintext_mask)
        
        MPC_Xor2(state, Plaintext_mask, Temp_plaintext, r);					  // state = plaintext[1/2/3] ^ state
        MPC_Sbox(state, Plaintext_mask, tapes, msgs, r, params);			  // state = S(state)                                       // Plaintext_mask = S(Plaintext_mask)
        MPC_L11(state, Plaintext_mask, Temp_plaintext, temp_masks, r, params);// plaintext[r % 4] = temp ^ L1(state)                    // Plaintext_mask = L1(Plaintext_mask)

       // reconstructShares((uint32_t*)xx, Key_mask);
       // xor_array((uint32_t*)xx, (uint32_t*)xx, Temp_maskedKey, 4);
       // //printHex("Key", (uint8_t*)xx, params->stateSizeBytes);

        //reconstructShares(xx, Plaintext_mask);
        //xor_array(xx, Temp_plaintext, xx, params->stateSizeWords);
        //printHex("state", (uint8_t*)xx, params->stateSizeBytes);
    }
    if (ReorOm != 0) {
        MPC_Reverse(state, Plaintext_mask);       // X28 X29 X30 X31 -> X31 X30 X29 X28
    }

    /* 签名、模拟器 */
    if ((msgs->unopened >= 0 && ReorOm != 0)) {
        /* 在签名验证期间，我们在msgs中已经有未打开方的输出份额，但在Key_mask中没有。 */
        for (size_t i = 0; i < params->stateSizeBits; i++) {
            uint8_t share = getBit(msgs->msgs[msgs->unopened], msgs->pos + i);      // share = 未打开方的msgs[pos+i]
            setBit((uint8_t*)&Plaintext_mask->shares[i], msgs->unopened, share);    // Key_mask->shares[i][unopened] = share
        }
    }

    if (ReorOm != 0) {
        if (Pre_Challenge == NOCHALLENGE) {
            broadcast(Plaintext_mask, msgs, params);									       
        }
        else if ((pubkey != NULL) && (Pre_Challenge != NOCHALLENGE)) { //simulator
            simulator_fixMsgs(msgs, pubkey, state, Plaintext_mask, Pre_Challenge, params);
            broadcast(Plaintext_mask, msgs, params);
        }
    }

    uint32_t output[4];
    reconstructShares(output, Plaintext_mask);
    xor_array(output, state, output, params->stateSizeWords);



    if (ReorOm != 0 && memcmp(output, pubkey, params->stateSizeBytes) != 0) {       // 如果output和ciphertext不相等，Exit
        printf("%s: output does not match pubKey\n", __func__);
        printHex("pubKey", (uint8_t*)pubkey, params->stateSizeBytes);
        printHex("output", (uint8_t*)output, params->stateSizeBytes);
        ret = -1;
        printf("ret:%d", ret);
        goto Exit;
    }
    else if(ReorOm == 0) {
        //printHex("output", (uint8_t*)output, params->stateSizeBytes);
        //printHex("masked_output", (uint8_t*)state, 16);
        //reconstructShares((uint32_t*)xx, Key_mask);
        //xor_array((uint32_t*)xx, (uint32_t*)xx, Temp_maskedKey,4);
        //printHex("Key", (uint8_t*)xx, params->stateSizeBytes);
        //printHex("masked_key", (uint8_t*)Temp_maskedKey, 16);
        //reconstructShares((uint32_t*)xx, Key_mask);
        //printHex("MPCkeymask", (uint8_t*)xx, 16);
        //reconstructShares(xx, Plaintext_mask);
        //printHex("MPCtextmask", (uint8_t*)xx, 16);
        //printf("\n");

        //正式
        //提取 maked_Z_inter
        memcpy(Zinter, Temp_maskedKey, params->stateSizeBytes);
        memcpy(Zinter + params->stateSizeWords, state, params->stateSizeBytes);
    }
    

    
    //printf("\n--- msgs->pos:%d", msgs->pos);                                      // pos = 128 + 246 * 8 * 32 = 63104

    free(Temp_plaintext);
    free(Temp_maskedKey);
    free(state);
    freeShares(temp_masks);
Exit:
    return ret;
}


/*=======================================================================================================================================================================*/

//修改输入掩码=中间状态掩码^随机掩码 && 修改Zinter的掩码
void* GetZinterTape(uint8_t* RemaskTape, uint8_t* Zinter, randomTape_t* tapes, Memparamset_t* params) {
    uint8_t* randomZinter = malloc(params->stateSizeBytes * 2);
    xor_array((uint32_t*)randomZinter, (uint32_t*)RemaskTape, (uint32_t*)Zinter, params->stateSizeWords * 2);
    //printHex("nowMask", (uint8_t*)randomZinter, params->stateSizeBytes * 2);

    shares_t* key = allocateShares(params->stateSizeBits);
    shares_t* text = allocateShares(params->stateSizeBits);
    tapesToWords(key, tapes);
    tapesToWords(text, tapes);

    uint64_t keybit, textbit;
    for (size_t i = 0; i < params->stateSizeBits; i++) {
        keybit = key->shares[i];
        textbit = text->shares[i];
        setBit((uint8_t*)&keybit, params->numMPCParties - 1, 0);
        setBit((uint8_t*)&textbit, params->numMPCParties - 1, 0);

        uint64_t fixKey_bit,fixtext_bit;
        fixKey_bit = (uint64_t)getBit(randomZinter, i);
        fixtext_bit = (uint64_t)getBit(randomZinter + params->stateSizeBytes, i);

        fixKey_bit ^= parity64(keybit);
        fixtext_bit ^= parity64(textbit);

        int lastParty = tapes->nTapes - 1;
        setBit(tapes->tape[lastParty], i, (uint8_t)fixKey_bit);
        setBit(tapes->tape[lastParty], i + params->stateSizeBits, (uint8_t)fixtext_bit);
    }
    tapes->pos = 0;
    free(randomZinter);
    freeShares(key);
    freeShares(text);
}

int MemberProof_sign(Memparamset_t* paramset, MemKey* Key, const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len, uint8_t* Xlist, size_t X_index,int* PreT,int* OnT) {
    //check if in the X
    if (memcmp(Key, Xlist + 16 * 2 * (X_index - 1), 16 * 2) != 0) {
        printf("not in Xlist\n");
        return -1;
    }

    int ret;

    signatureMem_t* sig = (signatureMem_t*)malloc(sizeof(signatureMem_t));
    allocateSignatureMem(sig, paramset);
    if (sig == NULL) {
        return -1;
    }


    ret = sign_memberpf(paramset, (uint32_t*)Key->sk, (uint32_t*)Key->pk, (uint32_t*)Key->c, message, message_len, sig, Xlist, X_index, PreT, OnT);

    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to create signature\n");
        fflush(stderr);
        freeSignatureMem(sig, paramset);
        free(sig);
        return -1;
    }

    ret = serializeSignatureMem(sig, signature, *signature_len, paramset);
    if (ret == -1) {
        fprintf(stderr, "Failed to serialize signature\n");
        fflush(stderr);
        freeSignatureMem(sig, paramset);
        free(sig);
        return -1;
    }
    *signature_len = ret;

    freeSignatureMem(sig, paramset);
    free(sig);

    return 0;
}

int MemberProof_verify(Memparamset_t* paramset, const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len, uint8_t* Xlist)
{
    int ret;

    signatureMem_t* sig = (signatureMem_t*)malloc(sizeof(signatureMem_t));
    allocateSignatureMem(sig, paramset);
    if (sig == NULL) {
        return -1;
    }

    ret = deserializeSignatureMem(sig, signature, signature_len, paramset);
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to deserialize signature\n");
        fflush(stderr);
        freeSignatureMem(sig, paramset);
        free(sig);
        return -1;
    }

    ret = verify_memberf(paramset, message, message_len, sig, Xlist);
    if (ret != EXIT_SUCCESS) {
        /* Signature is invalid, or verify function failed */
        freeSignatureMem(sig, paramset);
        free(sig);
        return -1;
    }

    freeSignatureMem(sig, paramset);
    free(sig);

    return 0;
}

static int reconstructSeedsMem(tree_t* tree, uint16_t* hideList, size_t hideListSize,
    uint8_t* input, size_t inputLen, uint8_t* salt, size_t repIndex, Memparamset_t* params)
{
    // iSeedInfo = input    challengeC = hideList    iSeedTree = tree
    int ret = 0;

    if (inputLen > INT_MAX) {
        return -1;
    }
    int inLen = (int)inputLen;

    size_t revealedSize = 0;
    size_t* revealed = getRevealedNodes(tree, hideList, hideListSize, &revealedSize);
    for (size_t i = 0; i < revealedSize; i++) {
        inLen -= params->seedSizeBytes;
        if (inLen < 0) {
            ret = -1;
            goto Exit;
        }
        memcpy(tree->nodes[revealed[i]], input, params->seedSizeBytes);
        tree->haveNode[revealed[i]] = 1;
        input += params->seedSizeBytes;
    }

    expandSeedsMem(tree, salt, repIndex, params);

Exit:
    free(revealed);
    return ret;
}

static int verifyMerkleTreeMem(tree_t* tree,
    uint8_t** leafData, uint8_t* salt, Memparamset_t* params)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;

    /* Copy the leaf data, where we have it. The actual data being committed to has already been
     * hashed, according to the spec. */
    for (size_t i = 0; i < tree->numLeaves; i++) {
        if (leafData[i] != NULL) {
            if (tree->haveNode[firstLeaf + i] == 1) {
                return -1;  /* A leaf was assigned from the prover for a node we've recomputed */
            }

            if (leafData[i] != NULL) {
                memcpy(tree->nodes[firstLeaf + i], leafData[i], tree->dataSize);
                tree->haveNode[firstLeaf + i] = 1;
            }
        }
    }

    /* At this point the tree has some of the leaves, and some intermediate nodes
     * Work up the tree, computing all nodes we don't have that are missing. */
    for (int i = (int)tree->numNodes; i > 0; i--) {
        computeParentHashMem(tree, i, salt, params);
    }

    /* Fail if the root was not computed. */
    if (!tree->haveNode[0]) {
        return -1;
    }

    return 0;
}

static int checkChallengePlist(const uint16_t* challengeP,const uint8_t** Plist,Memparamset_t* params) {
    for (size_t t = 0; t < params->numOpenedRounds; t++) {
        uint16_t Ptemp = 0x0000;
        for (size_t N = 0; N < params->memberSize; N++) {
            Ptemp ^= (uint16_t)Plist[t][N];
        }
        if (memcmp(&Ptemp, &challengeP[t],sizeof(uint16_t)) != 0) {
            return -1;
        }
    }
    return 0;
}

int verify_memberf(Memparamset_t* params, const uint8_t* message, size_t message_len, signatureMem_t* sig, uint8_t* Xlist)
{
    int ret = checkChallengePlist(sig->challengeP, sig->Plist, params);
    if (ret != 0) {
        ret = -1;
        printf("Challenge Plist does not Match, signature invalid\n");
        goto Exit;
    }

    commitments_t** C = malloc((params->memberSize + 1) * sizeof(commitments_t*));
    for (size_t N = 0; N < params->memberSize + 1; N++) {
        C[N] = allocateCommitmentsMem(params, 0);
    }
    commitments_t Ch = { 0 };
    commitments_t Cv = { 0 };
    inputs_t inputs;
    Zinter_t Zinter;
    msgs_t** msgs;
    shares_t** Key_mask;
    shares_t** Plaintext_mask;

#pragma omp parallel sections
    {
#pragma omp section
        inputs = allocateInputsMem(params);
#pragma omp section
        Zinter = allocateZinter(params);
#pragma omp section
        msgs = malloc((params->memberSize + 1) * sizeof(msgs_t*));
#pragma omp section
        Key_mask = malloc(params->numMPCRounds * sizeof(shares_t*));
#pragma omp section
        Plaintext_mask = malloc(params->numMPCRounds * sizeof(shares_t*));
    }
    for (int i = 0; i <= params->memberSize; i++) {
        msgs[i] = allocateMsgsMem(params, i);
    }

    tree_t* treeCv = createTree(params->numMPCRounds, params->digestSizeBytes);
    size_t challengeSizeBytes = params->numOpenedRounds * sizeof(uint16_t);
    uint16_t* challengeC = malloc(challengeSizeBytes);
    uint16_t* challengeP = malloc(challengeSizeBytes);
    allocateCommitments2Mem(&Ch, params, params->numMPCRounds);
    allocateCommitments2Mem(&Cv, params, params->numMPCRounds);

    tree_t* iRemaskSeedsTree = generateSeedsMem(params->numMPCRounds, sig->RemaskRootSeed, sig->salt, 0, params);
    tree_t** RemaskSeedsTree = malloc(params->numMPCRounds * sizeof(tree_t*));
    RemaskTape_t* Remasktapes = malloc(params->numMPCRounds * sizeof(RemaskTape_t));
    uint8_t** iRemaskSeeds = getLeaves(iRemaskSeedsTree);

    tree_t* iRootSeedsTree = createTree(params->numMPCRounds, params->digestSizeBytes);
    tree_t** iSeedsTree = malloc(params->numMPCRounds * sizeof(tree_t*));
    MemTree_t* SeedsTree = allocateMemTree(params);
    randomTape_t** tapes = allocateTape_Pointer(params);

    ret = reconstructSeedsMem(iRootSeedsTree, sig->challengeC, params->numOpenedRounds, sig->iRootSeedInfo, sig->iRootSeedInfoLen, sig->salt, 0, params);
    if (ret != 0) {
        ret = -1;
        goto Exit;
    }

    /* 用sig中的信息填充种子 */
#pragma omp parallel
    {
        int t;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            RemaskSeedsTree[t] = generateSeedsMem(params->memberSize, iRemaskSeeds[t], sig->salt, t, params);
            createRandomRemaskTapesMem(&Remasktapes[t], getLeaves(RemaskSeedsTree[t]), sig->salt, t, params);

            if (!contains(sig->challengeC, params->numOpenedRounds, t)) {
                iSeedsTree[t] = generateSeedsMem((params->memberSize + 1), getLeaf(iRootSeedsTree, t), sig->salt, t, params);
                uint8_t** iSeeds = getLeaves(iSeedsTree[t]);
                for (size_t N = 0; N < params->memberSize + 1; N++) {
                    SeedsTree[t][N] = generateSeedsMem(params->numMPCParties, iSeeds[N], sig->salt, t, params);//343->N+1
                    createRandomTapesMem(&tapes[t][N], getLeaves(SeedsTree[t][N]), sig->salt, t, params, N);   //343->N+1->64
                }
            }
            else {
                //iSeedsTree[t] = createTree(params->memberSize + 1, params->seedSizeBytes);
                size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
                uint16_t hideList[1];
                hideList[0] = sig->challengeP[P_index];
                SeedsTree[t][0] = createTree(params->numMPCParties, params->seedSizeBytes);
                ret = reconstructSeedsMem(SeedsTree[t][0], hideList, 1,
                    sig->Omproof[t].seedInfo, sig->Omproof[t].seedInfoLen,
                    sig->salt, t, params);
                createRandomTapesMem(&tapes[t][0], getLeaves(SeedsTree[t][0]), sig->salt, t, params, 0);
                for (size_t N = 1; N < params->memberSize + 1; N++) {
                    SeedsTree[t][N] = createTree(params->numMPCParties, params->seedSizeBytes);
                    hideList[0] = (uint16_t)sig->Plist[P_index][N - 1];
                    ret = reconstructSeedsMem(SeedsTree[t][N], hideList, 1,
                        sig->Reproofs[t].seedInfo[N - 1], sig->Reproofs[t].seedInfoLen[N - 1],
                        sig->salt, t, params);
                    createRandomTapesMem(&tapes[t][N], getLeaves(SeedsTree[t][N]), sig->salt, t, params, N);
                }
                if (ret != 0) {
                    printf("Failed to reconstruct seeds for round %lu\n", t);
                    ret = -1;
                }
            }
        }
    }
    if (ret == -1) {
        goto Exit;
    }

    /* 运行oneTime part的预处理阶段，计算aux并承诺*/

    size_t last = params->numMPCParties - 1;
    uint8_t** inter_mask = allocateInterMask(params);
#pragma omp parallel
    {
        int t;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            if (!contains(sig->challengeC, params->numOpenedRounds, t)) {
                uint8_t auxBit[OM_MAX_AUX_BYTES];
                computeAuxTapeMem(&tapes[t][0], inter_mask[t], params, 0);
                for (int j = 0; j < last; j++) {
                    commitMem(C[0][t].hashes[j], getLeaf(SeedsTree[t][0], j), NULL, sig->salt, t, j, params, 0);
                }
                getAuxBitsMem(auxBit, &tapes[t][0], params, 0);
                commitMem(C[0][t].hashes[last], getLeaf(SeedsTree[t][0], last), auxBit, sig->salt, t, last, params, 0);
            }
            else {
                size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
                size_t unopened = sig->challengeP[P_index];
                for (size_t j = 0; j < last; j++) {
                    if (j != unopened) {
                        commitMem(C[0][t].hashes[j], getLeaf(SeedsTree[t][0], j), NULL, sig->salt, t, j, params, 0);
                    }
                }
                if (last != unopened) {
                    commitMem(C[0][t].hashes[last], getLeaf(SeedsTree[t][0], last), sig->Omproof[t].aux, sig->salt, t, last, params, 0);
                }
                memcpy(C[0][t].hashes[unopened], sig->Omproof[t].C, params->digestSizeBytes);
            }
        }

#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            if (!contains(sig->challengeC, params->numOpenedRounds, t)) {
                uint8_t auxBit2[OM_MAX_AUX_BYTES];
                for (size_t N = 1; N <= params->memberSize; N++) {
                    GetZinterTape(Remasktapes[t].tape[N - 1], inter_mask[t], &tapes[t][N], params);
                    computeAuxTapeMem(&tapes[t][N], NULL, params, N);
                    for (size_t j = 0; j < last; j++) {
                        commitMem(C[N][t].hashes[j], getLeaf(SeedsTree[t][N], j), NULL, sig->salt, t, j, params, N);
                    }
                    getAuxBitsMem(auxBit2, &tapes[t][N], params, N);
                    commitMem(C[N][t].hashes[last], getLeaf(SeedsTree[t][N], last), auxBit2, sig->salt, t, last, params, N);
                }
            }
            else {
                size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
                for (size_t N = 1; N <= params->memberSize; N++) {
                    size_t unopened = (uint16_t)sig->Plist[P_index][N - 1];
                    for (size_t j = 0; j < last; j++) {
                        commitMem(C[N][t].hashes[j], getLeaf(SeedsTree[t][N], j), NULL, sig->salt, t, j, params, N);
                    }
                    if (last != unopened) {
                        commitMem(C[N][t].hashes[last], getLeaf(SeedsTree[t][N], last), sig->Reproofs[t].aux[N - 1], sig->salt, t, last, params, N);
                    }
                    memcpy(C[N][t].hashes[unopened], sig->Reproofs[t].C[N - 1], params->digestSizeBytes);
                }
            }
        }
    }

    /* 运行oneTime part的在线阶段，生成Z_inter */
    size_t tapeLengthBytes = 2 * params->OmAndSizeBytes + 2 * params->stateSizeBytes;
#pragma omp parallel
    {
        int t;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            if (!contains(sig->challengeC, params->numOpenedRounds, t)) {
                Cv.hashes[t] = NULL;
            }
            else {
                size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
                size_t unopened = sig->challengeP[P_index];
                if (unopened != last) {
                    setAuxBitsMem(&tapes[t][0], sig->Omproof[t].aux, params, 0);
                }
                memset(tapes[t][0].tape[unopened], 0, tapeLengthBytes);
                memcpy(msgs[0][t].msgs[unopened], sig->Omproof[t].msgs, params->OmAndSizeBytes);
                msgs[0][t].unopened = unopened;

                Key_mask[t] = allocateShares(params->stateSizeBits);
                tapesToWords(Key_mask[t], &tapes[t][0]);

                Plaintext_mask[t] = allocateShares(params->stateSizeBits);
                tapesToWords(Plaintext_mask[t], &tapes[t][0]);

                int rv = simulateOnline_SM4((uint32_t*)sig->Omproof[t].input, (uint32_t*)sig->Omproof[t].input + params->stateSizeWords, Key_mask[t], Plaintext_mask[t], &tapes[t][0], &msgs[0][t], params, 0, (uint32_t*)Zinter[t], NULL, NOCHALLENGE);
                if (rv != 0) {
                    printf("MPC simulation failed, aborting signature\n");
                    ret = -1;
                }
            }
        }
    }
    if (ret == -1) {
        goto Exit;
    }

    /* 运行resume part的预处理阶段,计算aux并承诺 */
#pragma omp parallel
    {
        int t;

#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            commitMem_h(Ch.hashes[t], C, t, params);
        }


        /* 运行resume part的在线阶段 */
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            if (!contains(sig->challengeC, params->numOpenedRounds, t)) {

            }
            else {
                size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
                for (size_t N = 1; N <= params->memberSize; N++) {
                    size_t unopened = (uint16_t)sig->Plist[P_index][N - 1];
                    if (unopened != last) {
                        setAuxBitsMem(&tapes[t][N], sig->Reproofs[t].aux[N - 1], params, N);
                        setMaskfix(&tapes[t][N], sig->Reproofs[t].maskfix[N - 1], params);
                    }
                    


                    memcpy(msgs[N][t].msgs[unopened], sig->Reproofs[t].msgs[N - 1], params->ReAndSizeBytes + params->stateSizeBytes);
                    msgs[N][t].unopened = unopened;

                    uint32_t maskedKey[4];
                    xor_array(maskedKey, (uint32_t*)Remasktapes[t].tape[N - 1], (uint32_t*)Zinter[t], params->stateSizeWords);
                    tapesToWords(Key_mask[t], &tapes[t][N]);

                    uint32_t maskedplaintext[4];
                    xor_array(maskedplaintext, (uint32_t*)Remasktapes[t].tape[N - 1] + params->stateSizeWords, (uint32_t*)Zinter[t] + params->stateSizeWords, params->stateSizeWords);
                    tapesToWords(Plaintext_mask[t], &tapes[t][N]);

                    uint32_t pubkey[4];
                    memcpy(pubkey, Xlist + (N - 1) * X_BYTES + PK_BYTES, PK_BYTES);

                    int rv;
                    rv = simulateOnline_SM4(maskedKey, maskedplaintext, Key_mask[t], Plaintext_mask[t], &tapes[t][N], &msgs[N][t], params, N, (uint32_t*)Zinter[t], pubkey, NOCHALLENGE);
                    if (rv != 0) {
                        printf("MPC simulation failed, aborting signature\n");
                        ret = -1;
                    }
                }
                commitMem_v(Cv.hashes[t], sig->Omproof[t].input, msgs, t, params);
            }
        }
    }
    if (ret == -1) {
        goto Exit;
    }

    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = getMissingLeavesListMem(sig->challengeC, params);
    ret = addMerkleNodes(treeCv, missingLeaves, missingLeavesSize, sig->cvInfo, sig->cvInfoLen);
    free(missingLeaves);
    if (ret != 0) {
        ret = -1;
        goto Exit;
    }

    ret = verifyMerkleTreeMem(treeCv, Cv.hashes, sig->salt, params);
    if (ret != 0) {
        ret = -1;
        goto Exit;
    }

    HCPMem(challengeC, challengeP, &Ch, treeCv->nodes[0], sig->salt, Xlist, message, message_len, params);

    if (memcmp(sig->challengeC, challengeC, challengeSizeBytes) != 0 ||
        memcmp(sig->challengeP, challengeP, challengeSizeBytes) != 0) {
        printf("Challenge does not Match, signature invalid\n");
        ret = -1;
        goto Exit;
    }

    ret = EXIT_SUCCESS;

Exit:

#pragma omp parallel
    {
        int t, N, j;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            if (!contains(sig->challengeC, params->numOpenedRounds, t)) {
                freeTree(iSeedsTree[t]);
            }
            else {
                freeShares(Key_mask[t]);
                freeShares(Plaintext_mask[t]);
            }
            freeTree(RemaskSeedsTree[t]);
            free(Remasktapes[t].tape);

            for (N = 0; N < params->memberSize + 1; N++) {
                freeRandomTape(&tapes[t][N]);
                freeTree(SeedsTree[t][N]);
            }
        }
#pragma omp for schedule(guided)
        for (N = 0; N < params->memberSize + 1; N++) {
            freeCommitments(C[N]);
            freeMsgs(msgs[N]);
        }
    }
#pragma omp parallel sections
    {
#pragma omp section
        freeTree(iRootSeedsTree);
#pragma omp section
        free(iSeedsTree);
#pragma omp section
        free(RemaskSeedsTree);
#pragma omp section
        freeTree(iRemaskSeedsTree);
#pragma omp section
        free(tapes);
#pragma omp section
        free(SeedsTree);
#pragma omp section
        free(Remasktapes);
#pragma omp section
        free(msgs);
#pragma omp section
        freeTree(treeCv);
#pragma omp section
        freeCommitments2(&Ch);
#pragma omp section
        freeCommitments2(&Cv);
#pragma omp section
        free(C);
#pragma omp section
        free(inputs);
#pragma omp section
        free(Zinter);
#pragma omp section
        free(Plaintext_mask);
#pragma omp section
        free(Key_mask);
#pragma omp section
        free(challengeC);
#pragma omp section
        free(challengeP);
#pragma omp section
        free(inter_mask);
    }

    return ret;
}


int sign_memberpf(Memparamset_t* params, uint32_t* sk, uint32_t* pk, uint32_t* plaintext,
    const uint8_t* message, size_t message_len, signatureMem_t* sig, uint8_t* Xlist, size_t X_index, int* PreT, int* OnT)
{
    int ret = 0;

    /* 计算salt RemaskRootSeed RootSeed */
    clock_t start, end;

    start = clock();
    uint8_t* saltAndRootAndRemask = malloc(params->saltSizeBytes + params->seedSizeBytes * 2);
    computeSaltAndSeed(saltAndRootAndRemask, params->saltSizeBytes + params->seedSizeBytes * 2, sk, pk, plaintext, message, message_len, Xlist, params);
    memcpy(sig->salt, saltAndRootAndRemask, params->saltSizeBytes);
    memcpy(sig->RemaskRootSeed, saltAndRootAndRemask + params->saltSizeBytes, params->seedSizeBytes);

    //获取iRootSeed和iRemaskSeed
    tree_t* iRootSeedsTree;
    tree_t* iRemaskSeedsTree;
    uint8_t** iRootSeeds;
    uint8_t** iRemaskSeeds;
    tree_t** iSeedsTree;
    MemTree_t* SeedsTree;
    randomTape_t** tapes;
    tree_t** RemaskSeedsTree;
    RemaskTape_t* Remasktapes;

#pragma omp parallel sections
    {
#pragma omp section
        {
            iRootSeedsTree = generateSeedsMem(params->numMPCRounds, saltAndRootAndRemask + params->saltSizeBytes + params->seedSizeBytes, sig->salt, 0, params);
            iRootSeeds = getLeaves(iRootSeedsTree);

        }
#pragma omp section
        {
            iRemaskSeedsTree = generateSeedsMem(params->numMPCRounds, sig->RemaskRootSeed, sig->salt, 0, params);
            iRemaskSeeds = getLeaves(iRemaskSeedsTree);
        }
#pragma omp section
            free(saltAndRootAndRemask);
//tapes[MPCRounds][memberSize+1][64]
#pragma omp section
            iSeedsTree = malloc(params->numMPCRounds * sizeof(tree_t*));
#pragma omp section
            SeedsTree = allocateMemTree(params);
#pragma omp section
            tapes = allocateTape_Pointer(params);
//RemaskTapes[MPCRounds][memberSize]
#pragma omp section
            RemaskSeedsTree = malloc(params->numMPCRounds * sizeof(tree_t*));
#pragma omp section
            Remasktapes = malloc(params->numMPCRounds * sizeof(RemaskTape_t));
    }


    uint8_t** inter_mask = allocateInterMask(params);
#pragma omp parallel
    {
        int t, N;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            iSeedsTree[t] = generateSeedsMem((params->memberSize + 1), iRootSeeds[t], sig->salt, t, params);    //343 
            RemaskSeedsTree[t] = generateSeedsMem(params->memberSize, iRemaskSeeds[t], sig->salt, t, params);
            uint8_t** iSeeds = getLeaves(iSeedsTree[t]);

            //SeedsTree[t] = malloc(sizeof(MemTree_t));
            //SeedsTree[t] = malloc((params->memberSize + 1) * sizeof(tree_t*));
            createRandomRemaskTapesMem(&Remasktapes[t], getLeaves(RemaskSeedsTree[t]), sig->salt, t, params);

            for (N = 0; N < params->memberSize + 1; N++) {
                SeedsTree[t][N] = generateSeedsMem(params->numMPCParties, iSeeds[N], sig->salt, t, params);//343->N+1
                createRandomTapesMem(&tapes[t][N], getLeaves(SeedsTree[t][N]), sig->salt, t, params, N);   //343->N+1->64
            }
        }

        /* 运行oneTime part的预处理阶段，计算aux */
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            computeAuxTapeMem(&tapes[t][0],(uint32_t*)inter_mask[t], params, 0);
        }
    }

    /* Commit to seeds and aux bits for one part round */
    commitments_t** C = malloc((params->memberSize + 1) * sizeof(commitments_t*));
#pragma omp parallel
    {
        int t, N, j;
#pragma omp for schedule(guided)
        for (N = 0; N < params->memberSize + 1; N++) {
            C[N] = allocateCommitmentsMem(params, 0);
        }

#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            for (j = 0; j < params->numMPCParties - 1; j++) {
                commitMem(C[0][t].hashes[j], getLeaf(SeedsTree[t][0], j), NULL, sig->salt, t, j, params, 0);
            }
            uint8_t auxBits[OM_MAX_AUX_BYTES];
            size_t last = params->numMPCParties - 1;
            getAuxBitsMem(auxBits, &tapes[t][0], params, 0);
            commitMem(C[0][t].hashes[last], getLeaf(SeedsTree[t][0], last), auxBits, sig->salt, t, last, params, 0);
        }
    }


    /* 运行resume part的预处理阶段,计算aux */
#pragma omp parallel
    {
        int t, N;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            for (N = 1; N <= params->memberSize; N++) {
                GetZinterTape(Remasktapes[t].tape[N - 1], inter_mask[t], &tapes[t][N], params);
                computeAuxTapeMem(&tapes[t][N], NULL, params, N);
            }
        }
    }

    end = clock();
    double acc = (double)(end - start);
    *PreT = (int)acc;
    printf("预处理阶段：%lf ms\n", acc);
    start = clock();


    /* 运行oneTime part的在线阶段，生成Z_inter */
    inputs_t inputs;
    Zinter_t Zinter;
    msgs_t** msgs;
    shares_t** Key_mask;
    shares_t** Plaintext_mask;

#pragma omp parallel sections
    {
#pragma omp section
        inputs = allocateInputsMem(params);
#pragma omp section
        Zinter = allocateZinter(params);
#pragma omp section
        msgs = malloc((params->memberSize + 1) * sizeof(msgs_t*));
#pragma omp section
        Key_mask = malloc(params->numMPCRounds * sizeof(shares_t*));
#pragma omp section
        Plaintext_mask = malloc(params->numMPCRounds * sizeof(shares_t*));
    }

#pragma omp parallel
    {
        int i, t;
#pragma omp for schedule(guided)
        for (i = 0; i <= params->memberSize; i++) {
            msgs[i] = allocateMsgsMem(params, i);
        }

#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            uint32_t* maskedKey = (uint32_t*)inputs[t];
            Key_mask[t] = allocateShares(params->stateSizeBits);
            tapesToWords(Key_mask[t], &tapes[t][0]);
            reconstructShares(maskedKey, Key_mask[t]);
            xor_array(maskedKey, maskedKey, sk, params->stateSizeWords);

            uint32_t* maskedplaintext = (uint32_t*)inputs[t] + params->stateSizeWords;
            Plaintext_mask[t] = allocateShares(params->stateSizeBits);
            tapesToWords(Plaintext_mask[t], &tapes[t][0]);
            reconstructShares(maskedplaintext, Plaintext_mask[t]);
            xor_array(maskedplaintext, maskedplaintext, plaintext, params->stateSizeWords);

            int rv = simulateOnline_SM4(maskedKey, maskedplaintext, Key_mask[t], Plaintext_mask[t], &tapes[t][0], &msgs[0][t], params, 0, (uint32_t*)Zinter[t], NULL, NOCHALLENGE);
            if (rv != 0) {
                printf("MPC simulation failed, aborting signature\n");
                ret = -1;
            }
        }
    }



    /* Commit to seeds and aux bits for resume part round */

#pragma omp parallel
    {
        int t, N, j;
        size_t last = params->numMPCParties - 1;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            for (N = 1; N <= params->memberSize; N++) {
                for (j = 0; j < params->numMPCParties - 1; j++) {
                    commitMem(C[N][t].hashes[j], getLeaf(SeedsTree[t][N], j), NULL, sig->salt, t, j, params, N);
                }
                uint8_t auxBits2[OM_MAX_AUX_BYTES];
                getAuxBitsMem(auxBits2, &tapes[t][N], params, N);
                commitMem(C[N][t].hashes[last], getLeaf(SeedsTree[t][N], last), auxBits2, sig->salt, t, last, params, N);
            }
        }
    }

    /* 运行resume part的在线阶段 */
    challengelist_t Plist = allocateChallengePlist(params);

#pragma omp parallel
    {
        int t, N;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            for (N = 1; N < params->memberSize + 1; N++) {
                uint32_t maskedKey[4];
                xor_array(maskedKey, (uint32_t*)Remasktapes[t].tape[N - 1], (uint32_t*)Zinter[t], params->stateSizeWords);
                tapesToWords(Key_mask[t], &tapes[t][N]);

                uint32_t maskedplaintext[4];
                xor_array(maskedplaintext, (uint32_t*)Remasktapes[t].tape[N - 1] + params->stateSizeWords, (uint32_t*)Zinter[t] + params->stateSizeWords, params->stateSizeWords);
                tapesToWords(Plaintext_mask[t], &tapes[t][N]);

                int rv;
                uint32_t pubkey[4];
                memcpy(pubkey, Xlist + (N - 1) * X_BYTES + PK_BYTES, PK_BYTES);

                if (N == X_index)
                    rv = simulateOnline_SM4(maskedKey, maskedplaintext, Key_mask[t], Plaintext_mask[t], &tapes[t][N], &msgs[N][t], params, N, (uint32_t*)Zinter[t], pubkey, NOCHALLENGE);
                else
                    rv = simulateOnline_SM4(maskedKey, maskedplaintext, Key_mask[t], Plaintext_mask[t], &tapes[t][N], &msgs[N][t], params, N, (uint32_t*)Zinter[t], pubkey, ((uint8_t*)Plist[t])[N - 1]);
                if (rv != 0) {
                    printf("MPC simulation failed, aborting signature\n");
                    ret = -1;
                }
            }
        }
    }

    commitments_t Ch;
    commitments_t Cv;
#pragma omp parallel sections
    {
#pragma omp section
        allocateCommitments2Mem(&Ch, params, params->numMPCRounds);
#pragma omp section
        allocateCommitments2Mem(&Cv, params, params->numMPCRounds);
    }

#pragma omp parallel
    {
        int t;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            commitMem_h(Ch.hashes[t], C, t, params);
            commitMem_v(Cv.hashes[t], inputs[t], msgs, t, params);
        }
    }

    /* Create a Merkle tree with Cv as the leaves */
    tree_t* treeCv = createTree(params->numMPCRounds, params->digestSizeBytes);
    buildMerkleTreeMem(treeCv, Cv.hashes, sig->salt, params);

    /* Compute the challenge; two lists of integers */
    uint16_t* challengeC = sig->challengeC;
    uint16_t* challengeP = sig->challengeP;
    HCPMem(challengeC, challengeP, &Ch, treeCv->nodes[0], sig->salt, Xlist, message, message_len, params);

    sig->Plist = FIX_PLIST(challengeC, challengeP, Plist, X_index, params);
    free(Plist);

    /* Send information required for checking commitments with Merkle tree.
     * The commitments the verifier will be missing are those not in challengeC. */
    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = getMissingLeavesListMem(challengeC, params);
    size_t cvInfoLen = 0;
    uint8_t* cvInfo = openMerkleTree(treeCv, missingLeaves, missingLeavesSize, &cvInfoLen);
    sig->cvInfo = cvInfo;
    sig->cvInfoLen = cvInfoLen;
    free(missingLeaves);

    /* Reveal iSeeds for unopned rounds, those in {0..T-1} \ ChallengeC. */
    sig->iRootSeedInfo = malloc(params->numMPCRounds * params->seedSizeBytes);
    sig->iRootSeedInfoLen = revealSeedsMem(iRootSeedsTree, challengeC, params->numOpenedRounds,
        sig->iRootSeedInfo, params->numMPCRounds * params->seedSizeBytes, params);
    sig->iRootSeedInfo = realloc(sig->iRootSeedInfo, sig->iRootSeedInfoLen);


    /* Assemble the proof */

    OmproofMem_t* Omproof = sig->Omproof;
    ReproofMem_t* Reproof = sig->Reproofs;

#pragma omp parallel
    {
        int t;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {
            if (contains(challengeC, params->numOpenedRounds, t)) {

                size_t P_index = indexOf(challengeC, params->numOpenedRounds, t);

                //Omproof
                allocateOmProof(&Omproof[t], params);
                uint16_t hideList[1];
                hideList[0] = challengeP[P_index];
                Omproof[t].seedInfo = malloc(params->numMPCParties * params->seedSizeBytes);
                Omproof[t].seedInfoLen = revealSeedsMem(SeedsTree[t][0], hideList, 1, Omproof[t].seedInfo, params->numMPCParties * params->seedSizeBytes, params);
                Omproof[t].seedInfo = realloc(Omproof[t].seedInfo, Omproof[t].seedInfoLen);

                size_t last = params->numMPCParties - 1;
                if (hideList[0] != last) {
                    getAuxBitsMem(Omproof[t].aux, &tapes[t][0], params, 0);
                }
                memcpy(Omproof[t].input, inputs[t], params->stateSizeBytes * 2);
                memcpy(Omproof[t].msgs, msgs[0][t].msgs[hideList[0]], params->OmAndSizeBytes);
                memcpy(Omproof[t].C, C[0][t].hashes[hideList[0]], params->digestSizeBytes);

                //Reproof
                allocateReProof(&Reproof[t], params);
                for (size_t N = 1; N < params->memberSize + 1; N++) {
                    hideList[0] = sig->Plist[P_index][N - 1];
                    Reproof[t].seedInfo[N - 1] = malloc(params->numMPCParties * params->seedSizeBytes);
                    Reproof[t].seedInfoLen[N - 1] = revealSeedsMem(SeedsTree[t][N], hideList, 1, Reproof[t].seedInfo[N - 1], params->numMPCParties * params->seedSizeBytes, params);
                    Reproof[t].seedInfo[N - 1] = realloc(Reproof[t].seedInfo[N - 1], Reproof[t].seedInfoLen[N - 1]);

                    if (hideList[0] != last) {
                        getAuxBitsMem(Reproof[t].aux[N - 1], &tapes[t][N], params, N);
                        getMaskfix(Reproof[t].maskfix[N - 1], &tapes[t][N], params);
                    }
                    
                    memcpy(Reproof[t].msgs[N - 1], msgs[N][t].msgs[hideList[0]], params->ReAndSizeBytes + params->stateSizeBytes);
                    memcpy(Reproof[t].C[N - 1], C[N][t].hashes[hideList[0]], params->digestSizeBytes);
                }
            }
        }
    }
#pragma omp parallel
    {
        int t, N, j;
#pragma omp for schedule(guided)
        for (t = 0; t < params->numMPCRounds; t++) {

            freeTree(iSeedsTree[t]);
            freeTree(RemaskSeedsTree[t]);
            free(Remasktapes[t].tape);
            freeShares(Key_mask[t]);
            freeShares(Plaintext_mask[t]);
            for (N = 0; N < params->memberSize + 1; N++) {
                freeRandomTape(&tapes[t][N]);
                freeTree(SeedsTree[t][N]);
            }
        }
#pragma omp for schedule(guided)
        for (N = 0; N < params->memberSize + 1; N++) {
            freeCommitments(C[N]);
            freeMsgs(msgs[N]);
        }
    }
#pragma omp parallel sections
    {
#pragma omp section
        freeTree(iRootSeedsTree);
#pragma omp section
        free(iSeedsTree);
#pragma omp section
        free(RemaskSeedsTree);
#pragma omp section
        freeTree(iRemaskSeedsTree);
#pragma omp section
        free(tapes);
#pragma omp section
        free(SeedsTree);
#pragma omp section
        free(Remasktapes);
#pragma omp section
        free(msgs);
#pragma omp section
        freeTree(treeCv);
#pragma omp section
        freeCommitments2(&Ch);
#pragma omp section
        freeCommitments2(&Cv);
#pragma omp section
        free(C);
#pragma omp section
        free(inputs);
#pragma omp section
        free(Zinter);
#pragma omp section
        free(Plaintext_mask);
#pragma omp section
        free(Key_mask);
#pragma omp section
        free(inter_mask);
    }

    end = clock();
    acc = (double)(end - start);
    printf("在线阶段：%lf ms\n", acc);
    *OnT = (int)acc;

#if 0
    printf("\n-----------------\n\nSelf-Test, trying to verify signature:\n");
    start = clock();
    ret = verify_memberf(params, message, message_len, sig, Xlist);
    end = clock();
    acc = (double)(end - start);
    printf("验证时间：%lf ms\n", acc);
    if (ret != 0) {
        printf("Verification failed; signature invalid\n");
        ret = -1;
    }
    else {
        printf("Verification succeeded\n\n");
    }
    printf("-----------------\n\nSelf-Test complete\n");

#endif

    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
    return 0;
}

static int inRange(uint16_t* list, size_t len, size_t low, size_t high)
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] > high || list[i] < low) {
            return 0;
        }
    }
    return 1;
}

static int unique(uint16_t* list, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        for (size_t j = 0; j < len; j++) {
            if (j != i && list[i] == list[j]) {
                return 0;
            }
        }
    }
    return 1;
}

static int arePaddingBitsZero(uint8_t* data, size_t byteLength, size_t bitLength)
{
    for (size_t i = bitLength; i < byteLength * 8; i++) {
        uint8_t bit_i = getBit(data, i);
        if (bit_i != 0) {
            return 0;
        }
    }
    return 1;
}

static size_t revealSeedsSizeMem(size_t numNodes, uint16_t* hideList, size_t hideListSize, Memparamset_t* params)
{
    tree_t* tree = createTree(numNodes, params->seedSizeBytes);
    size_t numNodesRevealed = 0;
    size_t* revealed = getRevealedNodes(tree, hideList, hideListSize, &numNodesRevealed);

    freeTree(tree);
    free(revealed);
    return numNodesRevealed * params->seedSizeBytes;
}

static size_t* getRevealedMerkleNodes(tree_t* tree, uint16_t* missingLeaves,
    size_t missingLeavesSize, size_t* outputSize)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;
    uint8_t* missingNodes = calloc(tree->numNodes, 1);

    /* Mark leaves that are missing */
    for (size_t i = 0; i < missingLeavesSize; i++) {
        missingNodes[firstLeaf + missingLeaves[i]] = 1;
    }

    /* For the nonleaf nodes, if both leaves are missing, mark it as missing too */
    int lastNonLeaf = getParent(tree->numNodes - 1);
    for (int i = lastNonLeaf; i > 0; i--) {
        if (!exists(tree, i)) {
            continue;
        }
        if (exists(tree, 2 * i + 2)) {
            if (missingNodes[2 * i + 1] && missingNodes[2 * i + 2]) {
                missingNodes[i] = 1;
            }
        }
        else {
            if (missingNodes[2 * i + 1]) {
                missingNodes[i] = 1;
            }
        }
    }

    /* For each missing leaf node, add the highest missing node on the path
     * back to the root to the set to be revealed */
    size_t* revealed = malloc(tree->numLeaves * sizeof(size_t));
    size_t pos = 0;
    for (size_t i = 0; i < missingLeavesSize; i++) {
        size_t node = missingLeaves[i] + firstLeaf;  /* input is leaf indexes, translate to nodes */
        do {
            if (!missingNodes[getParent(node)]) {
                if (!contains_size_t(revealed, pos, node)) {
                    revealed[pos] = node;
                    pos++;
                }
                break;
            }
        } while ((node = getParent(node)) != 0);
    }

    free(missingNodes);
    *outputSize = pos;
    return revealed;
}


static size_t openMerkleTreeSizeMem(size_t numNodes, uint16_t* missingLeaves, size_t missingLeavesSize, Memparamset_t* params)
{

    tree_t* tree = createTree(numNodes, params->digestSizeBytes);
    size_t revealedSize = 0;
    size_t* revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, &revealedSize);

    freeTree(tree);
    free(revealed);

    return revealedSize * params->digestSizeBytes;
}

int deserializeSignatureMem(signatureMem_t* sig, const uint8_t* sigBytes, size_t sigBytesLen, Memparamset_t* params)
{
    /* Read the challenge and salt */
    size_t bytesRequired = 4 * params->numOpenedRounds + params->memberSize * params->numOpenedRounds + params->saltSizeBytes;

    if (sigBytesLen < bytesRequired) {
        return EXIT_FAILURE;
    }

    memcpy(sig->challengeC, sigBytes, 2 * params->numOpenedRounds);
    sigBytes += 2 * params->numOpenedRounds;
    memcpy(sig->challengeP, sigBytes, 2 * params->numOpenedRounds);
    sigBytes += 2 * params->numOpenedRounds;

    sig->Plist = allocatePlist(params);
    for (size_t t = 0; t < params->numOpenedRounds; t++) {
        memcpy(sig->Plist[t], sigBytes, params->memberSize);
        sigBytes += params->memberSize;
    }
    memcpy(sig->salt, sigBytes, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numOpenedRounds; i++) {
        sig->challengeC[i] = fromLittleEndian(sig->challengeC[i]);
        sig->challengeP[i] = fromLittleEndian(sig->challengeP[i]);
    }

    if (!inRange(sig->challengeC, params->numOpenedRounds, 0, params->numMPCRounds - 1)) {
        return EXIT_FAILURE;
    }
    if (!unique(sig->challengeC, params->numOpenedRounds)) {
        return EXIT_FAILURE;
    }
    if (!inRange(sig->challengeP, params->numOpenedRounds, 0, params->numMPCParties - 1)) {
        return EXIT_FAILURE;
    }

    /* Add size of iSeeds tree data */
    sig->iRootSeedInfoLen = revealSeedsSizeMem(params->numMPCRounds, sig->challengeC, params->numOpenedRounds, params);
    bytesRequired += sig->iRootSeedInfoLen;

    bytesRequired += params->seedSizeBytes;

    /* Add the size of the Cv Merkle tree data */
    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = getMissingLeavesListMem(sig->challengeC, params);
    sig->cvInfoLen = openMerkleTreeSizeMem(params->numMPCRounds, missingLeaves, missingLeavesSize, params);
    bytesRequired += sig->cvInfoLen;
    free(missingLeaves);

    /* Compute the number of bytes required for the proofs */
    uint16_t hideList[1] = { 0 };
    size_t seedInfoLen = revealSeedsSizeMem(params->numMPCParties, hideList, 1, params);
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);

            //Omproof
            size_t P_t = sig->challengeP[P_index];
            bytesRequired += seedInfoLen;   //seedInfo
            if (P_t != (params->numMPCParties - 1)) {
                bytesRequired += params->OmAndSizeBytes;    //aux
            }
            bytesRequired += params->digestSizeBytes;       //C
            bytesRequired += params->stateSizeBytes * 2;    //input
            bytesRequired += params->OmAndSizeBytes;        //msgs

            //Reproofs
            for (size_t N = 0; N < params->memberSize; N++) {
                size_t hideP = sig->Plist[P_index][N];
                bytesRequired += seedInfoLen;   //seedInfo
                if (hideP != (params->numMPCParties - 1)) {
                    bytesRequired += params->ReAndSizeBytes;        //aux
                    bytesRequired += params->stateSizeBytes * 2;    //maskfix
                }
                bytesRequired += params->digestSizeBytes;           //C
                bytesRequired += params->ReAndSizeBytes + params->stateSizeBytes;        //msgs
            }
        }
    }

    /* Fail if the signature does not have the exact number of bytes we expect */
    if (sigBytesLen != bytesRequired) {
        printf("%s: sigBytesLen = %lu, expected bytesRequired = %lu\n", __func__, sigBytesLen, bytesRequired);
        return EXIT_FAILURE;
    }

    /* RemaskSeed、iRootSeeds、cvInfo、inter_mask*/
    memcpy(sig->RemaskRootSeed, sigBytes, params->seedSizeBytes);
    sigBytes += params->seedSizeBytes;

    sig->iRootSeedInfo = malloc(sig->iRootSeedInfoLen);
    memcpy(sig->iRootSeedInfo, sigBytes, sig->iRootSeedInfoLen);
    sigBytes += sig->iRootSeedInfoLen;

    sig->cvInfo = malloc(sig->cvInfoLen);
    memcpy(sig->cvInfo, sigBytes, sig->cvInfoLen);
    sigBytes += sig->cvInfoLen;

    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
            size_t last = params->numMPCParties - 1;

            //Omproof
            size_t P_t = sig->challengeP[P_index];
            allocateOmProof(&sig->Omproof[t], params);
            sig->Omproof[t].seedInfoLen = seedInfoLen;
            sig->Omproof[t].seedInfo = malloc(sig->Omproof[t].seedInfoLen);
            memcpy(sig->Omproof[t].seedInfo, sigBytes, sig->Omproof[t].seedInfoLen);    //seedInfo
            sigBytes += sig->Omproof[t].seedInfoLen;

            if (P_t != last) {
                memcpy(sig->Omproof[t].aux, sigBytes, params->OmAndSizeBytes);          //aux
                sigBytes += params->OmAndSizeBytes;
            }
            memcpy(sig->Omproof[t].input, sigBytes, params->stateSizeBytes * 2);            //input
            sigBytes += params->stateSizeBytes * 2;
            memcpy(sig->Omproof[t].msgs, sigBytes, params->OmAndSizeBytes);             //msgs
            sigBytes += params->OmAndSizeBytes;
            memcpy(sig->Omproof[t].C, sigBytes, params->digestSizeBytes);               //C
            sigBytes += params->digestSizeBytes;

            //Reproof
            allocateReProof(&sig->Reproofs[t], params);
            for (size_t N = 0; N < params->memberSize; N++) {
                size_t hideP = sig->Plist[P_index][N];
                sig->Reproofs[t].seedInfoLen[N] = seedInfoLen;
                sig->Reproofs[t].seedInfo[N] = malloc(sig->Reproofs[t].seedInfoLen[N]);
                memcpy(sig->Reproofs[t].seedInfo[N], sigBytes, sig->Reproofs[t].seedInfoLen[N]);    //seedInfo
                sigBytes += sig->Reproofs[t].seedInfoLen[N];
                if (hideP != last) {
                    memcpy(sig->Reproofs[t].aux[N], sigBytes, params->ReAndSizeBytes);              //aux
                    sigBytes += params->ReAndSizeBytes;
                    memcpy(sig->Reproofs[t].maskfix[N], sigBytes, params->stateSizeBytes * 2);      //maskfix
                    sigBytes += params->stateSizeBytes * 2;
                }
                memcpy(sig->Reproofs[t].C[N], sigBytes, params->digestSizeBytes);
                sigBytes += params->digestSizeBytes;
                memcpy(sig->Reproofs[t].msgs[N], sigBytes, params->stateSizeBytes + params->ReAndSizeBytes);
                sigBytes += params->stateSizeBytes + params->ReAndSizeBytes;
            }
        }
    }

    return EXIT_SUCCESS;
}

int serializeSignatureMem(const signatureMem_t* sig, uint8_t* sigBytes, size_t sigBytesLen, Memparamset_t* params)
{
    uint8_t* sigBytesBase = sigBytes;

    /* Compute the number of bytes required for the signature */
    size_t bytesRequired = 4 * params->numOpenedRounds + params->memberSize*params->numOpenedRounds + params->saltSizeBytes; /* challenge and salt */

    bytesRequired += sig->iRootSeedInfoLen;                                     /* Encode only iSeedInfo, the length will be recomputed by deserialize */
    bytesRequired += params->seedSizeBytes;
    bytesRequired += sig->cvInfoLen;

    for (size_t t = 0; t < params->numMPCRounds; t++) {   /* proofs */
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);

            //Omproof
            size_t P_t = sig->challengeP[P_index];
            bytesRequired += sig->Omproof[t].seedInfoLen;   //seedInfo
            if (P_t != (params->numMPCParties - 1)) {
                bytesRequired += params->OmAndSizeBytes;    //aux
            }
            bytesRequired += params->digestSizeBytes;       //C
            bytesRequired += params->stateSizeBytes * 2;    //input
            bytesRequired += params->OmAndSizeBytes;        //msgs

            //Reproofs
            for (size_t N = 0; N < params->memberSize; N++) {
                size_t hideP = sig->Plist[P_index][N];
                bytesRequired += sig->Reproofs[t].seedInfoLen[N];   //seedInfo
                if (hideP != (params->numMPCParties - 1)) {
                    bytesRequired += params->ReAndSizeBytes;        //aux
                    bytesRequired += params->stateSizeBytes * 2;    //maskfix
                }
                
                bytesRequired += params->digestSizeBytes;           //C
                bytesRequired += params->ReAndSizeBytes + params->stateSizeBytes;        //msgs
            }
        }
    }

    if (sigBytesLen < bytesRequired) {
        return -1;
    }

    /* challengeC 、 challengeP、 Plist、 salt */
    memcpy(sigBytes, sig->challengeC, 2 * params->numOpenedRounds); 
    uint16_t* challengeC = (uint16_t*)sigBytes;
    sigBytes += 2 * params->numOpenedRounds;
    memcpy(sigBytes, sig->challengeP, 2 * params->numOpenedRounds);
    uint16_t* challengeP = (uint16_t*)sigBytes;
    sigBytes += 2 * params->numOpenedRounds;
    for (size_t t = 0; t < params->numOpenedRounds; t++) {
        memcpy(sigBytes, sig->Plist[t], params->memberSize);
        sigBytes += params->memberSize;
    }
    
    memcpy(sigBytes, sig->salt, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numOpenedRounds; i++) {
        challengeC[i] = fromLittleEndian(sig->challengeC[i]);
        challengeP[i] = fromLittleEndian(sig->challengeP[i]);
    }

    /* RemaskSeed、iRootSeeds、cvInfo */
    memcpy(sigBytes, sig->RemaskRootSeed, params->seedSizeBytes);
    sigBytes += params->seedSizeBytes;
    memcpy(sigBytes, sig->iRootSeedInfo, sig->iRootSeedInfoLen);
    sigBytes += sig->iRootSeedInfoLen;
    memcpy(sigBytes, sig->cvInfo, sig->cvInfoLen);
    sigBytes += sig->cvInfoLen;

    /* Write the proofs */
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
            size_t last = params->numMPCParties - 1;
            //Omproof
            size_t P_t = sig->challengeP[P_index];
            memcpy(sigBytes, sig->Omproof[t].seedInfo, sig->Omproof[t].seedInfoLen);    //seedInfo
            sigBytes += sig->Omproof[t].seedInfoLen;
            if (P_t != last) {
                memcpy(sigBytes, sig->Omproof[t].aux, params->OmAndSizeBytes);          //aux
                sigBytes += params->OmAndSizeBytes;
            }
            memcpy(sigBytes, sig->Omproof[t].input, params->stateSizeBytes * 2);            //input
            sigBytes += params->stateSizeBytes * 2;
            memcpy(sigBytes, sig->Omproof[t].msgs, params->OmAndSizeBytes);             //msgs
            sigBytes += params->OmAndSizeBytes;                  
            memcpy(sigBytes, sig->Omproof[t].C, params->digestSizeBytes);               //C
            sigBytes += params->digestSizeBytes;    

            //Reproof
            for (size_t N = 0; N < params->memberSize; N++) {
                size_t hideP = sig->Plist[P_index][N];
                memcpy(sigBytes, sig->Reproofs[t].seedInfo[N], sig->Reproofs[t].seedInfoLen[N]);    //seedInfo
                sigBytes += sig->Reproofs[t].seedInfoLen[N];
                if (hideP != last) {
                    memcpy(sigBytes, sig->Reproofs[t].aux[N], params->ReAndSizeBytes);              //aux
                    sigBytes += params->ReAndSizeBytes;
                    memcpy(sigBytes, sig->Reproofs[t].maskfix[N], params->stateSizeBytes * 2);      //maskfix
                    sigBytes += params->stateSizeBytes * 2;
                }
                memcpy(sigBytes, sig->Reproofs[t].C[N], params->digestSizeBytes);
                sigBytes += params->digestSizeBytes;
                memcpy(sigBytes, sig->Reproofs[t].msgs[N], params->stateSizeBytes + params->ReAndSizeBytes);
                sigBytes += params->stateSizeBytes + params->ReAndSizeBytes;
            }
        }
    }

    return (int)(sigBytes - sigBytesBase);
}