/*! @file picnic_impl.h
 *  @brief This is the main implementation file of the signature scheme. All of
 *  the LowMC MPC code is here as well as lower-level versions of sign and
 *  verify that are called by the signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_IMPL_H
#define PICNIC_IMPL_H

#include <stdint.h>
#include <stddef.h>
//#define _CRTDBG_MAP_ALLOC
//#include<crtdbg.h>
// 密钥扩展算法的常数FK 
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// 密钥扩展算法的固定参数CK 
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};


typedef enum {
    TRANSFORM_FS = 0,
    TRANSFORM_UR = 1,
    TRANSFORM_INVALID = 255
} transform_t;

typedef struct paramset_t {
    uint32_t numRounds;
    uint32_t numSboxes;
    uint32_t stateSizeBits;         // 128
    uint32_t stateSizeBytes;
    uint32_t stateSizeWords;
    uint32_t andSizeBytes;
    uint32_t UnruhGWithoutInputBytes;
    uint32_t UnruhGWithInputBytes;
    uint32_t numMPCRounds;          // T
    uint32_t numOpenedRounds;       // u
    uint32_t numMPCParties;         // N
    uint32_t seedSizeBytes;
    uint32_t saltSizeBytes;
    uint32_t digestSizeBytes;
    uint32_t tempSizeBits;
    uint32_t tempSizeBytes;
    uint32_t tempSizeWords;
    transform_t transform;
} paramset_t;

typedef struct proof_t {
    uint8_t* seed1;
    uint8_t* seed2;
    uint32_t* inputShare;     // Input share of the party which does not derive it from the seed (not included if challenge is 0)
    uint8_t* communicatedBits;
    uint8_t* view3Commitment;
    uint8_t* view3UnruhG;     // we include the max length, but we will only serialize the bytes we use
} proof_t;

typedef struct signature_t {
    proof_t* proofs;
    uint8_t* challengeBits;     // has length numBytes(numMPCRounds*2)
    uint8_t* salt;              // has length saltSizeBytes
} signature_t;

int sign_picnic1(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, signature_t* sig, paramset_t* params);
int verify(signature_t* sig, const uint32_t* pubKey, const uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, paramset_t* params);

void allocateSignature(signature_t* sig, paramset_t* params);
void freeSignature(signature_t* sig, paramset_t* params);

uint8_t getChallenge(const uint8_t* challenge, size_t round);
void printHex(const char* s, const uint8_t* data, size_t len);

void LowMCEnc(const uint32_t* plaintext, uint32_t* output, uint32_t* key, paramset_t* params);
void SM4Enc(uint32_t* plaintext, uint32_t* ciphertext, uint32_t* Key);
/* Returns the number of bytes written on success, or -1 on error */
int serializeSignature(const signature_t* sig, uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params);
/* Returns EXIT_SUCCESS on success or EXIT_FAILURE on error */
int deserializeSignature(signature_t* sig, const uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params);

/*
 * Fill buf with len random bytes.
 * Returns 1 on success, 0 on failure
 */
int random_bytes_default(uint8_t* buf, size_t len);

/* Return the number of bytes required to represent the given number of bits */
uint32_t numBytes(uint32_t numBits);


uint32_t ceil_log2(uint32_t x);


uint8_t getBit(const uint8_t* array, uint32_t bitNumber);
uint8_t getBitFromWordArray(const uint32_t* array, uint32_t bitNumber);
void setBit(uint8_t* bytes, uint32_t bitNumber, uint8_t val);
void setBitInWordArray(uint32_t* array, uint32_t bitNumber, uint8_t val);
uint8_t parity(uint32_t* data, size_t len);
void xor_array(uint32_t* out, const uint32_t * in1, const uint32_t * in2, uint32_t length);

uint32_t L1(uint32_t a);
uint32_t L2(uint32_t a);

#endif /* PICNIC_IMPL_H */
