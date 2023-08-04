/*! @file example.c
 *  @brief This is an example program to demonstrate how to use the
 *  Picnic signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "picnic.h"
#include <stdio.h>
#include <memory.h>
#include <inttypes.h>
#include <Windows.h>
#include <time.h>
#include "MemberProof.h"
#define _CRTDBG_MAP_ALLOC
#include<stdlib.h>
#include<crtdbg.h>

#define MSG_LEN 500

int PQSM4Example(picnic_params_t parameters)
{
    clock_t start, end;
    picnic_publickey_t pk;
    picnic_privatekey_t sk;

    printf("\n\nPQSM4 example \n");

    fprintf(stdout, "Generating key... ");
    fflush(stdout);
    int ret  = picnic_keygen(parameters, &pk, &sk);

    if (ret != 0) {
        printf("PQSM4_keygen failed\n");
        exit(-1);
    }
    printf(" success\n");

    uint8_t message[MSG_LEN];
    memset(message, 0x01, sizeof(message));
    uint8_t* signature = NULL;

    size_t signature_len = picnic_signature_size(parameters);
    signature = (uint8_t*)malloc(signature_len);
    if (signature == NULL) {
        printf("failed to allocate signature\n");
        exit(-1);
    }
    fprintf(stdout, "Max signature length %" PRIuPTR " bytes\n", signature_len);

    fprintf(stdout, "Signing a %d byte message... \n", MSG_LEN);
    fflush(stdout);

    start = clock();

    ret = picnic_sign(&sk, message, sizeof(message), signature, &signature_len);
    if (ret != 0) {
        printf("PQSM4_sign failed\n");
        exit(-1);
    }
    printf(" success, signature is %d bytes\n", (int)signature_len);

    /* signature_len has the exact number of bytes used */
    if (signature_len < picnic_signature_size(parameters)) {
        uint8_t* newsig = realloc(signature, signature_len);
        if (newsig == NULL) {
            printf("failed to re-size signature\n");
            /* Not an error, we can continue with signature */
        }
        else {
            signature = newsig;
        }
    }
    end = clock();
    double acc = (double)(end - start);
    //printf("%lf ms\n", acc);

    fprintf(stdout, "Verifying signature... ");
    fflush(stdout);

    

    start = clock();

    ret = picnic_verify(&pk, message, sizeof(message), signature, signature_len);
    if (ret != 0) {
        printf("picnic_verify failed\n");
        exit(-1);
    }
    printf(" success\n");

    end = clock();
    acc = (double)(end - start);
    printf("验证用时：%lf ms\n", acc);

    free(signature);

    return 0;
}

int MemberProofExample(picnic_params_t parameters,size_t MemberSize) {
    clock_t start, end;
    MemKey Key;

    printf("\n\nPQSM4-EPID example with %llu MemberSize\n", MemberSize);

    //获取设置信息
    Memparamset_t paramset;
    int ret = Memget_param_set(&paramset, MemberSize);

    //生成消息
    uint8_t message[MSG_LEN];
    memset(message, 0x01, sizeof(message));
    uint8_t* signature = NULL;

    //生成群成员公私钥
    fprintf(stdout, "Generating key... ");
    fflush(stdout);
    ret = MemProof_keygen(&paramset,&Key);
    if (ret != 0) {
        printf("PQSM4-EPID_keygen failed\n");
        exit(-1);
    }

    //随机生成群成员公私钥承诺集合X
    size_t XSize = MemberSize * 16 * 2;//群成员承诺： {pk, challenge}
    uint8_t* X = (uint8_t*)malloc(XSize);
    if (random_bytes_default(X, XSize) != 0) {
        printf("Failed to generate X list\n");
        return -1;
    }

    //此处假设为第二个成员
    size_t X_index = 1;
    memcpy(X + 16 * 2 * (X_index - 1), &Key, 16 * 2);

    //获取签名最大大小
    size_t signature_len = MemberProof_size(MemberSize);
    signature = (uint8_t*)malloc(signature_len);
    if (signature == NULL) {
        printf("failed to allocate signature\n");
        exit(-1);
    }
    fprintf(stdout, "Max signature length %llu bytes\n", signature_len);

    fprintf(stdout, "Signing a %d byte message... \n", MSG_LEN);
    fflush(stdout);

    //签名
    start = clock();
    int PreT, OnT;
    ret = MemberProof_sign(&paramset, &Key, message, MSG_LEN, signature, &signature_len, X, X_index, &PreT, &OnT);
    if (ret != 0) {
        printf("PQSM4-EPID_sign failed\n");
        exit(-1);
    }
    printf(" success, signature is %d bytes\n", (int)signature_len);

    if (signature_len < MemberProof_size(parameters)) {
        uint8_t* newsig = realloc(signature, signature_len);
        if (newsig == NULL) {
            printf("failed to re-size signature\n");
        }
        else {
            signature = newsig;
        }
    }
    end = clock();
    double acc = (double)(end - start);
    //printf("%lf ms\n", acc);

    //验证
    fprintf(stdout, "Verifying signature... ");
    fflush(stdout);

    start = clock();
    ret = MemberProof_verify(&paramset, message, MSG_LEN, signature, signature_len, X);
    if (ret != 0) {
        printf("PQSM4-EPID_verify failed\n");
        exit(-1);
    }
    printf(" success\n");

    end = clock();
    acc = (double)(end - start);
    printf("验证用时：%lf ms\n", acc);

    free(signature);
    free(X);
    _CrtDumpMemoryLeaks();
    return 0;
}

int main(int argc, char** argv)
{

    picnic_params_t params = 7;
    //PQSM4Example(params); //PQSM4
    //for (int i = 2; i < 64; i*=2) {
    //    MemberProofExample(params, (size_t)i);   //PQSM4-EPID
    //}
    uint8_t* key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    uint32_t* a = malloc(16);
    uint32_t* b = malloc(16);
    memset(a, 0x61, 16);
    SM4Enc(a, b, key);

    Sleep(10000000);
}