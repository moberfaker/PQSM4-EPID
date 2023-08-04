#include "KKWsign.h"
#include <MemberProof.h>
#include <string.h>
#include <time.h>

int EPID_picnic_sign(PriKey* sk, PubKey* pk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len)
{
    int ret;
    paramset_t paramset;

    ret = get_param_set(Picnic2_L1_FS, &paramset);
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to initialize parameter set\n");
        fflush(stderr);
        return -1;
    }

    signature2_t* sig = (signature2_t*)malloc(sizeof(signature2_t));
    allocateSignature2(sig, &paramset);
    if (sig == NULL) {
        return -1;
    }
    ret = sign_picnic2((uint32_t*)sk->sk, (uint32_t*)pk->pk, (uint32_t*)pk->c, message,
        message_len, sig, &paramset);
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to create signature\n");
        fflush(stderr);
        freeSignature2(sig, &paramset);
        free(sig);
        return -1;
    }
    ret = serializeSignature2(sig, signature, *signature_len, &paramset);
    if (ret == -1) {
        fprintf(stderr, "Failed to serialize signature\n");
        fflush(stderr);
        freeSignature2(sig, &paramset);
        free(sig);
        return -1;
    }
    *signature_len = ret;

    freeSignature2(sig, &paramset);
    free(sig);

    return 0;
}



int EPID_picnic_verify(PubKey* pk, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len)
{
    int ret;

    paramset_t paramset;

    ret = get_param_set(Picnic2_L1_FS, &paramset);
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to initialize parameter set\n");
        fflush(stderr);
        return -1;
    }

    signature2_t* sig = (signature2_t*)malloc(sizeof(signature2_t));
    allocateSignature2(sig, &paramset);
    if (sig == NULL) {
        return -1;
    }

    ret = deserializeSignature2(sig, signature, signature_len, &paramset);
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to deserialize signature\n");
        fflush(stderr);
        freeSignature2(sig, &paramset);
        free(sig);
        return -1;
    }

    ret = verify_picnic2(sig, (uint32_t*)pk->pk,
        (uint32_t*)pk->c, message, message_len, &paramset);
    if (ret != EXIT_SUCCESS) {
        /* Signature is invalid, or verify function failed */
        freeSignature2(sig, &paramset);
        free(sig);
        return -1;
    }

    freeSignature2(sig, &paramset);
    free(sig);

    return 0;
}

uint8_t* EPID_MemberProof_sign(PriKey* sk, PubKey* pk, size_t* signature_len, const uint8_t* message, size_t message_len, size_t Member_Size, uint8_t* X, size_t X_index, int* PreT, int* OnT)
{
    int ret;
    clock_t start, end;
    Memparamset_t paramset;
    MemKey Key;

    ret = Memget_param_set(&paramset, Member_Size);

    memcpy(Key.c, pk->c, CHALLENGE_SIZE_BYTE);
    memcpy(Key.pk, pk->pk, SM4_SIZE_BYTE);
    memcpy(Key.sk, sk->sk, SM4_SIZE_BYTE);

    *signature_len = MemberProof_size(Member_Size);
    uint8_t* sig = (uint8_t*)malloc(*signature_len);
    if (sig == NULL) {
        printf("failed to allocate signature\n");
        return 0;
    }
    fprintf(stdout, "Max signature length %llu bytes\n", *signature_len);

    fprintf(stdout, "Signing a %llu byte message... \n", message_len);
    fflush(stdout);

    start = clock();
    ret = MemberProof_sign(&paramset, &Key, message, message_len, sig, signature_len, X, X_index + 1, PreT, OnT);
    if (ret != 0) {
        printf("MemberProof_sign failed\n");
        return 0;
    }
    printf(" success, signature is %d bytes\n", *signature_len);

    if (*signature_len < MemberProof_size(Member_Size)) {
        uint8_t* newsig = realloc(sig, *signature_len);
        if (newsig == NULL) {
            printf("failed to re-size signature\n");
        }
        else {
            sig = newsig;
        }
    }
    end = clock();
    double acc = (double)(end - start);
    printf("%lf ms\n", acc);

    return sig;
}


int EPID_MemberProof_verify(uint8_t* signature, uint8_t* signature_len, const uint8_t* message, size_t message_len, size_t Member_Size, uint8_t* X)
{
    fprintf(stdout, "Verifying signature... ");
    fflush(stdout);

    clock_t start, end;
    Memparamset_t paramset;

    int ret = Memget_param_set(&paramset, Member_Size);

    start = clock();
    ret = MemberProof_verify(&paramset, message, message_len, signature, signature_len, X);
    if (ret != 0) {
        printf("MemberProof_verify failed\n");
        return -1;
    }
    printf(" success\n");

    end = clock();
    double acc = (double)(end - start);
    printf("%lf ms\n", acc);
    return 0;
}