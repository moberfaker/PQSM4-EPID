#ifndef KKWSIGN_H
#define KKWSIGN_H
#include <picnic.h>
#include "typeDefine.h"
#include <picnic_impl.h>
#include <picnic2_impl.h>

int EPID_picnic_sign(PriKey* sk, PubKey* pk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len);

int EPID_picnic_verify(PubKey* pk, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len);

uint8_t* EPID_MemberProof_sign(PriKey* sk, PubKey* pk, size_t* signature_len, const uint8_t* message, size_t message_len, size_t Member_Size, uint8_t* X, size_t X_index, int* PreT, int* OnT);

int EPID_MemberProof_verify(uint8_t* signature, uint8_t* signature_len, const uint8_t* message, size_t message_len, size_t Member_Size, uint8_t* X);
#endif // !KKWSIGN_H
