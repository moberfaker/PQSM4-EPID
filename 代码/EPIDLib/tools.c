#include "tools.h"
#include <picnic.h>
#include "typeDefine.h"
#include <picnic_impl.h>
#include <picnic2_impl.h>

int random_bytes(uint8_t* buf, size_t len)
{
    if (len > ULONG_MAX) {
        return -3;
    }

    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return -4;
    }
    return 0;
}



void EPIDMessageSend(Msgs* Msgs)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 0x02);
    size_t len = Msgs->message_len;
    printf("(%llu Bytes)", len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        printf("%02X ", Msgs->message[i]);

    }
    printf("\n");
    SetConsoleTextAttribute(hConsole, 0x0f);
}



void EPIDprintHex(const char* s, const uint8_t* data, size_t len)
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        printf("%02X", data[i]);
    }
    printf("\n");
}



int keygenerator(PubKey* pk, PriKey* sk, int No_c) {

    if (pk == NULL) {
        printf("public key is NULL\n");
        return -1;
    }

    if (sk == NULL) {
        printf("private key is NULL\n");
        return -1;
    }

    /* Generate a random challenge block */
    if (No_c) {         //如果没有指定挑战值
        memset(pk, 0x00, sizeof(PubKey));
        memset(sk, 0x00, sizeof(PriKey));
        if (random_bytes(pk->c, CHALLENGE_SIZE_BYTE) != 0) {
            PRINT_DEBUG(("Failed to generate challenge\n"));
            return -1;
        }
    }
    else
    {
        memset(pk->pk, 0x00, SM4_SIZE_BYTE);
        memset(sk, 0x00, sizeof(PriKey));
    }


    /* Generate a private key */
    if (random_bytes(sk->sk, SM4_SIZE_BYTE) != 0) {
        PRINT_DEBUG(("Failed to generate private key\n"));
        return -1;
    }

    /* Compute the ciphertext */
    SM4Enc(pk->c, pk->pk, sk->sk);

#ifdef SHOW
    if (No_c)    EPIDprintHex("  Generate c\t", pk->c, SM4_SIZE_BYTE);
    else         EPIDprintHex("  Given    c\t", pk->c, SM4_SIZE_BYTE);
    EPIDprintHex("  Generate sk\t", sk->sk, SM4_SIZE_BYTE);
    EPIDprintHex("  Generate pk\t", pk->pk, SM4_SIZE_BYTE);

#endif // SHOW

    return 0;
}



/* Msgs初始化 */
int MsgsInit(Msgs* Msgs, size_t ByteLen)
{
    if (Msgs->message != NULL && Msgs->message != 0xCCCCCCCCCCCCCCCC)
        free(Msgs->message);
    Msgs->message = (uint8_t*)malloc(ByteLen);
    if (Msgs->message == NULL) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        printf("Message malloc failed\n");
        SetConsoleTextAttribute(hConsole, 0x0f);
        return -1;
    }
    memset(Msgs->message, 0x00, ByteLen);
    memcpy(Msgs->message + 8, &ByteLen, 8);
    Msgs->message_len = 0;
    return 1;
}



void Msgsmemcpy(Msgs* Msgs, const void* Src, size_t Size)
{
    memcpy(Msgs->message + Msgs->message_len, Src, Size);
    Msgs->message_len += Size;
}


void Msgsdelfront(Msgs* message, size_t Size)
{
    size_t temp = message->message_len;
    message->message = message->message + Size;
    message->message_len -= Size;
}


int find_in_X(PubKey* pk, uint32_t index, uint64_t* X, uint16_t X_len) {
    if (memcmp(pk, &X[index * 2], X_EACH_SIZE_BYTE) == 0)
        return index;       //按index索引、在X中
    else
    {
        for (int i = 0; i < X_len; i++) {

            if (memcmp(pk, &X[i * 4], X_EACH_SIZE_BYTE) == 0)
                return i;   //索引改变，仍在X中
        }
        return -1;          //不在X中
    }
}
