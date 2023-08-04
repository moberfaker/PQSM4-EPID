/*! @file picnic2_impl.c
 *  @brief This is the main file of the signature scheme for the Picnic2
 *  parameter sets.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "picnic_impl.h"
#include "picnic2_impl.h"
#include "picnic.h"
#include "platform.h"
#include "lowmc_constants.h"
#include "picnic_types.h"
#include "hash.h"
#include "tree.h"
#include <omp.h>
#include <time.h>

#define OMP_KKW
#define MIN(a,b)            (((a) < (b)) ? (a) : (b))

//#define MAX_AUX_BYTES ((LOWMC_MAX_AND_GATES + LOWMC_MAX_KEY_BITS) / 8 + 1)
#define MAX_AUX_BYTES ((SM4_MAX_AND_GATES + SM4_KEY_BITS) / 8 + 1)

/* Number of leading zeroes of x.
 * From the book
 * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
 * http://www.hackersdelight.org/hdcodetxt/nlz.c.txt
 */
static int32_t nlz(uint32_t x)      // x的前端0数
{
    uint32_t n;

    if (x == 0) return (32);
    n = 1;
    if((x >> 16) == 0) {n = n + 16; x = x << 16;}
    if((x >> 24) == 0) {n = n + 8;  x = x << 8;}
    if((x >> 28) == 0) {n = n + 4;  x = x << 4;}
    if((x >> 30) == 0) {n = n + 2;  x = x << 2;}
    n = n - (x >> 31);

    return n;
}

uint32_t ceil_log2(uint32_t x)      // x的有效位数
{
    if (x == 0) {
        return 0;
    }
    return 32 - nlz(x - 1);
}

static void createRandomTapes(randomTape_t* tapes, uint8_t** seeds, uint8_t* salt, size_t t, paramset_t* params)    // 生成随机数
{
    HashInstance ctx;                                                               // 上下文

    size_t tapeSizeBytes = 2 * params->andSizeBytes + params->stateSizeBytes;       // 随机带字节大小

    allocateRandomTape(tapes, params);                                              // 随机带分配？
    for (size_t i = 0; i < params->numMPCParties; i++) {                            // 哈希主seed, salt, t, i得到tape[i]
        HashInit(&ctx, params, HASH_PREFIX_NONE);
        HashUpdate(&ctx, seeds[i], params->seedSizeBytes);
        HashUpdate(&ctx, salt, params->saltSizeBytes);
        HashUpdateIntLE(&ctx, t);                                                   // 
        HashUpdateIntLE(&ctx, i);
        HashFinal(&ctx);

        HashSqueeze(&ctx, tapes->tape[i], tapeSizeBytes);
    }
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

/* 对于输入位b = 0或1，return the word of all b bits, i.e.,
 * extend(1) = 0xFFFFFFFFFFFFFFFF
 * extend(0) = 0x0000000000000000
 * 假设输入总是0或1，如果不成立，在输入中添加“& 1”
 */

static uint64_t extend(uint8_t bit)     // 带掩码的值
{
    return ~(bit - 1);
}

uint64_t parity64(uint64_t x)    // 64bit的奇偶校验位，奇数位1输出1，偶数位1输出0
{
    uint64_t y = x ^ (x >> 1);

    y ^= (y >> 2);
    y ^= (y >> 4);
    y ^= (y >> 8);
    y ^= (y >> 16);
    y ^= (y >> 32);
    return y & 1;
}

static uint64_t aux_mpc_AND(uint64_t a, uint64_t b, randomTape_t* tapes, paramset_t* params)    // 与门
{
    uint64_t mask_a = parity64(a);                      // a掩码值：a的奇偶校验
    uint64_t mask_b = parity64(b);                      // b掩码值：a的奇偶校验
    uint64_t fresh_output_mask = tapesToWord(tapes);    // tapesToWord：从16个tapes中获取pos处的比特值组成返回值share，pos++

    uint64_t and_helper = tapesToWord(tapes);           // tapesToWord：从16个tapes中获取pos处的比特值组成返回值share，pos++
                                                        // 猜测：and_helper = aux

    /* 将最后一方的helper值份额归零，根据输入掩码计算它；然后更新磁带 */
    setBit((uint8_t*)&and_helper, params->numMPCParties - 1, 0);        // setBit：Set a specific bit in a byte array to a given value
    uint64_t aux_bit = (mask_a & mask_b) ^ parity64(and_helper);        // aux = a & b ^ parity(and_helper)
    size_t lastParty = tapes->nTapes - 1;
    setBit(tapes->tape[lastParty], tapes->pos - 1, (uint8_t)aux_bit);   // tape[lastParty][pos-1] = aux_bit

    return fresh_output_mask;                                           // 返回从16个tapes中获取pos处的比特值组成的share
}

static void aux_mpc_sbox(shares_t* state, randomTape_t* tapes, paramset_t* params)
{
    for (size_t i = 0; i < params->numSboxes * 3; i += 3) {     // 
        uint64_t a = state->shares[i + 2];                      // a = shares[i+2]
        uint64_t b = state->shares[i + 1];                      // b = shares[i+1]
        uint64_t c = state->shares[i];                          // c = shares[i]

        uint64_t ab = aux_mpc_AND(a, b, tapes, params);         // ab = 从16个tapes中获取pos处的比特值组成返回值share，pos++
        uint64_t bc = aux_mpc_AND(b, c, tapes, params);         // bc = 从16个tapes中获取pos处的比特值组成返回值share，pos++
        uint64_t ca = aux_mpc_AND(c, a, tapes, params);         // ca = 从16个tapes中获取pos处的比特值组成返回值share，pos++

        state->shares[i + 2] = a ^ bc;                          // shares[i+2] = a ^ bc
        state->shares[i + 1] = a ^ b ^ ca;                      // shares[i+1] = a ^ b ^ ca
        state->shares[i] = a ^ b ^ c ^ ab;                      // shares[i]   = a ^ b ^ c ^ ab
    }
}

static void mpc_xor_masks(shares_t* out, const shares_t* a, const shares_t* b)  // 异或
{
    assert(out->numWords == a->numWords && a->numWords == b->numWords);         // 断言

    for (size_t i = 0; i < out->numWords; i++) {                                // i < shares_numwords
        out->shares[i] = a->shares[i] ^ b->shares[i];                           // 注意：out->shares, a->shares, b->shares
    }
}

static void aux_matrix_mul(shares_t* output, const shares_t* vec, const uint32_t* matrix, shares_t* tmp_output, paramset_t* params) // 复杂版
{
    for (size_t i = 0; i < params->stateSizeBits; i++) {
        uint64_t new_mask_i = 0;                                                    // mask_i = 0
        for (uint32_t j = 0; j < params->stateSizeBits / 8; j++) {                  // 分8种情况讨论
            uint8_t matrix_byte = ((uint8_t*)matrix)[i * (params->stateSizeBits / 8) + j];
            new_mask_i ^= vec->shares[j * 8] & extend((matrix_byte >> 7) & 1);      // matrix_byte最高位，与1，取反，与shares[j*8]，异或mask_i
            new_mask_i ^= vec->shares[j * 8 + 1] & extend((matrix_byte >> 6) & 1);  // matrix_byte次高位，与1，取反，与shares[j*8+1]，异或mask_i
            new_mask_i ^= vec->shares[j * 8 + 2] & extend((matrix_byte >> 5) & 1);
            new_mask_i ^= vec->shares[j * 8 + 3] & extend((matrix_byte >> 4) & 1);
            new_mask_i ^= vec->shares[j * 8 + 4] & extend((matrix_byte >> 3) & 1);
            new_mask_i ^= vec->shares[j * 8 + 5] & extend((matrix_byte >> 2) & 1);
            new_mask_i ^= vec->shares[j * 8 + 6] & extend((matrix_byte >> 1) & 1);
            new_mask_i ^= vec->shares[j * 8 + 7] & extend(matrix_byte & 1);
        }
        tmp_output->shares[i] = new_mask_i;
    }

    copyShares(output, tmp_output);     // output->share = tmp_output->share
}

#if 1
/* aux_matrix_mul的简化版本，更接近规范中的描述 */
static void aux_matrix_mul_simple(shares_t* output, const shares_t* vec, const uint32_t* matrix, shares_t* tmp_output, paramset_t* params)
{
    for (size_t i = 0; i < params->stateSizeBits; i++) {

        uint64_t new_mask_i = 0;
        for (uint32_t j = 0; j < params->stateSizeBits; j++) {
            uint8_t matrix_bit = getBit((uint8_t*)matrix, i * params->stateSizeBits + j);
            new_mask_i ^= vec->shares[j] & extend(matrix_bit);
        }
        tmp_output->shares[i] = new_mask_i;
    }

    copyShares(output, tmp_output);
}
#endif



/*======================================================================================================================================================================*/

static void Aux_Xor1(shares_t* state, shares_t* Key, uint64_t i, paramset_t* params) {		// int
    for (uint64_t j = 0; j < params->tempSizeBits; j++) {
        state->shares[(j + i * 32) % 128] = Key->shares[(j + 96 + i * 32) % 128] ^ Key->shares[(j + 32 + i * 32) % 128] ^ Key->shares[(j + 64 + i * 32) % 128];
    }
}

static void Aux_Xor2(shares_t* state, uint64_t r, paramset_t* params)
{
    for (int i = 0; i < params->tempSizeBits; i++)
    {
        state->shares[(r * 32 + i) % 128] ^= state->shares[(r * 32 + i + 32) % 128] ^ state->shares[(r * 32 + i + 64) % 128] ^ state->shares[(r * 32 + i + 96) % 128];
    }
}

static uint64_t Aux_AND(uint64_t a, uint64_t b, randomTape_t* tapes, paramset_t* params)
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

    //printf("\n%x", (uint8_t)(parity64(and_helper) ^ aux_bit ) ^ (mask_a & mask_b));

    return fresh_output_mask;                                           // 返回从16个tapes中获取pos处的比特值组成的share
}

static void Aux_Sbox(shares_t* state_masks, randomTape_t* tapes, uint64_t r, paramset_t* params) {
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
static void Aux_L22(shares_t* state, shares_t* Key, uint64_t i, paramset_t* params) {
    Aux_L2(state, i);
    for (int k = 0; k < params->tempSizeBits; k++) {
        Key->shares[(i * 32 + k) % 128] ^= state->shares[(i * 32 + k) % 128];
        state->shares[(i * 32 + k) % 128] = Key->shares[(i * 32 + k) % 128];
    }
}

static void Aux_L11(shares_t* state, shares_t* temp, uint64_t r, paramset_t* params) {
    Aux_L1(state, r);
    for (int i = 0; i < params->tempSizeBits; i++)
    {
        state->shares[(r * 32 + i) % 128] ^= temp->shares[i];
    }
}
/*======================================================================================================================================================================*/




/* 输入为1次并行重复的随即磁带，如tapes[t]
 * 用与门输出的掩码值更新所有随机磁带的成员,
 * 并计算第n方的份额，使与门的不变量带有掩码值
 */
static void computeAuxTape(randomTape_t* tapes, paramset_t* params)
{
    shares_t* state = allocateShares(params->stateSizeBits);
    shares_t* key = allocateShares(params->stateSizeBits);
    shares_t* temp = allocateShares(params->tempSizeBits);
    //shares_t* roundKey = allocateShares(params->stateSizeBits);
    uint32_t xx[4];

    tapesToWords(key, tapes);                                       // 从16个tapes中获取pos处的比特值组成返回值，赋值每个key[w]

    // 下一行是两个操作的组合，它进行了简化，因为 XORs 除以常数在预处理期间是一个NOP（空指令）。
     //roundKey = key * KMatrix[0]
     //state = roundKey + plaintext
    //aux_matrix_mul(state, key, KMatrix(0, params), tmp1, params);

    for (uint32_t r = 0; r < params->numRounds; r++) {
        for (int i = 0; i < params->tempSizeBits; i++)              // temp = state
        {
            temp->shares[i] = state->shares[(r * 32 + i) % 128];
        }
        Aux_Xor1(state, key, r, params);						    // state = Key[1] ^ Key[2] ^ Key[3]
        Aux_Sbox(state, tapes, r, params);							// state = S(state)
        Aux_L22(state, key, r, params);			                    // state = Key[0] ^ L2(state)
        Aux_Xor2(state, r, params);                                 // state = plaintext[1/2/3] ^ state
        Aux_Sbox(state, tapes, r, params);							// state = S(state)
        Aux_L11(state, temp, r, params);			                // state = L1(state)^temp
    }

    // 重置随机磁带计数器，使在线执行使用与计算辅助共享时相同的随机位
    tapes->pos = 0;

    //free(roundKey);
    freeShares(key);
    freeShares(state);
    freeShares(temp);
}

static void commit(uint8_t* digest, uint8_t* seed, uint8_t* aux, uint8_t* salt, size_t t, size_t j, paramset_t* params)
{
    /* Compute C[t][j];  as digest = H(seed||[aux]) aux is optional —————— Com承诺  */
    HashInstance ctx;

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    if (aux != NULL) {
        size_t tapeLenBytes = params->andSizeBytes;
        HashUpdate(&ctx, aux, tapeLenBytes);
    }
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, t);       // HashUpdateIntLE：HashUpdate(ctx, (uint_8*)&toLittleEndian(t), sizeof(uint16_t))???
    HashUpdateIntLE(&ctx, j);       // HashUpdateIntLE：HashUpdate(ctx, (uint_8*)&toLittleEndian(j), sizeof(uint16_t))???
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);         // digest = hash(seed || aux || salt || t || j)
}

static void commit_h(uint8_t* digest, commitments_t* C, paramset_t* params)
{
    HashInstance ctx;

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    for (size_t i = 0; i < params->numMPCParties; i++) {
        HashUpdate(&ctx, C->hashes[i], params->digestSizeBytes);    // digest = H(C->hashes[i])
    }
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);             // h_j = H(com_{j,1} ,...,com_{j,n})
}

// Commit to the views for one parallel rep，向视图提交一个平行代表？？？
static void commit_v(uint8_t* digest, uint8_t* input, msgs_t* msgs, paramset_t* params)
{
    HashInstance ctx;

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, input, params->stateSizeBytes);        // H(input)
    for (size_t i = 0; i < params->numMPCParties; i++) {
        size_t msgs_size = numBytes(msgs->pos);
        HashUpdate(&ctx, msgs->msgs[i], msgs_size);         // H(msgs->msgs[i])
    }
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);     // h_j^` = H({z_{j,α}},msgs_{j,1} ,..., msgs_{j,n})
}

static void reconstructShares(uint32_t* output, shares_t* shares)   // 猜测：用于重构第n方的share值???
{
    for (size_t i = 0; i < shares->numWords; i++) {
        setBitInWordArray(output, i, parity64(shares->shares[i]));  // output[i] = parity64(shares->shares[i])，i∈[shares->numWords]
    }
}

static void wordToMsgs(uint64_t w, msgs_t* msgs, paramset_t* params)// 广播
{
    for (size_t i = 0; i < params->numMPCParties; i++) {
        uint8_t w_i = getBit((uint8_t*)&w, i);                      // s_shares[i]
        setBit(msgs->msgs[i], msgs->pos, w_i);                      // msgs[i][pos] = s_shares[i]，i∈[n]
    }
    msgs->pos++;                                                    // pos++
}

static uint8_t mpc_AND(uint8_t a, uint8_t b, uint64_t mask_a, uint64_t mask_b, randomTape_t* tapes, msgs_t* msgs, uint64_t* out, paramset_t* params)
{
    uint64_t output_mask = tapesToWord(tapes);  // 输出掩码，即[λ_{γ}]

    *out = output_mask;
    uint64_t and_helper = tapesToWord(tapes);   // 在预处理过程中为每个与门设置特殊的掩码值，即[λ_{α,β}]
    uint64_t s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ output_mask;
                                                // [s]计算：s_shares = (-a&b)^(-b&a)^and_helper^output_mask

    if (msgs->unopened >= 0) {                                                      // 存在没有打开的一方
        uint8_t unopenedPartyBit = getBit(msgs->msgs[msgs->unopened], msgs->pos);   // unopenedPartyBit = msgs[unopened][pos]
        setBit((uint8_t*)&s_shares, msgs->unopened, unopenedPartyBit);              // s_shares[unopened] = unopenedPartyBit
    }

    // 广播每一个share的s
    wordToMsgs(s_shares, msgs, params);

    return (uint8_t)(parity64(s_shares) ^ (a & b));                                 // 返回带掩码的输出值
}

//static void mpc_sbox(uint32_t* state, shares_t* state_masks, randomTape_t* tapes, msgs_t* msgs, paramset_t* params) // LowMC中的S-box
//{
//    for (size_t i = 0; i < params->numSboxes * 3; i += 3) {
//        uint8_t a = getBitFromWordArray(state, i + 2);      // a = state[i+2]
//        uint64_t mask_a = state_masks->shares[i + 2];       // mask_a = state_masks->shares[i+2]
//
//        uint8_t b = getBitFromWordArray(state, i + 1);      // b = state[i+1]
//        uint64_t mask_b = state_masks->shares[i + 1];       // mask_b = state_masks->shares[i+1]
//
//        uint8_t c = getBitFromWordArray(state, i);          // c = state[i]
//        uint64_t mask_c = state_masks->shares[i];           // mask_c = state_masks->shares[i]
//
//        uint64_t bc_mask, ab_mask, ca_mask; // 用于与门的新的掩码输出
//
//        uint8_t ab = mpc_AND(a, b, mask_a, mask_b, tapes, msgs, &ab_mask, params);  // ab = a与b构成的与门中，带掩码的输出值
//        uint8_t bc = mpc_AND(b, c, mask_b, mask_c, tapes, msgs, &bc_mask, params);  // bc = b与c构成的与门中，带掩码的输出值
//        uint8_t ca = mpc_AND(c, a, mask_c, mask_a, tapes, msgs, &ca_mask, params);  // ca = c与a构成的与门中，带掩码的输出值
//
//        setBitInWordArray(state, i + 2, a ^ bc);                        // state[i+2] = a ^ bc
//        state_masks->shares[i + 2] = mask_a ^ bc_mask;
//        setBitInWordArray(state, i + 1, a ^ b ^ ca);                    // state[i+1] = a ^ b ^ ca
//        state_masks->shares[i + 1] = mask_b ^ mask_a ^ ca_mask;
//        setBitInWordArray(state, i, a ^ b ^ c ^ ab);                    // state[i]   = a ^ b ^ c ^ ab
//        state_masks->shares[i] = mask_a ^ mask_b ^ mask_c ^ ab_mask;
//    }
//}

/* 对每个share中的word ; 写玩家i的share到他们的msgs流中 */
static void broadcast(shares_t* shares, msgs_t* msgs, paramset_t* params)   // 广播
{
    for (size_t w = 0; w < shares->numWords; w++) {
        wordToMsgs(shares->shares[w], msgs, params);        //msgs[i][pos] = shares[w][i]，i∈[n], pos++
    }
}

static void mpc_matrix_mul(uint32_t* output, const uint32_t* vec, const uint32_t* matrix, shares_t* mask_shares, paramset_t* params)    // LowMC中的线性层
{
    uint32_t prod[LOWMC_MAX_STATE_SIZE];
    uint32_t temp[LOWMC_MAX_STATE_SIZE];

    shares_t* tmp_mask = allocateShares(mask_shares->numWords);

    for (size_t i = 0; i < params->stateSizeBits; i++) {
        tmp_mask->shares[i] = 0;
        for (uint32_t j = 0; j < params->stateSizeBits / 8; j++) {
            uint8_t matrix_byte = ((uint8_t*)matrix)[(i * params->stateSizeBits) / 8 + j];
            uint8_t vec_byte = ((uint8_t*)vec)[j];

            ((uint8_t*)prod)[j] = matrix_byte & vec_byte;

            tmp_mask->shares[i] ^= mask_shares->shares[j * 8] & extend((matrix_byte >> 7) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 1] & extend((matrix_byte >> 6) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 2] & extend((matrix_byte >> 5) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 3] & extend((matrix_byte >> 4) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 4] & extend((matrix_byte >> 3) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 5] & extend((matrix_byte >> 2) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 6] & extend((matrix_byte >> 1) & 1);
            tmp_mask->shares[i] ^= mask_shares->shares[j * 8 + 7] & extend(matrix_byte & 1);

        }
        uint8_t output_bit_i = parity(&prod[0], params->stateSizeWords);
        setBit((uint8_t*)temp, i, output_bit_i);
    }

    memcpy(output, &temp, params->stateSizeBytes);
    copyShares(mask_shares, tmp_mask);
    freeShares(tmp_mask);
}

#if 0
/* mpc_matrix_mul的另一种更简单的实现，更接近规范中的描述 */
static void mpc_matrix_mul_simple(uint32_t* output, const uint32_t* vec, const uint32_t* matrix, shares_t* mask_shares, paramset_t* params)
{
    uint32_t prod[LOWMC_MAX_STATE_SIZE];
    uint32_t temp[LOWMC_MAX_STATE_SIZE];

    shares_t* tmp_mask = allocateShares(mask_shares->numWords);

    for (size_t i = 0; i < params->stateSizeBits; i++) {
        tmp_mask->shares[i] = 0;
        for (uint32_t j = 0; j < params->stateSizeBits; j++) {
            uint8_t matrix_bit = getBit((uint8_t*)matrix, i * params->stateSizeBits + j);
            uint8_t vec_bit = getBit((uint8_t*)vec, j);
            setBit((uint8_t*)prod, j, matrix_bit & vec_bit);
            tmp_mask->shares[i] ^= mask_shares->shares[j] & extend(matrix_bit);
        }
        uint8_t output_bit_i = parity(&prod[0], params->stateSizeWords);
        setBit((uint8_t*)temp, i, output_bit_i);
    }

    memcpy(output, &temp, params->stateSizeBytes);
    copyShares(mask_shares, tmp_mask);
    freeShares(tmp_mask);
}
#endif

static void mpc_xor2(uint32_t* output, shares_t* output_masks, const uint32_t* x,
                     const shares_t* x_masks,  const uint32_t* y, const shares_t* y_masks, paramset_t* params)
{
    xor_array(output, x, y, params->stateSizeWords);        // output = x ^ y
    mpc_xor_masks(output_masks, x_masks, y_masks);          // output_masks->shares = x_masks->shares + y_masks->shares
}

#if 0
/* 在调试操作掩码值的MPC函数时使用的辅助函数 */
static void print_unmasked(char* label, uint32_t* state, shares_t* mask_shares, paramset_t* params)
{
    uint32_t tmp[LOWMC_MAX_STATE_SIZE];

    reconstructShares(tmp, mask_shares);
    xor_array(tmp, tmp, state, params->stateSizeWords);
    printHex(label, (uint8_t*)tmp, params->stateSizeBytes);
}
#endif



static int contains(uint16_t* list, size_t len, size_t value)   // 如果list中包含value，返回1，否则返回0
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] == value) {
            return 1;
        }
    }
    return 0;
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

static void getAuxBits(uint8_t* output, randomTape_t* tapes, paramset_t* params)    // 由名称：获取Aux
{
    // size_t，即 unsigned int
    size_t firstAuxIndex = params->stateSizeBits + 1;
    size_t last = params->numMPCParties - 1;
    size_t pos = 0;

    memset(output, 0, params->andSizeBytes);        // 将output指向的字符串，的前andSizeBytes个字符，设为0
    size_t andSizeBits = 64 * params->numRounds * params->numSboxes;     // andSizeBits = 3 * 轮数(r) * S盒数(m)，LowMC参数
    for (size_t i = 0; i < andSizeBits * 2; i += 2) {
        uint8_t auxBit = getBit(tapes->tape[last], firstAuxIndex + i);  // auxBit = tape[last][firstAuxIndex + i]???
        setBit(output, pos, auxBit);                                    // output[pos] = auxBit
        pos++;                                                          // pos++
    }
}

static void setAuxBits(randomTape_t* tapes, uint8_t* input, paramset_t* params)     // 由名称：设置Aux
{
    size_t firstAuxIndex = params->stateSizeBits + 1;
    size_t last = params->numMPCParties - 1;
    size_t pos = 0;

    for (size_t i = 0; i < params->andSizeBytes * 2 * 8; i += 2) {
        uint8_t auxBit = getBit(input, pos);
        setBit(tapes->tape[last], firstAuxIndex + i, auxBit);
        pos++;
    }
}

// 模拟在线阶段：参数列表(掩码密钥，掩码份额，随机磁带，广播信息，明文，公钥，参数表)
static int simulateOnline(uint32_t* maskedKey, shares_t* mask_shares, randomTape_t*
                          tapes, msgs_t* msgs, const uint32_t* plaintext, const uint32_t* pubKey, paramset_t* params)
{
    int ret = 0;
    uint32_t* roundKey = malloc(params->stateSizeBytes);
    uint32_t* state = malloc(params->stateSizeBytes);
    shares_t* key_masks = allocateShares(mask_shares->numWords);    // 复制，待计算轮密钥使用

    copyShares(key_masks, mask_shares);                             // key_masks->shares = mask_shares->shares

    mpc_matrix_mul(roundKey, maskedKey, KMatrix(0, params), mask_shares, params);       // roundKey = maskedKey * KMatrix[0]
    xor_array(state, roundKey, plaintext, params->stateSizeWords);                      // state = plaintext + roundKey

    shares_t* round_key_masks = allocateShares(mask_shares->numWords);
    for (uint32_t r = 1; r <= params->numRounds; r++) {
        copyShares(round_key_masks, key_masks);
        mpc_matrix_mul(roundKey, maskedKey, KMatrix(r, params), round_key_masks, params);

        mpc_sbox(state, mask_shares, tapes, msgs, params);
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), mask_shares, params);              // state = state * LMatrix (r-1)
        xor_array(state, state, RConstant(r - 1, params), params->stateSizeWords);              // state += RConstant
        mpc_xor2(state, mask_shares, roundKey, round_key_masks, state, mask_shares, params);    // state += roundKey
    }
    freeShares(round_key_masks);

    /* 打开输出的掩码，检查是否为1 */
    if (msgs->unopened >= 0) {
        /* 在签名验证期间，我们在msgs中已经有未打开方（第c方???）的输出份额，但在mask_shares中没有。 */
        for (size_t i = 0; i < params->stateSizeBits; i++) {
            uint8_t share = getBit(msgs->msgs[msgs->unopened], msgs->pos + i);  // share = 未打开方的msgs[pos+i]???
            setBit((uint8_t*)&mask_shares->shares[i],  msgs->unopened, share);  // mask_shares->shares[i][unopened] = share
        }

    }
    uint32_t output[LOWMC_MAX_STATE_SIZE];
    reconstructShares(output, mask_shares);                         // output[i] = parity64(shares->shares[i])，i∈[shares->numWords]
    xor_array(output, output, state, params->stateSizeWords);       // output = output ^ state

    if (memcmp(output, pubKey, params->stateSizeBytes) != 0) {      // 如果output和pubKey不相等，进入循环???
        printf("%s: output does not match pubKey\n", __func__);
        printHex("pubKey", (uint8_t*)pubKey, params->stateSizeBytes);
        printHex("output", (uint8_t*)output, params->stateSizeBytes);
        ret = -1;
        goto Exit;
    }

    broadcast(mask_shares, msgs, params);                           // 广播 mask_shares

    free(state);
    free(roundKey);
    freeShares(key_masks);

Exit:
    return ret;
}

/*=======================================================================================================================================================================*/

MPC_Init(uint32_t* plaintext, uint32_t* Temp_plaintext, uint32_t* maskedKey, uint32_t* Temp_maskedKey, paramset_t* params)
{
    for (int i = 0; i < params->stateSizeWords; i++)
    {
        Temp_plaintext[i] = plaintext[i];
        Temp_maskedKey[i] = maskedKey[i];
    }
}

// maskedKey = maskedKey ^ FK				mask_shares = mask_shares ^ FK
void MPC_InitKey(uint32_t* maskedKey, shares_t* mask_shares, paramset_t* params) {
    for (int i = 0; i < params->stateSizeWords; i++)
        maskedKey[i] ^= FK[i];
    for (int i = 0; i < params->stateSizeBits; i++) {
        int m = i / 32;
        int n = i % 32;
        uint8_t bit = (FK[m] >> (n - 31)) & 0x01;
        mask_shares->shares[i] ^= extend(bit);
    }
}

// state = maskedKey[1/2/3] ^ CK[i]			mask_shares = maskedKey[1/2/3]
void MPC_Xor1(uint32_t* state, shares_t* state_masks, uint32_t* maskedKey, shares_t* mask_shares, uint32_t r, paramset_t* params) {
    state[r%4] = maskedKey[(r + 1) % 4] ^ maskedKey[(r + 2) % 4] ^ maskedKey[(r + 3) % 4] ^ CK[r];

    for (int i = 0; i < params->tempSizeBits; i++) {
        state_masks->shares[(i+r*32)%128] = mask_shares->shares[(i + 96 + r * 32) % 128] ^ mask_shares->shares[(i + 32 + r * 32) % 128] ^ mask_shares->shares[(i + 64 + r * 32) % 128];
    }
}

// state = plaintext[1/2/3] ^ state
void MPC_Xor2(uint32_t* state, shares_t* state_masks, uint32_t* plaintext, uint32_t r)
{
    state[r % 4] = state[r % 4] ^ plaintext[(r + 1) % 4] ^ plaintext[(r + 2) % 4] ^ plaintext[(r + 3) % 4];
    for (int i = 0; i < 32; i++)
    {
        state_masks->shares[(r * 32 + i) % 128] ^= state_masks->shares[(r * 32 + i + 32) % 128] ^ state_masks->shares[(r * 32 + i + 64) % 128] ^ state_masks->shares[(r * 32 + i + 96) % 128];
    }
}

uint8_t MPC_AND(uint8_t a, uint8_t b, uint64_t mask_a, uint64_t mask_b, randomTape_t* tapes, msgs_t* msgs, uint64_t* out, paramset_t* params)
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
void MPC_Sbox(uint32_t* state, shares_t* state_masks, randomTape_t* tapes, msgs_t* msgs, uint32_t r, paramset_t* params) {
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

// state = Key[r % 4] ^ L2(state)			state_masks = mask_shares[r % 4] ^ L2(state_masks)
void MPC_L22(uint32_t* state, shares_t* state_masks, uint32_t* maskedKey, shares_t* mask_shares, uint32_t r, paramset_t* params) {

    state[r % 4] = L2(state[r % 4]);

    Aux_L2(state_masks, r);

    state[r % 4] ^= maskedKey[r % 4];
    maskedKey[r % 4] = state[r % 4];
    for (int k = 0; k < params->tempSizeBits; k++) {
        state_masks->shares[(r * 32 + k) % 128] = mask_shares->shares[(r * 32 + k) % 128] ^ state_masks->shares[(r * 32 + k) % 128];
        mask_shares->shares[(r * 32 + k) % 128] = state_masks->shares[(r * 32 + k) % 128];
    }
}

// plaintext[r % 4] = plaintext[r % 4] ^ L1(state)
void MPC_L11(uint32_t* state, shares_t* state_masks, uint32_t* plaintext, shares_t* temp_masks, uint32_t r, paramset_t* params) {
    // state = L1(state)		mask_shares = L1(mask_shares)
    state[r % 4] = L1(state[r % 4]);
    Aux_L1(state_masks, r);

    state[r % 4] = plaintext[r % 4] ^ state[r % 4];
    plaintext[r % 4] = state[r % 4];
    for (int i = 0; i < params->tempSizeBits; i++)
    {
        state_masks->shares[(r * 32 + i) % 128] ^= temp_masks->shares[i];
    }
}

// temp = state         temp_masks = state_masks
static void MPC_Init_temp(uint32_t* state, shares_t* state_masks, shares_t* temp_masks, uint64_t r, paramset_t* params) {
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

// 模拟在线阶段：参数列表(掩码密钥，掩码份额，随机磁带，广播信息，明文，公钥)
int simulateOnline_SM4(uint32_t* maskedKey, shares_t* mask_shares,
    randomTape_t* tapes, msgs_t* msgs, const uint32_t* plaintext, const uint32_t* pubKey, paramset_t* params)
{
    int ret = 0;
    uint32_t* Temp_maskedKey = (uint32_t*)calloc(params->stateSizeWords, sizeof(uint32_t)); // 4
    uint32_t* Temp_plaintext = (uint32_t*)calloc(params->stateSizeWords, sizeof(uint32_t)); // 4
    uint32_t* state = (uint32_t*)malloc(params->stateSizeBytes);							// 4
    shares_t* state_masks = allocateShares(params->stateSizeBits);
    shares_t* temp_masks = allocateShares(params->tempSizeBits);

    MPC_Init(plaintext, Temp_plaintext, maskedKey, Temp_maskedKey, params);

    MPC_InitKey(Temp_maskedKey, mask_shares, params);					        // maskedKey = maskedKey ^ FK
                                                                                // mask_shares = mask_shares ^ FK

    for (uint32_t r = 0; r < params->numRounds; r++) {

        MPC_Init_temp(plaintext, state_masks, temp_masks, r, params);               // temp = state
                                                                                    // temp_masks = state_masks

        MPC_Xor1(state, state_masks, Temp_maskedKey, mask_shares, r, params);		    // state = maskedKey[1/2/3] ^ CK[i]
                                                                                    // state_masks = mask_shares[1/2/3]

        MPC_Sbox(state, state_masks, tapes, msgs, r, params);						// state = S(state)
                                                                                    // state_masks = S(state_masks)

        MPC_L22(state, state_masks, Temp_maskedKey, mask_shares, r, params);	    // Key[r % 4] = state = Key[r % 4] ^ L2(state)
                                                                                    // mask_shares[r % 4] = state_masks = mask_shares[r % 4] ^ L2(state_masks)

        MPC_Xor2(state, state_masks, Temp_plaintext, r);							// state = plaintext[1/2/3] ^ state

        MPC_Sbox(state, state_masks, tapes, msgs, r, params);						// state = S(state)
                                                                                    // state_masks = S(state_masks)

        MPC_L11(state, state_masks, Temp_plaintext, temp_masks, r, params);	        // plaintext[r % 4] = temp ^ L1(state)
                                                                                    // state_masks = L1(state_masks)

    }

    MPC_Reverse(state, state_masks);       // X28 X29 X30 X31 -> X31 X30 X29 X28

    // printf("\n--- msgs->pos:%d", msgs->pos);     pos = 600

    /* 打开输出的掩码，检查是否为1 */
    if (msgs->unopened >= 0) {
        /* 在签名验证期间，我们在msgs中已经有未打开方的输出份额，但在mask_shares中没有。 */
        for (size_t i = 0; i < params->stateSizeBits; i++) {
            uint8_t share = getBit(msgs->msgs[msgs->unopened], msgs->pos + i);      // share = 未打开方的msgs[pos+i]
            setBit((uint8_t*)&state_masks->shares[i], msgs->unopened, share);       // mask_shares->shares[i][unopened] = share
        }
    }
    uint32_t output[4];
    reconstructShares(output, state_masks);
    xor_array(output, state, output, params->stateSizeWords);   

    if (memcmp(output, pubKey, params->stateSizeBytes) != 0) {                      // 如果output和ciphertext不相等，Exit
        printf("%s: output does not match pubKey\n", __func__);
        printHex("pubKey", (uint8_t*)pubKey, params->stateSizeBytes);
        printHex("output", (uint8_t*)output, params->stateSizeBytes);
        ret = -1;
        printf("ret:%d", ret);
        goto Exit;
    }

    broadcast(state_masks, msgs, params);									        // 广播 state_masks
    //printf("\n--- msgs->pos:%d", msgs->pos);                                      // pos = 128 + 246 * 8 * 32 = 63104

    free(Temp_plaintext);
    free(Temp_maskedKey);
    free(state);
    freeShares(temp_masks);
    freeShares(state_masks);

Exit:
    return ret;
}

/*=======================================================================================================================================================================*/


static size_t bitsToChunks(size_t chunkLenBits, const uint8_t* input, size_t inputLen, uint16_t* chunks)
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

static size_t appendUnique(uint16_t* list, uint16_t value, size_t position)
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

static void HCP(uint16_t* challengeC, uint16_t* challengeP, commitments_t* Ch,
                uint8_t* hCv, uint8_t* salt, const uint32_t* pubKey, const uint32_t* plaintext, const uint8_t* message,
                size_t messageByteLength, paramset_t* params)
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
    printf("%s pubKey", __func__);
    printHex("", (uint8_t*)pubKey, params->stateSizeBytes);
    printf("%s plaintext", __func__);
    printHex("", (uint8_t*)plaintext, params->stateSizeBytes);

#endif

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        HashUpdate(&ctx, Ch->hashes[t], params->digestSizeBytes);       // H(Ch->hashes)_承诺Com
    }

    HashUpdate(&ctx, hCv, params->digestSizeBytes);                     // H(hCv)
    HashUpdate(&ctx, salt, params->saltSizeBytes);                      // H(salt)
    HashUpdate(&ctx, (uint8_t*)pubKey, params->stateSizeBytes);         // H(pubKey)
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);      // H(plaintext)
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
        size_t numChunks = bitsToChunks(bitsPerChunkC, h, params->digestSizeBytes, chunks);
        for (size_t i = 0; i < numChunks; i++) {
            if (chunks[i] < params->numMPCRounds) {
                countC = appendUnique(challengeC, chunks[i], countC);
            }
            if (countC == params->numOpenedRounds) {
                break;
            }
        }

        HashInit(&ctx, params, HASH_PREFIX_1);
        HashUpdate(&ctx, h, params->digestSizeBytes);
        HashFinal(&ctx);
        HashSqueeze(&ctx, h, params->digestSizeBytes);                  // h = H(h)
    }

    // Note that we always compute h = H(h) after setting C
    size_t countP = 0;

    while (countP < params->numOpenedRounds) {                          // 获取挑战P
        size_t numChunks = bitsToChunks(bitsPerChunkP, h, params->digestSizeBytes, chunks);
        for (size_t i = 0; i < numChunks; i++) {
            if (chunks[i] < params->numMPCParties) {
                challengeP[countP] = chunks[i];
                countP++;
            }
            if (countP == params->numOpenedRounds) {
                break;
            }
        }

        HashInit(&ctx, params, HASH_PREFIX_1);
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

static uint16_t* getMissingLeavesList(uint16_t* challengeC, paramset_t* params)     // Merkle哈希结构
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

int verify_picnic2(signature2_t* sig, const uint32_t* pubKey, const uint32_t* plaintext, const uint8_t* message, size_t messageByteLength,
                   paramset_t* params)
{
    commitments_t* C = allocateCommitments(params, 0);
    commitments_t Ch = { 0 };
    commitments_t Cv = { 0 };
    msgs_t* msgs = allocateMsgs(params);
    tree_t* treeCv = createTree(params->numMPCRounds, params->digestSizeBytes);     // Cv：commitment to views
    size_t challengeSizeBytes = params->numOpenedRounds * sizeof(uint16_t);
    uint16_t* challengeC = malloc(challengeSizeBytes);
    uint16_t* challengeP = malloc(challengeSizeBytes);
    tree_t** seeds = calloc(params->numMPCRounds, sizeof(tree_t*));
    randomTape_t* tapes = malloc(params->numMPCRounds * sizeof(randomTape_t));
    tree_t* iSeedsTree = createTree(params->numMPCRounds, params->seedSizeBytes);
    int ret = reconstructSeeds(iSeedsTree, sig->challengeC, params->numOpenedRounds, sig->iSeedInfo, sig->iSeedInfoLen, sig->salt, 0, params);

    if (ret != 0) {
        ret = -1;
        goto Exit;
    }

    /* 用签名中的值填充种子 */
    int t;
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {                     
        if (!contains(sig->challengeC, params->numOpenedRounds, t)) {               // 挑战C不包含t，则进入
            /* Expand iSeed[t] to seeds for each parties, using a seed tree：
               getLeaf(iSeedsTree, t) = tree->node[firstLeaf + t] */
            seeds[t] = generateSeeds(params->numMPCParties, getLeaf(iSeedsTree, t), sig->salt, t, params);  // 生成Seeds
        }
        else {
            /* We don't have the initial seed for the round, but instead a seed
             * for each unopened party */
            // 没有主seed，对于未打开的每一方有一个seed???
            seeds[t] = createTree(params->numMPCParties, params->seedSizeBytes);    // 生成树
            size_t P_index = indexOf(sig->challengeC, params->numOpenedRounds, t);
            uint16_t hideList[1];
            hideList[0] = sig->challengeP[P_index];
            ret = reconstructSeeds(seeds[t], hideList, 1,
                                   sig->proofs[t].seedInfo, sig->proofs[t].seedInfoLen,
                                   sig->salt, t, params);
            if (ret != 0) {
                printf("Failed to reconstruct seeds for round %lu\n", t);
                ret = -1;
            }
        }
    }
    if (ret == -1) {
        goto Exit;
    }


    /* Commit */
    size_t last = params->numMPCParties - 1;
#ifndef OMP_KKW
    uint8_t auxBits[MAX_AUX_BYTES];
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        /* 为各方计算随机磁带。每一次重复挑战都会有一个虚假的种子;但我们不会用那个派对的随机磁带。 */
        createRandomTapes(&tapes[t], getLeaves(seeds[t]), sig->salt, t, params);

        if (!contains(sig->challengeC, params->numOpenedRounds, t)) {               // 挑战C不包含t，则进入
            /* 给定iSeed, 拥有拓展的seeds, 从头计算的aux，所以我们可以计算Com[t] */
            computeAuxTape(&tapes[t], params);
            for (size_t j = 0; j < last; j++) {
                commit(C[t].hashes[j], getLeaf(seeds[t], j), NULL, sig->salt, t, j, params);    // C[t].hashes[j] = H(seeds[t][j] || null || t || j)
            }
            getAuxBits(auxBits, &tapes[t], params);
            commit(C[t].hashes[last], getLeaf(seeds[t], last), auxBits, sig->salt, t, last, params);    // C[t].hashes[last] = H(seeds[t][j] || aux || t || j)
        }
        else {
            /* We're given all seeds and aux bits, execpt for the unopened 
             * party, we get their commitment */
            size_t unopened = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            for (size_t j = 0; j < last; j++) {
                if (j != unopened) {
                    commit(C[t].hashes[j], getLeaf(seeds[t], j), NULL, sig->salt, t, j, params);    // C[t].hashes[j] = H(seeds[t][j] || null || t || j)
                }
            }
            if (last != unopened) {
                commit(C[t].hashes[last], getLeaf(seeds[t], last), sig->proofs[t].aux, sig->salt, t, last, params); // C[t].hashes[last] = H(seeds[t][j] || aux || t || j)
            }

            memcpy(C[t].hashes[unopened], sig->proofs[t].C, params->digestSizeBytes);   // C[t].hashes[unopened] = sig->proofs[t].C     直接复制
        }

    }
#else
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        uint8_t auxBits[MAX_AUX_BYTES];
        /* 为各方计算随机磁带。每一次重复挑战都会有一个虚假的种子;但我们不会用那个派对的随机磁带。 */
        createRandomTapes(&tapes[t], getLeaves(seeds[t]), sig->salt, t, params);

        if (!contains(sig->challengeC, params->numOpenedRounds, t)) {               // 挑战C不包含t，则进入
            /* 给定iSeed, 拥有拓展的seeds, 从头计算的aux，所以我们可以计算Com[t] */
            computeAuxTape(&tapes[t], params);
            for (size_t j = 0; j < last; j++) {
                commit(C[t].hashes[j], getLeaf(seeds[t], j), NULL, sig->salt, t, j, params);    // C[t].hashes[j] = H(seeds[t][j] || null || t || j)
            }
            getAuxBits(auxBits, &tapes[t], params);
            commit(C[t].hashes[last], getLeaf(seeds[t], last), auxBits, sig->salt, t, last, params);    // C[t].hashes[last] = H(seeds[t][j] || aux || t || j)
        }
        else {
            /* We're given all seeds and aux bits, execpt for the unopened
             * party, we get their commitment */
            size_t unopened = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            for (size_t j = 0; j < last; j++) {
                if (j != unopened) {
                    commit(C[t].hashes[j], getLeaf(seeds[t], j), NULL, sig->salt, t, j, params);    // C[t].hashes[j] = H(seeds[t][j] || null || t || j)
                }
            }
            if (last != unopened) {
                commit(C[t].hashes[last], getLeaf(seeds[t], last), sig->proofs[t].aux, sig->salt, t, last, params); // C[t].hashes[last] = H(seeds[t][j] || aux || t || j)
            }

            memcpy(C[t].hashes[unopened], sig->proofs[t].C, params->digestSizeBytes);   // C[t].hashes[unopened] = sig->proofs[t].C     直接复制
        }

    }
#endif // !OMP_KKW

    


    /* Commit to the commitments */
    allocateCommitments2(&Ch, params, params->numMPCRounds);                // ???
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        commit_h(Ch.hashes[t], &C[t], params);                              // h_j = H(com_{j,1} ,...,com_{j,n})
    }

#ifndef OMP_KKW
/* Commit to the views */
    allocateCommitments2(&Cv, params, params->numMPCRounds);                // ???
    shares_t* mask_shares = allocateShares(params->stateSizeBits);
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            /* 2. When t is in C, we have everything we need to re-compute the view, as an honest signer would.
             * We simulate the MPC with one fewer party; the unopned party's values are all set to zero. */
            // 未打开方全部设为0 ???
            size_t unopened = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            size_t tapeLengthBytes = 2 * params->andSizeBytes + params->stateSizeBytes;
            if(unopened != last) {
                setAuxBits(&tapes[t], sig->proofs[t].aux, params);  // sig->proofs[t].aux is only set when P_t != N ???
            }
            //memset(tapes[t].tape[unopened], 0, tapeLengthBytes);    // 复制0到tapes[t].tape[unopened]的前tapeLengthBytes字符
            memcpy(msgs[t].msgs[unopened], sig->proofs[t].msgs, params->andSizeBytes + params->stateSizeBytes );
            msgs[t].unopened = unopened;

            tapesToWords(mask_shares, &tapes[t]);

            int rv = simulateOnline_SM4((uint32_t*)sig->proofs[t].input, mask_shares, &tapes[t], &msgs[t], plaintext, pubKey, params);  
            if (rv != 0) {
                printf("MPC simulation failed for round %lu, signature invalid\n", t);
                ret = -1;
                freeShares(mask_shares);
                goto Exit;
            }
            commit_v(Cv.hashes[t], sig->proofs[t].input, &msgs[t], params);
        }
        else {
            Cv.hashes[t] = NULL;
        }
    }
    freeShares(mask_shares);
#else
    /* Commit to the views */

    allocateCommitments2(&Cv, params, params->numMPCRounds);                // ???
    //int t;
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        shares_t* mask_shares = allocateShares(params->stateSizeBits);
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            /* 2. When t is in C, we have everything we need to re-compute the view, as an honest signer would.
             * We simulate the MPC with one fewer party; the unopned party's values are all set to zero. */
            size_t unopened = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            size_t tapeLengthBytes = 2 * params->andSizeBytes + params->stateSizeBytes;
            if (unopened != last) {
                setAuxBits(&tapes[t], sig->proofs[t].aux, params);  // sig->proofs[t].aux is only set when P_t != N ???
            }
            memset(tapes[t].tape[unopened], 0, tapeLengthBytes);    // 复制0到tapes[t].tape[unopened]的前tapeLengthBytes字符
            memcpy(msgs[t].msgs[unopened], sig->proofs[t].msgs, params->andSizeBytes + params->stateSizeBytes);
            msgs[t].unopened = unopened;

            tapesToWords(mask_shares, &tapes[t]);

            int rv = simulateOnline_SM4((uint32_t*)sig->proofs[t].input, mask_shares, &tapes[t], &msgs[t], plaintext, pubKey, params);
            if (rv != 0) {
                printf("MPC simulation failed for round %lu, signature invalid\n", t);
                ret = -1;
                freeShares(mask_shares);
                break;
                //goto Exit;
            }
            commit_v(Cv.hashes[t], sig->proofs[t].input, &msgs[t], params);
        }
        else {
            Cv.hashes[t] = NULL;
        }
        freeShares(mask_shares);
    }
    if (ret == -1) {
        goto Exit;
    }
#endif // !OMP_KKW

    

    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = getMissingLeavesList(sig->challengeC, params);
    ret = addMerkleNodes(treeCv, missingLeaves, missingLeavesSize, sig->cvInfo, sig->cvInfoLen);
    free(missingLeaves);
    if (ret != 0) {
        ret = -1;
        goto Exit;
    }

    ret = verifyMerkleTree(treeCv, Cv.hashes, sig->salt, params);
    if (ret != 0) {
        ret = -1;
        goto Exit;
    }

    /* Compute the challenge; two lists of integers */
    HCP(challengeC, challengeP, &Ch, treeCv->nodes[0], sig->salt, pubKey, plaintext, message, messageByteLength, params);

    /* Compare to challenge from signature */
    if ( memcmp(sig->challengeC, challengeC, challengeSizeBytes) != 0 ||
         memcmp(sig->challengeP, challengeP, challengeSizeBytes) != 0 ) {
        printf("Challenge does not match, signature invalid\n");
        ret = -1;
        goto Exit;
    }

    ret = EXIT_SUCCESS;

Exit:

    free(challengeC);
    free(challengeP);
    freeCommitments(C);
    freeCommitments2(&Cv);
    freeCommitments2(&Ch);
    freeMsgs(msgs);
    freeTree(treeCv);
    freeTree(iSeedsTree);
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        freeRandomTape(&tapes[t]);
        freeTree(seeds[t]);
    }
    free(seeds);
    free(tapes);

    return ret;
}

static void computeSaltAndRootSeed(uint8_t* saltAndRoot, size_t saltAndRootLength, uint32_t* privateKey, uint32_t* pubKey,
                                   uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    HashInstance ctx;

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, (uint8_t*)privateKey, params->stateSizeBytes);
    HashUpdate(&ctx, message, messageByteLength);
    HashUpdate(&ctx, (uint8_t*)pubKey, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);
    HashUpdateIntLE(&ctx, params->stateSizeBits);
    HashFinal(&ctx);
    HashSqueeze(&ctx, saltAndRoot, saltAndRootLength);
}

int sign_picnic2(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message,
                 size_t messageByteLength, signature2_t* sig, paramset_t* params)
{
    clock_t start, end;

    start = clock();

    int ret = 0;
    uint8_t* saltAndRoot = malloc(params->saltSizeBytes + params->seedSizeBytes);
    computeSaltAndRootSeed(saltAndRoot, params->saltSizeBytes + params->seedSizeBytes, privateKey, pubKey, plaintext, message, messageByteLength, params);
    memcpy(sig->salt, saltAndRoot, params->saltSizeBytes);
    tree_t* iSeedsTree = generateSeeds(params->numMPCRounds, saltAndRoot + params->saltSizeBytes, sig->salt, 0, params);
    uint8_t** iSeeds = getLeaves(iSeedsTree);
    free(saltAndRoot);

    randomTape_t* tapes = malloc(params->numMPCRounds * sizeof(randomTape_t));
    tree_t** seeds = malloc(params->numMPCRounds * sizeof(tree_t*));

#ifndef OMP_KKW
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        seeds[t] = generateSeeds(params->numMPCParties, iSeeds[t], sig->salt, t, params);
        createRandomTapes(&tapes[t], getLeaves(seeds[t]), sig->salt, t, params);
    }

    /* Preprocessing; compute aux tape for the N-th player, for each parallel rep */
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        computeAuxTape(&tapes[t], params);
    }

#else

#pragma omp parallel
    {
        //printf("线程数：%d,处理器个数：%d\n", omp_get_num_threads(), omp_get_num_procs());
        int t;
#pragma omp for schedule(guided)// shared(params,seeds,tapes,sig->salt,iSeeds)
        for (t = 0; t < params->numMPCRounds; t++) {
            seeds[t] = generateSeeds(params->numMPCParties, iSeeds[t], sig->salt, t, params);
            createRandomTapes(&tapes[t], getLeaves(seeds[t]), sig->salt, t, params);
        }

    /* Preprocessing; compute aux tape for the N-th player, for each parallel rep */
    
#pragma omp for schedule(guided) //shared(tapes,params)
            for (t = 0; t < params->numMPCRounds; t++) {
                computeAuxTape(&tapes[t], params);
            }
    }
#endif


    /* Commit to seeds and aux bits */
    
    commitments_t* C = allocateCommitments(params, 0);
#ifndef OMP_KKW
    uint8_t auxBits[MAX_AUX_BYTES];
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        for (size_t j = 0; j < params->numMPCParties - 1; j++) {
            commit(C[t].hashes[j], getLeaf(seeds[t], j), NULL, sig->salt, t, j, params);
        }
        size_t last = params->numMPCParties - 1;
        getAuxBits(auxBits, &tapes[t], params);
        commit(C[t].hashes[last], getLeaf(seeds[t], last), auxBits, sig->salt, t, last, params);
    }
#else
    int t;
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        uint8_t auxBits[MAX_AUX_BYTES];
        for (size_t j = 0; j < params->numMPCParties - 1; j++) {
            commit(C[t].hashes[j], getLeaf(seeds[t], j), NULL, sig->salt, t, j, params);
        }
        size_t last = params->numMPCParties - 1;
        getAuxBits(auxBits, &tapes[t], params);
        commit(C[t].hashes[last], getLeaf(seeds[t], last), auxBits, sig->salt, t, last, params);
    }
#endif


    end = clock();
    double acc = (double)(end - start);
    printf("预处理阶段：%lf ms\n", acc);
    start = clock();

    /* Simulate the online phase of the MPC */
    inputs_t inputs = allocateInputs(params);
    msgs_t* msgs = allocateMsgs(params);
    
#ifndef OMP_KKW
    shares_t* mask_shares = allocateShares(params->stateSizeBits);
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        uint32_t* maskedKey = (uint32_t*)inputs[t];
        tapesToWords(mask_shares, &tapes[t]);
        reconstructShares(maskedKey, mask_shares);                                      // maskedKey = masks
        xor_array(maskedKey, maskedKey, privateKey, params->stateSizeWords);            // maskedKey += privateKey

        int rv = simulateOnline_SM4(maskedKey, mask_shares, &tapes[t], &msgs[t], plaintext, pubKey, params);
        if (rv != 0) {
            printf("MPC simulation failed, aborting signature\n");
            ret = -1;
        }
    }
    freeShares(mask_shares);
#else 
    //int t;
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        //printf("%d", omp_get_num_threads());
        uint32_t* maskedKey = (uint32_t*)inputs[t];
        shares_t* mask_shares = allocateShares(params->stateSizeBits);
        tapesToWords(mask_shares, &tapes[t]);
        reconstructShares(maskedKey, mask_shares);                                      // maskedKey = masks
        xor_array(maskedKey, maskedKey, privateKey, params->stateSizeWords);            // maskedKey += privateKey

        int rv = simulateOnline_SM4(maskedKey, mask_shares, &tapes[t], &msgs[t], plaintext, pubKey, params);
        if (rv != 0) {
            printf("MPC simulation failed, aborting signature\n");
            ret = -1;
        }
        freeShares(mask_shares);
    }
#endif // !OMP_KKW

    
    

    /* Commit to the commitments and views */
    commitments_t Ch;
    allocateCommitments2(&Ch, params, params->numMPCRounds);
    commitments_t Cv;
    allocateCommitments2(&Cv, params, params->numMPCRounds);
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        commit_h(Ch.hashes[t], &C[t], params);
        commit_v(Cv.hashes[t], inputs[t], &msgs[t], params);
    }

    /* Create a Merkle tree with Cv as the leaves */
    tree_t* treeCv = createTree(params->numMPCRounds, params->digestSizeBytes);
    buildMerkleTree(treeCv, Cv.hashes, sig->salt, params);

    /* Compute the challenge; two lists of integers */
    uint16_t* challengeC = sig->challengeC;
    uint16_t* challengeP = sig->challengeP;
    HCP(challengeC, challengeP, &Ch, treeCv->nodes[0], sig->salt, pubKey, plaintext, message, messageByteLength, params);

    /* Send information required for checking commitments with Merkle tree.
     * The commitments the verifier will be missing are those not in challengeC. */
    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = getMissingLeavesList(challengeC, params);
    size_t cvInfoLen = 0;
    uint8_t* cvInfo = openMerkleTree(treeCv, missingLeaves, missingLeavesSize, &cvInfoLen);
    sig->cvInfo = cvInfo;
    sig->cvInfoLen = cvInfoLen;
    free(missingLeaves);

    /* Reveal iSeeds for unopned rounds, those in {0..T-1} \ ChallengeC. */
    sig->iSeedInfo = malloc(params->numMPCRounds * params->seedSizeBytes);
    sig->iSeedInfoLen = revealSeeds(iSeedsTree, challengeC, params->numOpenedRounds,
                                    sig->iSeedInfo, params->numMPCRounds * params->seedSizeBytes, params);
    sig->iSeedInfo = realloc(sig->iSeedInfo, sig->iSeedInfoLen);

    /* Assemble the proof */
    proof2_t* proofs = sig->proofs;
#ifndef OMP_KKW
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(challengeC, params->numOpenedRounds, t)) {
            allocateProof2(&proofs[t], params);
            size_t P_index = indexOf(challengeC, params->numOpenedRounds, t);

            uint16_t hideList[1];
            hideList[0] = challengeP[P_index];
            proofs[t].seedInfo = malloc(params->numMPCParties * params->seedSizeBytes);
            proofs[t].seedInfoLen = revealSeeds(seeds[t], hideList, 1, proofs[t].seedInfo, params->numMPCParties * params->seedSizeBytes, params);
            proofs[t].seedInfo = realloc(proofs[t].seedInfo, proofs[t].seedInfoLen);

            size_t last = params->numMPCParties - 1;
            if (challengeP[P_index] != last) {
                getAuxBits(proofs[t].aux, &tapes[t], params);
            }
            memcpy(proofs[t].input, inputs[t], params->stateSizeBytes);
            memcpy(proofs[t].msgs, msgs[t].msgs[challengeP[P_index]], params->andSizeBytes + params->stateSizeBytes );
            memcpy(proofs[t].C, C[t].hashes[challengeP[P_index]], params->digestSizeBytes);
        }
    }
#else
#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        if (contains(challengeC, params->numOpenedRounds, t)) {
            allocateProof2(&proofs[t], params);
            size_t P_index = indexOf(challengeC, params->numOpenedRounds, t);

            uint16_t hideList[1];
            hideList[0] = challengeP[P_index];
            proofs[t].seedInfo = malloc(params->numMPCParties * params->seedSizeBytes);
            proofs[t].seedInfoLen = revealSeeds(seeds[t], hideList, 1, proofs[t].seedInfo, params->numMPCParties * params->seedSizeBytes, params);
            proofs[t].seedInfo = realloc(proofs[t].seedInfo, proofs[t].seedInfoLen);

            size_t last = params->numMPCParties - 1;
            if (challengeP[P_index] != last) {
                getAuxBits(proofs[t].aux, &tapes[t], params);
            }
            memcpy(proofs[t].input, inputs[t], params->stateSizeBytes);
            memcpy(proofs[t].msgs, msgs[t].msgs[challengeP[P_index]], params->andSizeBytes + params->stateSizeBytes);
            memcpy(proofs[t].C, C[t].hashes[challengeP[P_index]], params->digestSizeBytes);
        }
    }
#endif

#if 0
    printf("\n-----------------\n\nSelf-Test, trying to verify signature:\n");
    int ret = verify_picnic2(sig, pubKey, plaintext, message, messageByteLength, params);
    if (ret != 0) {
        printf("Verification failed; signature invalid\n");
        ret = -1;
    }
    else {
        printf("Verification succeeded\n\n");
    }
    printf("-----------------\n\nSelf-Test complete\n");

#endif

#pragma omp parallel for schedule(guided)
    for (t = 0; t < params->numMPCRounds; t++) {
        freeRandomTape(&tapes[t]);
        freeTree(seeds[t]);
    }
#pragma omp parallel sections
    {
#pragma omp section
        free(tapes);
#pragma omp section
        free(seeds);
#pragma omp section
        freeTree(iSeedsTree);
#pragma omp section
        freeTree(treeCv);
#pragma omp section
        freeCommitments(C);
#pragma omp section
        freeCommitments2(&Ch);
#pragma omp section
        freeCommitments2(&Cv);
#pragma omp section
        freeInputs(inputs);
#pragma omp section
        freeMsgs(msgs);
    }
    end = clock();
    acc = (double)(end - start);
    printf("在线阶段：%lf ms\n", acc);

    return ret;

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

int deserializeSignature2(signature2_t* sig, const uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params)
{
    /* Read the challenge and salt */
    size_t bytesRequired = 4 * params->numOpenedRounds + params->saltSizeBytes;

    if (sigBytesLen < bytesRequired) {
        return EXIT_FAILURE;
    }

    memcpy(sig->challengeC, sigBytes, 2 * params->numOpenedRounds);
    sigBytes += 2 * params->numOpenedRounds;
    memcpy(sig->challengeP, sigBytes, 2 * params->numOpenedRounds);
    sigBytes += 2 * params->numOpenedRounds;
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
    sig->iSeedInfoLen = revealSeedsSize(params->numMPCRounds, sig->challengeC, params->numOpenedRounds, params);
    bytesRequired += sig->iSeedInfoLen;

    /* Add the size of the Cv Merkle tree data */
    size_t missingLeavesSize = params->numMPCRounds - params->numOpenedRounds;
    uint16_t* missingLeaves = getMissingLeavesList(sig->challengeC, params);
    sig->cvInfoLen = openMerkleTreeSize(params->numMPCRounds, missingLeaves, missingLeavesSize, params);
    bytesRequired += sig->cvInfoLen;
    free(missingLeaves);

    /* Compute the number of bytes required for the proofs */
    uint16_t hideList[1] = { 0 };
    size_t seedInfoLen = revealSeedsSize(params->numMPCParties, hideList, 1, params);
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            size_t P_t = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            if (P_t != (params->numMPCParties - 1)) {
                bytesRequired += params->andSizeBytes;
            }
            bytesRequired += params->digestSizeBytes;
            bytesRequired += params->stateSizeBytes;
            bytesRequired += params->stateSizeBytes + params->andSizeBytes;
            bytesRequired += seedInfoLen;
        }
    }

    /* Fail if the signature does not have the exact number of bytes we expect */
    if (sigBytesLen != bytesRequired) {
        printf("%s: sigBytesLen = %lu, expected bytesRequired = %lu\n", __func__, sigBytesLen, bytesRequired);
        return EXIT_FAILURE;
    }

    sig->iSeedInfo = malloc(sig->iSeedInfoLen);
    memcpy(sig->iSeedInfo, sigBytes, sig->iSeedInfoLen);
    sigBytes += sig->iSeedInfoLen;

    sig->cvInfo = malloc(sig->cvInfoLen);
    memcpy(sig->cvInfo, sigBytes, sig->cvInfoLen);
    sigBytes += sig->cvInfoLen;

    /* Read the proofs */
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            allocateProof2(&sig->proofs[t], params);
            sig->proofs[t].seedInfoLen = seedInfoLen;
            sig->proofs[t].seedInfo = malloc(sig->proofs[t].seedInfoLen);
            memcpy(sig->proofs[t].seedInfo, sigBytes, sig->proofs[t].seedInfoLen);
            sigBytes += sig->proofs[t].seedInfoLen;

            size_t P_t = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            if (P_t != (params->numMPCParties - 1) ) {
                memcpy(sig->proofs[t].aux, sigBytes, params->andSizeBytes);
                sigBytes += params->andSizeBytes;
                if (!arePaddingBitsZero(sig->proofs[t].aux, params->andSizeBytes, 64 * params->numRounds * params->numSboxes)) {
                    printf("%s: failed while deserializing aux bits\n", __func__);
                    return -1;
                }
            }

            memcpy(sig->proofs[t].input, sigBytes, params->seedSizeBytes);
            sigBytes += params->stateSizeBytes;

            size_t msgsByteLength = params->stateSizeBytes + params->andSizeBytes;
            memcpy(sig->proofs[t].msgs, sigBytes, msgsByteLength);
            sigBytes += msgsByteLength;
            size_t msgsBitLength = params->stateSizeBits + 64 * params->numRounds * params->numSboxes;
            if (!arePaddingBitsZero(sig->proofs[t].msgs, msgsByteLength, msgsBitLength)) {
                printf("%s: failed while deserializing msgs bits\n", __func__);
                return -1;
            }

            memcpy(sig->proofs[t].C, sigBytes, params->digestSizeBytes);
            sigBytes += params->digestSizeBytes;
        }
    }

    return EXIT_SUCCESS;
}

int serializeSignature2(const signature2_t* sig, uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params)
{
    uint8_t* sigBytesBase = sigBytes;

    /* Compute the number of bytes required for the signature */
    size_t bytesRequired = 4 * params->numOpenedRounds + params->saltSizeBytes; /* challenge and salt */

    bytesRequired += sig->iSeedInfoLen;                                         /* Encode only iSeedInfo, the length will be recomputed by deserialize */
    bytesRequired += sig->cvInfoLen;

    for (size_t t = 0; t < params->numMPCRounds; t++) {   /* proofs */
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            size_t P_t = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];
            bytesRequired += sig->proofs[t].seedInfoLen;
            if (P_t != (params->numMPCParties - 1)) {
                bytesRequired += params->andSizeBytes;
            }
            bytesRequired += params->digestSizeBytes;
            bytesRequired += params->stateSizeBytes;
            bytesRequired += params->stateSizeBytes + params->andSizeBytes;
        }
    }

    if (sigBytesLen < bytesRequired) {
        return -1;
    }

    memcpy(sigBytes, sig->challengeC, 2 * params->numOpenedRounds);
    uint16_t* challengeC = (uint16_t*)sigBytes;
    sigBytes += 2 * params->numOpenedRounds;
    memcpy(sigBytes, sig->challengeP, 2 * params->numOpenedRounds);
    uint16_t* challengeP = (uint16_t*)sigBytes;
    sigBytes += 2 * params->numOpenedRounds;
    memcpy(sigBytes, sig->salt, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numOpenedRounds; i++) {
        challengeC[i] = fromLittleEndian(sig->challengeC[i]);
        challengeP[i] = fromLittleEndian(sig->challengeP[i]);
    }

    memcpy(sigBytes, sig->iSeedInfo, sig->iSeedInfoLen);
    sigBytes += sig->iSeedInfoLen;
    memcpy(sigBytes, sig->cvInfo, sig->cvInfoLen);
    sigBytes += sig->cvInfoLen;

    /* Write the proofs */
    for (size_t t = 0; t < params->numMPCRounds; t++) {
        if (contains(sig->challengeC, params->numOpenedRounds, t)) {
            memcpy(sigBytes, sig->proofs[t].seedInfo,  sig->proofs[t].seedInfoLen);
            sigBytes += sig->proofs[t].seedInfoLen;

            size_t P_t = sig->challengeP[indexOf(sig->challengeC, params->numOpenedRounds, t)];

            if (P_t != (params->numMPCParties - 1) ) {
                memcpy(sigBytes, sig->proofs[t].aux, params->andSizeBytes);
                sigBytes += params->andSizeBytes;
            }

            memcpy(sigBytes, sig->proofs[t].input, params->seedSizeBytes);
            sigBytes += params->stateSizeBytes;

            memcpy(sigBytes, sig->proofs[t].msgs, params->stateSizeBytes + params->andSizeBytes);
            sigBytes += params->stateSizeBytes + params->andSizeBytes;

            memcpy(sigBytes, sig->proofs[t].C, params->digestSizeBytes);
            sigBytes += params->digestSizeBytes;
        }
    }

    return (int)(sigBytes - sigBytesBase);
}






