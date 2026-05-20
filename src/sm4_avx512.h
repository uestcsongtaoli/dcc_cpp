#pragma once
#include "sm4.h"
#include <cstddef>

// Encrypt 16 independent SM4-CBC chains in parallel using AVX-512.
//
// Each chain i:  plaintext  = pt[i][0 .. pt_len[i]-1]
//                ciphertext = ct[i][0 .. ct_len[i]-1]  (PKCS7-padded)
//
// ct[i] must point to a buffer of at least (pt_len[i]/16 + 1)*16 bytes.
// ct_len[i] is written on return; it is 0 when pt_len[i] == 0.
void sm4_cbc_encrypt_x16(
    const SM4Ctx&        ctx,
    const uint8_t        iv[16],
    const uint8_t* const pt[16],
    const size_t         pt_len[16],
    uint8_t* const       ct[16],
    size_t               ct_len[16]);

// Like sm4_cbc_encrypt_x16 but inputs are already PKCS7-padded.
// pt[i] points to ct_len[i] bytes (must be a multiple of 16).
// Reads pt[i] directly — no staging-buffer copy, no re-padding.
void sm4_cbc_encrypt_x16_nopad(
    const SM4Ctx&        ctx,
    const uint8_t        iv[16],
    const uint8_t* const pt[16],
    const size_t         ct_len[16],
    uint8_t* const       ct[16]);

// 32-chain variant: two interleaved ZMM groups to hide gather latency.
// Chains 0-15 from pt[0..15] / ct_len[0..15] / ct[0..15].
// Chains 16-31 from pt[16..31] / ct_len[16..31] / ct[16..31].
void sm4_cbc_encrypt_x32_nopad(
    const SM4Ctx&        ctx,
    const uint8_t        iv[16],
    const uint8_t* const pt[32],
    const size_t         ct_len[32],
    uint8_t* const       ct[32]);
