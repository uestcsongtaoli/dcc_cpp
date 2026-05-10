#pragma once
#include "sm4.h"
#include <cstddef>

// Runtime check: true if CPU supports AVX-512F.
bool cpu_has_avx512f();

// Encrypt 16 independent SM4-CBC chains in parallel using the same key and IV.
//
// Each chain i:  plaintext  = pt[i][0 .. pt_len[i]-1]
//                ciphertext = ct[i][0 .. ct_len[i]-1]  (PKCS7-padded)
//
// ct[i] must point to a buffer of at least (pt_len[i]/16 + 1)*16 bytes.
// ct_len[i] is written on return; it is 0 when pt_len[i] == 0.
//
// When compiled without __AVX512F__ (e.g. macOS / ARM) the function
// falls back to 16 sequential scalar calls.
void sm4_cbc_encrypt_x16(
    const SM4Ctx&        ctx,
    const uint8_t        iv[16],
    const uint8_t* const pt[16],
    const size_t         pt_len[16],
    uint8_t* const       ct[16],
    size_t               ct_len[16]);
