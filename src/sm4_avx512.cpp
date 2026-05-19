#include "sm4_avx512.h"
#include <immintrin.h>
#include <cstring>

// T-box tables built at startup by sm4.cpp (non-static there, extern here).
extern uint32_t TT[4][256];

static inline uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}
static inline void store_be32(uint8_t* p, uint32_t v) {
    p[0]=(v>>24)&0xff; p[1]=(v>>16)&0xff; p[2]=(v>>8)&0xff; p[3]=v&0xff;
}

// T transform for 16 parallel 32-bit words (one per ZMM lane).
// 4 gathers + 3 XOR — identical logic to scalar T_enc, but 16× throughput.
static inline __m512i T_enc_x16(__m512i x) {
    const __m512i m = _mm512_set1_epi32(0xff);
    __m512i b0 = _mm512_srli_epi32(x, 24);
    __m512i b1 = _mm512_and_si512(_mm512_srli_epi32(x, 16), m);
    __m512i b2 = _mm512_and_si512(_mm512_srli_epi32(x,  8), m);
    __m512i b3 = _mm512_and_si512(x, m);
    __m512i r0 = _mm512_i32gather_epi32(b0, (const int*)TT[0], 4);
    __m512i r1 = _mm512_i32gather_epi32(b1, (const int*)TT[1], 4);
    __m512i r2 = _mm512_i32gather_epi32(b2, (const int*)TT[2], 4);
    __m512i r3 = _mm512_i32gather_epi32(b3, (const int*)TT[3], 4);
    return _mm512_xor_epi32(_mm512_xor_epi32(r0, r1), _mm512_xor_epi32(r2, r3));
}

// SM4 block cipher on 16 independent 16-byte blocks.
// st[j] holds word-j from all 16 blocks (column-major).
// On return, st[j] holds the corresponding ciphertext words.
static void sm4_ecb_x16(const SM4Ctx& ctx, __m512i st[4]) {
    __m512i X0=st[0], X1=st[1], X2=st[2], X3=st[3];
    for (int i = 0; i < 32; ++i) {
        __m512i rk = _mm512_set1_epi32(ctx.rk[i]);
        __m512i nx = _mm512_xor_epi32(X0, T_enc_x16(
            _mm512_xor_epi32(_mm512_xor_epi32(X1, X2),
                             _mm512_xor_epi32(X3, rk))));
        X0=X1; X1=X2; X2=X3; X3=nx;
    }
    // SM4 output reversal: (X3, X2, X1, X0)
    st[0]=X3; st[1]=X2; st[2]=X1; st[3]=X0;
}

// ── nopad variant ─────────────────────────────────────────────────────────────
// Inputs are already PKCS7-padded.  Reads directly from pt[i] — no staging copy.
// ct_len[i] must be a multiple of 16.
void sm4_cbc_encrypt_x16_nopad(
    const SM4Ctx&        ctx,
    const uint8_t        iv[16],
    const uint8_t* const pt[16],
    const size_t         ct_len[16],
    uint8_t* const       ct[16])
{
    size_t max_total = 0;
    for (int i = 0; i < 16; ++i)
        if (ct_len[i] > max_total) max_total = ct_len[i];
    if (max_total == 0) return;

    uint32_t iv_w[4];
    for (int j = 0; j < 4; ++j) iv_w[j] = load_be32(iv + j*4);

    alignas(64) uint32_t prev[4][16];
    for (int j = 0; j < 4; ++j)
        for (int i = 0; i < 16; ++i)
            prev[j][i] = iv_w[j];

    alignas(64) uint32_t col[16];
    alignas(64) uint32_t ct_col[16];
    for (size_t off = 0; off < max_total; off += 16) {
        __m512i st[4];
        for (int j = 0; j < 4; ++j) {
            for (int i = 0; i < 16; ++i) {
                uint32_t pt_w = (off < ct_len[i]) ? load_be32(pt[i] + off + j*4) : 0u;
                col[i] = pt_w ^ prev[j][i];
            }
            st[j] = _mm512_load_si512((const __m512i*)col);
        }
        sm4_ecb_x16(ctx, st);
        for (int j = 0; j < 4; ++j) {
            _mm512_store_si512((__m512i*)ct_col, st[j]);
            for (int i = 0; i < 16; ++i) {
                prev[j][i] = ct_col[i];
                if (off < ct_len[i])
                    store_be32(ct[i] + off + j*4, ct_col[i]);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
void sm4_cbc_encrypt_x16(
    const SM4Ctx&        ctx,
    const uint8_t        iv[16],
    const uint8_t* const pt[16],
    const size_t         pt_len[16],
    uint8_t* const       ct[16],
    size_t               ct_len[16])
{
    // PKCS7-pad each plaintext into staging[chain][byte].
    // Largest SM4 field in our CSV ≤ 18 bytes → ciphertext ≤ 32 bytes (2 blocks).
    // 64-byte buffer per chain (4 blocks) gives ample headroom.
    alignas(64) uint8_t stg[16][64];
    size_t ctotal[16];
    size_t max_total = 0;

    for (int i = 0; i < 16; ++i) {
        if (pt_len[i] == 0) { ct_len[i] = 0; ctotal[i] = 0; continue; }
        uint8_t pad = (uint8_t)(16 - (pt_len[i] & 15u));
        ctotal[i]  = pt_len[i] + pad;
        ct_len[i]  = ctotal[i];
        if (ctotal[i] > max_total) max_total = ctotal[i];
        memcpy(stg[i], pt[i], pt_len[i]);
        memset(stg[i] + pt_len[i], pad, pad);
    }
    if (max_total == 0) return;

    // Parse IV into 4 big-endian words.
    uint32_t iv_w[4];
    for (int j = 0; j < 4; ++j) iv_w[j] = load_be32(iv + j*4);

    // CBC carry: prev[word][chain]
    alignas(64) uint32_t prev[4][16];
    for (int j = 0; j < 4; ++j)
        for (int i = 0; i < 16; ++i)
            prev[j][i] = iv_w[j];

    // One SM4 block (16 bytes) per iteration, all 16 chains in parallel.
    alignas(64) uint32_t col[16];
    alignas(64) uint32_t ct_col[16];
    for (size_t off = 0; off < max_total; off += 16) {
        // Build column-major state: XOR plaintext with CBC carry.
        __m512i st[4];
        for (int j = 0; j < 4; ++j) {
            for (int i = 0; i < 16; ++i) {
                uint32_t pt_w = (off < ctotal[i]) ? load_be32(stg[i] + off + j*4) : 0u;
                col[i] = pt_w ^ prev[j][i];
            }
            st[j] = _mm512_load_si512((const __m512i*)col);
        }

        sm4_ecb_x16(ctx, st);

        // Extract ciphertext, update CBC carry, write output.
        for (int j = 0; j < 4; ++j) {
            _mm512_store_si512((__m512i*)ct_col, st[j]);
            for (int i = 0; i < 16; ++i) {
                prev[j][i] = ct_col[i];
                if (off < ctotal[i])
                    store_be32(ct[i] + off + j*4, ct_col[i]);
            }
        }
    }
}
