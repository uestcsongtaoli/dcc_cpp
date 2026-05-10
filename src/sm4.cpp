#include "sm4.h"
#include <cstring>

// ─── SM4 constants ────────────────────────────────────────────────────────────

static const uint8_t SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static const uint32_t FK[4] = {
    0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu
};

static const uint32_t CK[32] = {
    0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
    0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
    0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
    0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
    0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
    0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
    0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
    0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u
};

// ─── Helpers (used only during T-box build) ───────────────────────────────────

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// L  — linear transform for encryption rounds
static inline uint32_t L(uint32_t b) {
    return b ^ rotl32(b,2) ^ rotl32(b,10) ^ rotl32(b,18) ^ rotl32(b,24);
}

// L' — linear transform for key schedule
static inline uint32_t Lprime(uint32_t b) {
    return b ^ rotl32(b,13) ^ rotl32(b,23);
}

// ─── T-box tables (built once at startup) ────────────────────────────────────
//
// Idea: T(x) = L(τ(x))
// L is linear over GF(2), so for x with bytes (a,b,c,d):
//   T(x) = L(S[a]<<24) ^ L(S[b]<<16) ^ L(S[c]<<8) ^ L(S[d])
//        = TT[0][a]    ^ TT[1][b]    ^ TT[2][c]   ^ TT[3][d]
//
// Each table is 256 × 4 bytes = 1 KB; all 4 tables = 4 KB → fits in L1 cache.
// Same trick applied to T'(x) for key schedule → TK[0..3][].
//
// Net effect: 4 lookups + 3 XOR  vs  4 S-box + 4 shifts + 4 ORs + 5 XOR + 4 rotates

uint32_t        TT[4][256];  // for encryption  (uses L) — extern'd by sm4_avx512.cpp
static uint32_t TK[4][256];  // for key schedule (uses L')

static void build_tboxes() {
    for (int i = 0; i < 256; i++) {
        uint32_t s = SBOX[i];
        TT[0][i] = L(s << 24);  TK[0][i] = Lprime(s << 24);
        TT[1][i] = L(s << 16);  TK[1][i] = Lprime(s << 16);
        TT[2][i] = L(s <<  8);  TK[2][i] = Lprime(s <<  8);
        TT[3][i] = L(s      );  TK[3][i] = Lprime(s      );
    }
}

// C++11 guarantees this runs before main(), thread-safe
static bool s_tbox_ready = (build_tboxes(), true);

// ─── Hot-path T functions (now just 4 lookups + 3 XOR) ───────────────────────

static inline uint32_t T_enc(uint32_t x) {
    return TT[0][(x >> 24)       ]
         ^ TT[1][(x >> 16) & 0xff]
         ^ TT[2][(x >>  8) & 0xff]
         ^ TT[3][ x        & 0xff];
}

static inline uint32_t T_key(uint32_t x) {
    return TK[0][(x >> 24)       ]
         ^ TK[1][(x >> 16) & 0xff]
         ^ TK[2][(x >>  8) & 0xff]
         ^ TK[3][ x        & 0xff];
}

// ─── I/O helpers ─────────────────────────────────────────────────────────────

static inline uint32_t load32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static inline void store32be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}

// ─── Public API ───────────────────────────────────────────────────────────────

void sm4_init(SM4Ctx& ctx, const uint8_t key[16]) {
    (void)s_tbox_ready; // ensure tables are built
    uint32_t K[4] = {
        load32be(key)      ^ FK[0],
        load32be(key +  4) ^ FK[1],
        load32be(key +  8) ^ FK[2],
        load32be(key + 12) ^ FK[3],
    };
    for (int i = 0; i < 32; i++) {
        uint32_t t = T_key(K[1] ^ K[2] ^ K[3] ^ CK[i]);
        ctx.rk[i] = K[0] ^ t;
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = ctx.rk[i];
    }
}

static void sm4_encrypt_block(const SM4Ctx& ctx, const uint8_t in[16], uint8_t out[16]) {
    uint32_t X[4] = {
        load32be(in),    load32be(in+4),
        load32be(in+8),  load32be(in+12)
    };
    for (int i = 0; i < 32; i++) {
        uint32_t nx = X[0] ^ T_enc(X[1] ^ X[2] ^ X[3] ^ ctx.rk[i]);
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = nx;
    }
    store32be(out,    X[3]); store32be(out+4,  X[2]);
    store32be(out+8,  X[1]); store32be(out+12, X[0]);
}

std::vector<uint8_t> sm4_cbc_encrypt(const SM4Ctx& ctx, const uint8_t iv[16],
                                      const uint8_t* pt, size_t len) {
    size_t pad   = 16 - (len % 16);
    size_t total = len + pad;

    std::vector<uint8_t> buf(total);
    memcpy(buf.data(), pt, len);
    memset(buf.data() + len, (uint8_t)pad, pad);

    std::vector<uint8_t> out(total);
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t i = 0; i < total; i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) block[j] = buf[i+j] ^ prev[j];
        sm4_encrypt_block(ctx, block, out.data() + i);
        memcpy(prev, out.data() + i, 16);
    }
    return out;
}

size_t sm4_cbc_encrypt_into(const SM4Ctx& ctx, const uint8_t iv[16],
                             const uint8_t* pt, size_t len, uint8_t* out)
{
    uint8_t tmp[256]; // plaintext + PKCS7 padding; enough for ≤240-byte inputs
    size_t pad   = 16 - (len % 16);
    size_t total = len + pad;
    if (total > sizeof(tmp)) {
        // Fallback for unexpectedly large fields (not seen in our CSV schema)
        auto ct = sm4_cbc_encrypt(ctx, iv, pt, len);
        memcpy(out, ct.data(), ct.size());
        return ct.size();
    }
    memcpy(tmp, pt, len);
    memset(tmp + len, (uint8_t)pad, pad);

    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < total; i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) block[j] = tmp[i+j] ^ prev[j];
        sm4_encrypt_block(ctx, block, out + i);
        memcpy(prev, out + i, 16);
    }
    return total;
}

std::string bytes_to_hex_upper(const uint8_t* data, size_t len) {
    static const char HEX[] = "0123456789ABCDEF";
    std::string s(len * 2, '\0');
    for (size_t i = 0; i < len; i++) {
        s[i*2]   = HEX[data[i] >> 4];
        s[i*2+1] = HEX[data[i] & 0xf];
    }
    return s;
}
