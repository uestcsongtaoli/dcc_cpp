#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

// Pre-computed SM4 round keys
struct SM4Ctx {
    uint32_t rk[32];
};

// Expand 16-byte key into round keys
void sm4_init(SM4Ctx& ctx, const uint8_t key[16]);

// SM4-CBC encrypt with PKCS7 padding
// key/iv: 16 bytes each; returns ciphertext
std::vector<uint8_t> sm4_cbc_encrypt(const SM4Ctx& ctx, const uint8_t iv[16],
                                      const uint8_t* plaintext, size_t len);

// Zero-allocation version: writes ciphertext into caller-supplied buffer.
// out must have at least (len/16 + 1)*16 bytes of space.
// Returns number of ciphertext bytes written.
size_t sm4_cbc_encrypt_into(const SM4Ctx& ctx, const uint8_t iv[16],
                             const uint8_t* pt, size_t len, uint8_t* out);

// Bytes → uppercase hex string (e.g. {0x1A,0xBC} → "1ABC")
std::string bytes_to_hex_upper(const uint8_t* data, size_t len);
