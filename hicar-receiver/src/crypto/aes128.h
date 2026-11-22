#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hicar {

// AES-128-CFB128（NIST SP 800-38A 6.3 节，等价 JCE 的 AES/CFB/NoPadding）。
// CFB 加解密都只用 AES 的正向分组加密，不需要逆变换。
constexpr size_t kAesBlockSize = 16;

// 单块加密：key 16 字节、in/out 16 字节（out 可与 in 相同）。
void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

// CFB128：输出与输入等长。encrypt 与 decrypt 互为逆运算。
std::vector<uint8_t> aes128_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t* data,
                                        size_t size);
std::vector<uint8_t> aes128_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t* data,
                                        size_t size);

}  // namespace hicar
