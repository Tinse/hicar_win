#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace hicar::auth {

using Bytes = std::vector<uint8_t>;

Bytes sha256(std::span<const uint8_t> data);
Bytes sha256_parts(const std::vector<Bytes>& parts);
Bytes hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data);
Bytes hkdf_sha256(std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
                  std::span<const uint8_t> info, size_t length);

// 输出 = 密文 || 16 字节标签。
Bytes aes_gcm_encrypt(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                      std::span<const uint8_t> aad, std::span<const uint8_t> plain);
bool aes_gcm_decrypt(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                     std::span<const uint8_t> aad, std::span<const uint8_t> cipher_and_tag,
                     Bytes* out);

Bytes ed25519_public_from_seed(std::span<const uint8_t> seed);
Bytes ed25519_sign(std::span<const uint8_t> seed, std::span<const uint8_t> message);
bool ed25519_verify(std::span<const uint8_t> public_key, std::span<const uint8_t> message,
                    std::span<const uint8_t> signature);

Bytes x25519_public_from_private(std::span<const uint8_t> private_key);
bool x25519_agree(std::span<const uint8_t> private_key, std::span<const uint8_t> peer_public,
                  Bytes* shared);

// RFC 3526 3072 位 MODP：base^exponent mod p，输出定长 length 字节（大端）。
Bytes modp_modpow(std::span<const uint8_t> base, std::span<const uint8_t> exponent, size_t length);
bool modp_is_valid_public(std::span<const uint8_t> value, size_t length);

class RandomSource {
 public:
  virtual ~RandomSource() = default;
  virtual Bytes bytes(size_t count) = 0;
};

class SystemRandom : public RandomSource {
 public:
  Bytes bytes(size_t count) override;
};

// 测试用：SHA-256(seed || BE32(i)) 依次拼接。
class SequenceRandom : public RandomSource {
 public:
  explicit SequenceRandom(std::string seed);
  Bytes bytes(size_t count) override;
  size_t drawn() const { return drawn_; }

 private:
  std::string seed_;
  Bytes block_;
  size_t position_ = 0;
  uint32_t counter_ = 0;
  size_t drawn_ = 0;
};

}  // namespace hicar::auth
