#include "nearby/cipher.h"

#include <memory>

#include "common/error.h"
#include "crypto/aes128.h"
#include "crypto/sha256.h"

namespace hicar {

NearbyFrameCipher::NearbyFrameCipher(const NearbyKeyMaterial& keys) {
  const size_t n = keys.root_key.size();
  if (n < kMinKeyMaterial || keys.const_a.size() != n || keys.const_b.size() != n) {
    throw std::invalid_argument("nearby 密钥材料每段长度必须相同且不少于 5 字节");
  }

  std::vector<uint8_t> h1(n);
  for (size_t i = 0; i < n; ++i) {
    h1[i] = static_cast<uint8_t>(keys.const_a[(i + 3) % n] ^ keys.const_b[i]);
  }
  derived_root_.resize(n);
  for (size_t i = 0; i < n; ++i) {
    derived_root_[i] = static_cast<uint8_t>(h1[(i + n - 5) % n] ^ keys.root_key[i]);
  }
}

std::vector<uint8_t> NearbyFrameCipher::frame_key(const std::vector<uint8_t>& seed) const {
  if (seed.size() != NearbyFrame::kSeedLength) throw std::invalid_argument("种子应为 8 字节");
  const Sha256Digest mac = hmac_sha256(derived_root_, seed);
  return std::vector<uint8_t>(mac.begin(), mac.end());
}

std::vector<uint8_t> NearbyFrameCipher::encrypt(const std::vector<uint8_t>& plain,
                                                const std::vector<uint8_t>& seed) const {
  const std::vector<uint8_t> e = frame_key(seed);
  return aes128_cfb_encrypt(e.data(), e.data() + 16, plain.data(), plain.size());
}

std::vector<uint8_t> NearbyFrameCipher::decrypt(const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& seed) const {
  const std::vector<uint8_t> e = frame_key(seed);
  return aes128_cfb_decrypt(e.data(), e.data() + 16, ciphertext.data(), ciphertext.size());
}

NearbyFrame NearbyFrameCipher::seal(uint32_t outer_type, const std::vector<uint8_t>& plain,
                                    const std::vector<uint8_t>& seed) const {
  return NearbyFrame::encrypted(outer_type, encrypt(plain, seed), seed);
}

std::vector<uint8_t> NearbyFrameCipher::open(const NearbyFrame& frame) const {
  if (!frame.is_encrypted()) return frame.payload();
  return decrypt(frame.payload(), frame.seed());
}

}  // namespace hicar
