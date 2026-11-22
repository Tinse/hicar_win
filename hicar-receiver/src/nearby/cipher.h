#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nearby/frame.h"

namespace hicar {

// 身份资产里的三段密钥材料（各 16 字节）。
struct NearbyKeyMaterial {
  std::vector<uint8_t> const_a;
  std::vector<uint8_t> const_b;
  std::vector<uint8_t> root_key;
};

// 控制帧载荷的加解密（每帧独立）：
//   h1 = (constA 循环左移 3 字节) XOR constB
//   H  = (h1 循环右移 5 字节) XOR rootKey
//   E  = HMAC-SHA256(key = H, data = 8 字节种子)
//   AES-128-CFB：key = E[0,16)，IV = E[16,32)
class NearbyFrameCipher {
 public:
  static constexpr size_t kMinKeyMaterial = 5;

  explicit NearbyFrameCipher(const NearbyKeyMaterial& keys);

  std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plain, const std::vector<uint8_t>& seed) const;
  std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& seed) const;

  NearbyFrame seal(uint32_t outer_type, const std::vector<uint8_t>& plain,
                   const std::vector<uint8_t>& seed) const;
  std::vector<uint8_t> open(const NearbyFrame& frame) const;

  const std::vector<uint8_t>& derived_root_for_test() const { return derived_root_; }

 private:
  std::vector<uint8_t> frame_key(const std::vector<uint8_t>& seed) const;

  std::vector<uint8_t> derived_root_;
};

}  // namespace hicar
