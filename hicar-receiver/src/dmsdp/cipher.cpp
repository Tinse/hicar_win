#include "dmsdp/cipher.h"

#include <string>

#include "common/error.h"
#include "crypto/aes128.h"

namespace hicar {
namespace dmsdp {
namespace {

void increment_counter(uint8_t counter[16]) {
  for (size_t i = 16; i-- > 0;) {
    ++counter[i];
    if (counter[i] != 0) return;
  }
}

}  // namespace

std::vector<uint8_t> aes128_ctr_crypt(const uint8_t key[16], const uint8_t iv[16],
                                      const uint8_t* data, size_t size) {
  std::vector<uint8_t> out(size);
  uint8_t counter[16];
  for (size_t i = 0; i < 16; ++i) counter[i] = iv[i];

  size_t offset = 0;
  while (offset < size) {
    uint8_t stream[16];
    aes128_encrypt_block(key, counter, stream);
    const size_t take = size - offset < 16 ? size - offset : 16;
    for (size_t i = 0; i < take; ++i) {
      out[offset + i] = static_cast<uint8_t>(data[offset + i] ^ stream[i]);
    }
    offset += take;
    increment_counter(counter);
  }
  return out;
}

std::vector<uint8_t> seal_control_payload(const uint8_t key[16], const uint8_t iv[16],
                                          const std::vector<uint8_t>& plain) {
  if (plain.empty()) throw std::invalid_argument("控制载荷不能为空");
  std::vector<uint8_t> sealed(iv, iv + 16);
  const auto cipher = aes128_ctr_crypt(key, iv, plain.data(), plain.size());
  sealed.insert(sealed.end(), cipher.begin(), cipher.end());
  return sealed;
}

std::vector<uint8_t> open_control_payload(const uint8_t key[16], const std::vector<uint8_t>& sealed) {
  if (sealed.size() < 16) throw MalformedMessage("加密控制载荷不足 16 字节 IV");
  const auto plain = aes128_ctr_crypt(key, sealed.data(), sealed.data() + 16, sealed.size() - 16);
  return plain;
}

}  // namespace dmsdp
}  // namespace hicar
