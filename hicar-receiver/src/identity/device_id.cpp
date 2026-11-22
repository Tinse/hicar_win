#include "identity/device_id.h"

#include <cstring>

#include "common/hex.h"
#include "crypto/sha256.h"

namespace hicar {

std::array<uint8_t, 32> derive_device_id(const std::array<uint8_t, 3>& model_id, uint8_t sub_model_id,
                                         const std::array<uint8_t, 6>& bluetooth_address) {
  static const std::array<uint8_t, 6> kUnavailable = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};

  std::array<uint8_t, 10> material{};
  std::memcpy(material.data(), model_id.data(), 3);
  material[3] = sub_model_id;
  if (bluetooth_address != kUnavailable) {
    std::memcpy(material.data() + 4, bluetooth_address.data(), 6);
  }

  const std::string text = to_hex_upper(material.data(), material.size());
  const Sha256Digest digest = sha256(reinterpret_cast<const uint8_t*>(text.data()), text.size());
  std::array<uint8_t, 32> out{};
  std::memcpy(out.data(), digest.data(), out.size());
  return out;
}

std::string device_id_hex(const std::array<uint8_t, 32>& device_id) {
  return to_hex_upper(device_id.data(), device_id.size());
}

}  // namespace hicar
