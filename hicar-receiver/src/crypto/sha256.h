#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace hicar {

// SHA-256 / HMAC-SHA256（FIPS 180-4、RFC 2104）。控制帧加密与 deviceId 派生都要用。
using Sha256Digest = std::array<uint8_t, 32>;

Sha256Digest sha256(const uint8_t* data, size_t size);
Sha256Digest sha256(const std::vector<uint8_t>& data);

Sha256Digest hmac_sha256(const uint8_t* key, size_t key_size, const uint8_t* data, size_t data_size);
Sha256Digest hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

}  // namespace hicar
