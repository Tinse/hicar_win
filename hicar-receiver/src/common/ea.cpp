#include "common/ea.h"

#include <stdexcept>

namespace hicar {

size_t ea_encoded_size(uint32_t value) {
  if (value > kEaMaxValue) throw std::invalid_argument("EA 取值越界");
  size_t size = 1;
  for (uint32_t rest = value >> 7; rest != 0; rest >>= 7) ++size;
  return size;
}

void ea_encode(uint32_t value, uint8_t* out) {
  const size_t n = ea_encoded_size(value);
  uint32_t rest = value;
  for (size_t i = 0; i < n; ++i) {
    const uint32_t group = rest & 0x7F;
    rest >>= 7;
    out[i] = static_cast<uint8_t>(i == n - 1 ? (group | 0x80) : group);
  }
}

EaDecoded ea_decode(const uint8_t* data, size_t size, size_t offset, size_t limit) {
  if (offset > size || limit > size || offset > limit) throw std::invalid_argument("EA 范围非法");
  EaDecoded out;
  uint32_t value = 0;
  for (int i = 0; i < kEaMaxBytes; ++i) {
    const size_t pos = offset + static_cast<size_t>(i);
    if (pos >= limit) {
      out.status = EaStatus::kNeedMore;
      return out;
    }
    const uint8_t b = data[pos];
    value |= static_cast<uint32_t>(b & 0x7F) << (7 * i);
    if ((b & 0x80) != 0) {
      out.status = EaStatus::kOk;
      out.value = value;
      out.size = static_cast<uint8_t>(i + 1);
      return out;
    }
  }
  out.status = EaStatus::kUnterminated;
  return out;
}

}  // namespace hicar
