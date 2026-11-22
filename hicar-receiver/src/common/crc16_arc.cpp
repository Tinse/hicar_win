#include "common/crc16_arc.h"

#include <array>

namespace hicar {

namespace {

constexpr std::array<uint16_t, 256> make_table() {
  std::array<uint16_t, 256> table{};
  for (int n = 0; n < 256; ++n) {
    uint16_t crc = static_cast<uint16_t>(n);
    for (int i = 0; i < 8; ++i) {
      crc = (crc & 1) ? static_cast<uint16_t>((crc >> 1) ^ 0xA001) : static_cast<uint16_t>(crc >> 1);
    }
    table[static_cast<size_t>(n)] = crc;
  }
  return table;
}

constexpr std::array<uint16_t, 256> kTable = make_table();

}  // namespace

uint16_t crc16_arc(const uint8_t* data, size_t size) {
  uint16_t crc = 0;
  for (size_t i = 0; i < size; ++i) {
    crc = static_cast<uint16_t>((crc >> 8) ^ kTable[(crc ^ data[i]) & 0xFF]);
  }
  return crc;
}

}  // namespace hicar
