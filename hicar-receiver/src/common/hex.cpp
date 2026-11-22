#include "common/hex.h"

#include <stdexcept>

namespace hicar {

namespace {
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
}  // namespace

std::string to_hex(const uint8_t* data, size_t size) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0F]);
  }
  return out;
}

std::string to_hex(const std::vector<uint8_t>& data) { return to_hex(data.data(), data.size()); }

namespace {
std::string to_hex_impl(const uint8_t* data, size_t size, const char* digits) {
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 0x0F]);
  }
  return out;
}
}  // namespace

std::string to_hex_upper(const uint8_t* data, size_t size) {
  return to_hex_impl(data, size, "0123456789ABCDEF");
}

std::string to_hex_upper(const std::vector<uint8_t>& data) { return to_hex_upper(data.data(), data.size()); }

std::vector<uint8_t> from_hex(std::string_view text) {
  std::vector<uint8_t> out;
  int hi = -1;
  for (char c : text) {
    if (c == ' ' || c == ':' || c == '-' || c == '_' || c == '\n' || c == '\r' || c == '\t') continue;
    const int v = nibble(c);
    if (v < 0) throw std::invalid_argument("十六进制字符串含非法字符");
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(static_cast<uint8_t>((hi << 4) | v));
      hi = -1;
    }
  }
  if (hi >= 0) throw std::invalid_argument("十六进制字符串长度为奇数");
  return out;
}

}  // namespace hicar
