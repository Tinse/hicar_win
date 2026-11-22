#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace hicar {

std::string to_hex(const uint8_t* data, size_t size);
std::string to_hex(const std::vector<uint8_t>& data);
std::string to_hex_upper(const uint8_t* data, size_t size);  // 大写，deviceId 用
std::string to_hex_upper(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_hex(std::string_view text);  // 允许分隔符以外的空白，长度必须为偶数

}  // namespace hicar
