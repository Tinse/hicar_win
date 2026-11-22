#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hicar {

// 控制帧里的 TLV：EA(tag) EA(长度) 值。通道管理、资源层、消息层的载荷以及帧标志段都用它。
struct Tlv {
  uint32_t tag = 0;
  std::vector<uint8_t> value;
};

// 拆整段字节；结构不完整抛 MalformedMessage。
std::vector<Tlv> parse_tlvs(const uint8_t* data, size_t size);
std::vector<Tlv> parse_tlvs(const std::vector<uint8_t>& data);

// 单条 TLV 编码。
std::vector<uint8_t> encode_tlv(uint32_t tag, const std::vector<uint8_t>& value);
std::vector<uint8_t> encode_tlv(uint32_t tag);

}  // namespace hicar
