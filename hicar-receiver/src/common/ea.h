#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hicar {

// EA 变长整数：每字节低 7 位承载数值、低位组在前，最高位为 1 的字节是最后一个字节。
// 最多 4 字节，取值 0..0x0FFFFFFF。编码总是最短形式；解码接受非最短形式。
constexpr int kEaMaxBytes = 4;
constexpr uint32_t kEaMaxValue = 0x0FFFFFFFu;

enum class EaStatus {
  kOk,
  kNeedMore,      // 终止字节之前数据就到头了
  kUnterminated,  // 连续 kEaMaxBytes 字节都没有终止位
};

struct EaDecoded {
  EaStatus status = EaStatus::kNeedMore;
  uint32_t value = 0;
  uint8_t size = 0;
};

// 从 data[offset, limit) 开头解一个 EA，不抛异常。
EaDecoded ea_decode(const uint8_t* data, size_t size, size_t offset, size_t limit);

// value 必须 <= kEaMaxValue。
size_t ea_encoded_size(uint32_t value);
void ea_encode(uint32_t value, uint8_t* out);

}  // namespace hicar
