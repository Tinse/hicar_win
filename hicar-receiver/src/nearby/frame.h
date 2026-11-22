#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace hicar {

// 控制通道上的一帧：
//   7F | EA(外层类型) | 标志段 | EA(载荷长度) | 载荷 | CRC16 低字节 | CRC16 高字节
//   标志段 = TLV(标志, 值)：明文 flag=0、无值；加密 flag=1、值 = TLV(1, 8 字节种子)
// CRC-16/ARC 覆盖从 0x7F 到载荷末尾（加密帧算在密文上）。
class NearbyFrame {
 public:
  static constexpr uint8_t kHead = 0x7F;
  static constexpr uint32_t kSeedTag = 1;
  static constexpr size_t kSeedLength = 8;
  static constexpr uint32_t kFlagEncrypted = 1;

  NearbyFrame() = default;
  NearbyFrame(uint32_t outer_type, uint32_t flag, std::vector<uint8_t> flag_value,
              std::vector<uint8_t> payload);

  static NearbyFrame plain(uint32_t outer_type, std::vector<uint8_t> payload);
  static NearbyFrame encrypted(uint32_t outer_type, std::vector<uint8_t> ciphertext,
                               const std::vector<uint8_t>& seed);

  bool is_encrypted() const { return (flag_ & 1u) == 1u; }
  uint32_t outer_type() const { return outer_type_; }
  uint32_t flag() const { return flag_; }
  const std::vector<uint8_t>& flag_value() const { return flag_value_; }
  const std::vector<uint8_t>& payload() const { return payload_; }

  // 加密帧的 8 字节种子；明文帧抛 MalformedMessage（调用方先判断 is_encrypted）。
  std::vector<uint8_t> seed() const;

  std::vector<uint8_t> encode() const;

 private:
  uint32_t outer_type_ = 0;
  uint32_t flag_ = 0;
  std::vector<uint8_t> flag_value_;
  std::vector<uint8_t> payload_;
};

// 流式拆帧器：TCP/RFCOMM 一次读到的数据可能是半帧，也可能粘着好几帧。
// 数据非法时清空缓冲并抛 MalformedMessage，连接不断，后续数据重新开始拆。
class NearbyFrameDecoder {
 public:
  static constexpr size_t kDefaultMaxPayload = 64 * 1024;
  static constexpr uint32_t kMaxFlagValue = 256;

  explicit NearbyFrameDecoder(size_t max_payload = kDefaultMaxPayload);

  void feed(const uint8_t* data, size_t size);
  void feed(const std::vector<uint8_t>& data);

  // 数据还不够一帧时返回 std::nullopt。
  std::optional<NearbyFrame> next();

  void clear() { buffer_.clear(); }
  size_t buffered() const { return buffer_.size(); }

 private:
  std::optional<NearbyFrame> parse();

  std::vector<uint8_t> buffer_;
  size_t max_payload_;
};

}  // namespace hicar
