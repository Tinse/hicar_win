#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace hicar {
namespace dmsdp {

// 业务 20（DMSDP）TCP 的外层帧：
//   0x7F | EA(module) | EA(载荷长度) | 载荷 | CRC16-ARC(小端)
// CRC 覆盖从 0x7F 到载荷最后一个字节。会话数据的 module 是 1。
constexpr uint8_t kSessionHead = 0x7F;
constexpr uint32_t kSessionModule = 1;
constexpr size_t kMaxSessionPayload = 10240;

// 首轮协商只有 16 字节：结果(1) | 控制端口(BE16) | 13 个 0。
constexpr size_t kNegotiationBytes = 16;

std::vector<uint8_t> encode_session_frame(uint32_t module, const std::vector<uint8_t>& payload);
std::vector<uint8_t> negotiation_reply(uint16_t control_port);

struct SessionFrame {
  uint32_t module = 0;
  std::vector<uint8_t> payload;
};

class SessionFrameDecoder {
 public:
  void append(const uint8_t* data, size_t size);
  bool has_partial() const { return !buffer_.empty(); }

  // 字节不够返回 nullopt；首字节、EA、长度或 CRC 不对抛 MalformedMessage。
  std::optional<SessionFrame> next();

 private:
  std::vector<uint8_t> buffer_;
};

// 控制连接的外层帧：标志(1) | 长度(BE16) | 载荷。
// 0x00 明文；0xAB 加密，载荷是 IV(16) | AES-128-CTR 密文。长度不能为 0。
constexpr uint8_t kControlPlain = 0x00;
constexpr uint8_t kControlEncrypted = 0xAB;
constexpr size_t kMaxControlPayload = 0xFFFF;

std::vector<uint8_t> encode_control_frame(uint8_t flag, const std::vector<uint8_t>& payload);

struct ControlFrame {
  bool encrypted = false;
  std::vector<uint8_t> payload;
};

class ControlFrameDecoder {
 public:
  void append(const uint8_t* data, size_t size);
  bool has_partial() const { return !buffer_.empty(); }

  std::optional<ControlFrame> next();

 private:
  std::vector<uint8_t> buffer_;
};

// 控制载荷里的设备二进制记录（解密之后）：
//   '$'(0x24) | module(BE32) | type(BE32 有符号) | 数据长度(BE16) | 数据
// 一个载荷里可以连着多条记录。type 为 -1 时线上是 ff ff ff ff。
struct DeviceRecord {
  uint32_t module = 0;
  int32_t type = 0;
  std::vector<uint8_t> data;
};

constexpr uint8_t kDeviceRecordMarker = 0x24;
constexpr size_t kDeviceRecordHeaderBytes = 11;
constexpr size_t kMaxDeviceRecordData = kMaxControlPayload - 16 - kDeviceRecordHeaderBytes;

bool is_device_record(const std::vector<uint8_t>& payload);
std::vector<uint8_t> encode_device_record(uint32_t module, int32_t type,
                                          const std::vector<uint8_t>& data);
std::vector<DeviceRecord> parse_device_records(const std::vector<uint8_t>& payload);

}  // namespace dmsdp
}  // namespace hicar
