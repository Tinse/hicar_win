#include "dmsdp/framing.h"

#include <stdexcept>
#include <string>

#include "common/byte_buffer.h"
#include "common/crc16_arc.h"
#include "common/ea.h"
#include "common/error.h"

namespace hicar {
namespace dmsdp {
namespace {

[[noreturn]] void fail(const std::string& text) { throw MalformedMessage(text); }

}  // namespace

std::vector<uint8_t> encode_session_frame(uint32_t module, const std::vector<uint8_t>& payload) {
  if (payload.size() > kMaxSessionPayload) {
    throw std::invalid_argument("会话帧载荷超过上限");
  }
  ByteWriter out(1 + 8 + payload.size() + 2);
  out.u8(kSessionHead).ea(module).ea(static_cast<uint32_t>(payload.size())).raw(payload);
  const uint16_t crc = crc16_arc(out.data().data(), out.size());
  out.u16le(crc);
  return out.take();
}

std::vector<uint8_t> negotiation_reply(uint16_t control_port) {
  if (control_port == 0) throw std::invalid_argument("控制端口不能为 0");
  std::vector<uint8_t> payload(kNegotiationBytes, 0);
  payload[1] = static_cast<uint8_t>(control_port >> 8);
  payload[2] = static_cast<uint8_t>(control_port & 0xFF);
  return encode_session_frame(kSessionModule, payload);
}

void SessionFrameDecoder::append(const uint8_t* data, size_t size) {
  if (size > 0) buffer_.insert(buffer_.end(), data, data + size);
}

std::optional<SessionFrame> SessionFrameDecoder::next() {
  if (buffer_.empty()) return std::nullopt;
  if (buffer_[0] != kSessionHead) fail("会话帧首字节不是 0x7F");

  const EaDecoded module = ea_decode(buffer_.data(), buffer_.size(), 1, buffer_.size());
  if (module.status == EaStatus::kNeedMore) return std::nullopt;
  if (module.status != EaStatus::kOk) fail("会话帧 module 的 EA 不完整");

  const size_t length_at = 1 + static_cast<size_t>(module.size);
  const EaDecoded length = ea_decode(buffer_.data(), buffer_.size(), length_at, buffer_.size());
  if (length.status == EaStatus::kNeedMore) return std::nullopt;
  if (length.status != EaStatus::kOk) fail("会话帧长度的 EA 不完整");
  if (length.value > kMaxSessionPayload) fail("会话帧载荷超过上限");

  const size_t payload_at = length_at + static_cast<size_t>(length.size);
  const size_t payload_end = payload_at + static_cast<size_t>(length.value);
  if (buffer_.size() < payload_end + 2) return std::nullopt;

  const uint16_t expected = static_cast<uint16_t>(buffer_[payload_end]) |
                            (static_cast<uint16_t>(buffer_[payload_end + 1]) << 8);
  if (crc16_arc(buffer_.data(), payload_end) != expected) fail("会话帧 CRC16 校验失败");

  SessionFrame frame;
  frame.module = module.value;
  frame.payload.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(payload_at),
                       buffer_.begin() + static_cast<std::ptrdiff_t>(payload_end));
  buffer_.erase(buffer_.begin(),
                buffer_.begin() + static_cast<std::ptrdiff_t>(payload_end + 2));
  return frame;
}

std::vector<uint8_t> encode_control_frame(uint8_t flag, const std::vector<uint8_t>& payload) {
  if (flag != kControlPlain && flag != kControlEncrypted) {
    throw std::invalid_argument("控制帧标志不认识");
  }
  if (payload.empty() || payload.size() > kMaxControlPayload) {
    throw std::invalid_argument("控制帧载荷长度非法");
  }
  ByteWriter out(3 + payload.size());
  out.u8(flag).u16be(static_cast<uint32_t>(payload.size())).raw(payload);
  return out.take();
}

void ControlFrameDecoder::append(const uint8_t* data, size_t size) {
  if (size > 0) buffer_.insert(buffer_.end(), data, data + size);
}

std::optional<ControlFrame> ControlFrameDecoder::next() {
  if (buffer_.size() < 3) return std::nullopt;
  const uint8_t flag = buffer_[0];
  const uint16_t length = static_cast<uint16_t>(buffer_[1] << 8) |
                          static_cast<uint16_t>(buffer_[2]);
  if (flag != kControlPlain && flag != kControlEncrypted) fail("控制帧标志不认识");
  if (length == 0) fail("控制帧长度为 0");
  if (buffer_.size() < 3 + static_cast<size_t>(length)) return std::nullopt;

  ControlFrame frame;
  frame.encrypted = flag == kControlEncrypted;
  frame.payload.assign(buffer_.begin() + 3,
                       buffer_.begin() + static_cast<std::ptrdiff_t>(3 + length));
  buffer_.erase(buffer_.begin(),
                buffer_.begin() + static_cast<std::ptrdiff_t>(3 + length));
  return frame;
}

bool is_device_record(const std::vector<uint8_t>& payload) {
  return !payload.empty() && payload[0] == kDeviceRecordMarker;
}

std::vector<uint8_t> encode_device_record(uint32_t module, int32_t type,
                                          const std::vector<uint8_t>& data) {
  if (data.empty() || data.size() > kMaxDeviceRecordData) {
    throw std::invalid_argument("设备记录数据长度非法");
  }
  ByteWriter out(kDeviceRecordHeaderBytes + data.size());
  out.u8(kDeviceRecordMarker)
      .u32be(module)
      .u32be(static_cast<uint32_t>(type))
      .u16be(static_cast<uint32_t>(data.size()))
      .raw(data);
  return out.take();
}

std::vector<DeviceRecord> parse_device_records(const std::vector<uint8_t>& payload) {
  std::vector<DeviceRecord> records;
  ByteReader reader(payload);
  while (reader.remaining() > 0) {
    if (reader.remaining() < kDeviceRecordHeaderBytes) {
      fail("设备记录头不完整");
    }
    if (reader.u8() != kDeviceRecordMarker) {
      fail("设备记录标记不是 '$'");
    }
    DeviceRecord record;
    record.module = reader.u32be();
    record.type = static_cast<int32_t>(reader.u32be());
    const uint16_t length = reader.u16be();
    record.data = reader.bytes(length);
    records.push_back(std::move(record));
  }
  return records;
}

}  // namespace dmsdp
}  // namespace hicar
