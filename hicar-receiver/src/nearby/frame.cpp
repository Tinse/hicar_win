#include "nearby/frame.h"

#include <cstring>

#include "common/byte_buffer.h"
#include "common/crc16_arc.h"
#include "common/error.h"
#include "nearby/tlv.h"

namespace hicar {

NearbyFrame::NearbyFrame(uint32_t outer_type, uint32_t flag, std::vector<uint8_t> flag_value,
                         std::vector<uint8_t> payload)
    : outer_type_(outer_type), flag_(flag), flag_value_(std::move(flag_value)), payload_(std::move(payload)) {}

NearbyFrame NearbyFrame::plain(uint32_t outer_type, std::vector<uint8_t> payload) {
  return NearbyFrame(outer_type, 0, {}, std::move(payload));
}

NearbyFrame NearbyFrame::encrypted(uint32_t outer_type, std::vector<uint8_t> ciphertext,
                                   const std::vector<uint8_t>& seed) {
  if (seed.size() != kSeedLength) throw std::invalid_argument("附近帧种子应为 8 字节");
  return NearbyFrame(outer_type, kFlagEncrypted, encode_tlv(kSeedTag, seed), std::move(ciphertext));
}

std::vector<uint8_t> NearbyFrame::seed() const {
  if (!is_encrypted()) throw MalformedMessage("明文帧没有种子");
  for (const Tlv& item : parse_tlvs(flag_value_)) {
    if (item.tag == kSeedTag) {
      if (item.value.size() != kSeedLength) throw MalformedMessage("种子应为 8 字节");
      return item.value;
    }
  }
  throw MalformedMessage("加密帧的标志段里没有种子");
}

std::vector<uint8_t> NearbyFrame::encode() const {
  ByteWriter w(payload_.size() + flag_value_.size() + 32);
  w.u8(kHead).ea(outer_type_);
  w.raw(encode_tlv(flag_, flag_value_));
  w.ea(static_cast<uint32_t>(payload_.size())).raw(payload_);
  const std::vector<uint8_t> body = w.take();
  const uint16_t crc = crc16_arc(body.data(), body.size());
  std::vector<uint8_t> out = body;
  out.push_back(static_cast<uint8_t>(crc));
  out.push_back(static_cast<uint8_t>(crc >> 8));
  return out;
}

NearbyFrameDecoder::NearbyFrameDecoder(size_t max_payload) : max_payload_(max_payload) {}

void NearbyFrameDecoder::feed(const uint8_t* data, size_t size) {
  if (size == 0) return;
  buffer_.insert(buffer_.end(), data, data + size);
}

void NearbyFrameDecoder::feed(const std::vector<uint8_t>& data) { feed(data.data(), data.size()); }

std::optional<NearbyFrame> NearbyFrameDecoder::next() {
  if (buffer_.empty()) return std::nullopt;
  try {
    return parse();
  } catch (const MalformedMessage&) {
    buffer_.clear();
    throw;
  }
}

std::optional<NearbyFrame> NearbyFrameDecoder::parse() {
  const uint8_t* buf = buffer_.data();
  const size_t end = buffer_.size();
  if (buf[0] != NearbyFrame::kHead) throw MalformedMessage("首字节不是 0x7F");

  size_t off = 1;
  const EaDecoded outer = ea_decode(buf, end, off, end);
  if (outer.status == EaStatus::kNeedMore) return std::nullopt;
  if (outer.status == EaStatus::kUnterminated) throw MalformedMessage("EA 外层类型没有终止位");
  off += outer.size;

  const EaDecoded flag = ea_decode(buf, end, off, end);
  if (flag.status == EaStatus::kNeedMore) return std::nullopt;
  if (flag.status == EaStatus::kUnterminated) throw MalformedMessage("EA 标志没有终止位");
  off += flag.size;

  const EaDecoded flag_len = ea_decode(buf, end, off, end);
  if (flag_len.status == EaStatus::kNeedMore) return std::nullopt;
  if (flag_len.status == EaStatus::kUnterminated) throw MalformedMessage("EA 标志长度没有终止位");
  off += flag_len.size;
  if (flag_len.value > kMaxFlagValue) throw MalformedMessage("标志段值超过上限");
  if (end - off < flag_len.value) return std::nullopt;

  std::vector<uint8_t> flag_value(buf + off, buf + off + flag_len.value);
  off += flag_len.value;

  const EaDecoded payload_len = ea_decode(buf, end, off, end);
  if (payload_len.status == EaStatus::kNeedMore) return std::nullopt;
  if (payload_len.status == EaStatus::kUnterminated) throw MalformedMessage("EA 载荷长度没有终止位");
  off += payload_len.size;
  if (payload_len.value > max_payload_) throw MalformedMessage("载荷超过上限");
  if (end - off < payload_len.value + 2) return std::nullopt;

  const size_t payload_end = off + payload_len.value;
  const uint16_t got = static_cast<uint16_t>(buf[payload_end] | (buf[payload_end + 1] << 8));
  const uint16_t want = crc16_arc(buf, payload_end);
  if (got != want) throw MalformedMessage("CRC 不符");

  NearbyFrame frame(outer.value, flag.value, std::move(flag_value),
                    std::vector<uint8_t>(buf + off, buf + payload_end));
  if (frame.is_encrypted()) frame.seed();  // 加密帧拿不到合格种子同样按非法处理

  buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(payload_end + 2));
  return frame;
}

}  // namespace hicar
