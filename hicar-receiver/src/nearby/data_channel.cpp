#include "nearby/data_channel.h"

#include "common/byte_buffer.h"
#include "common/error.h"
#include "nearby/tlv.h"

namespace hicar {

namespace {

constexpr uint32_t kTagGroupOwner = 1;
constexpr uint32_t kTagGroupClient = 2;
constexpr uint32_t kTag2g = 3;
constexpr uint32_t kTag5g = 4;
constexpr uint32_t kTagChannelBitmap = 5;
constexpr uint32_t kTagDualBand = 6;
constexpr uint32_t kTagConnectedFrequency = 7;
constexpr int kMaxBitmapBytes = 9;

uint64_t read_bitmap(ByteReader& reader) {
  uint64_t value = 0;
  for (int i = 0; i < kMaxBitmapBytes; ++i) {
    const uint8_t b = reader.u8();
    value |= static_cast<uint64_t>(b & 0x7F) << (7 * i);
    if ((b & 0x80) != 0) return value;
  }
  throw MalformedMessage("信道位图连续 9 字节都没有终止位");
}

bool is_2g(uint32_t frequency) { return frequency >= 2400 && frequency <= 2484; }

bool is_5g(uint32_t frequency) { return frequency >= 4900 && frequency <= 5900; }

// 5 GHz 信道表：频率 5000 + 5 * 信道。
std::optional<uint32_t> channel_of(uint32_t frequency) {
  if (frequency == 2484) return 14;
  if (is_2g(frequency)) return (frequency - 2407) / 5;
  if (is_5g(frequency)) return (frequency - 5000) / 5;
  return std::nullopt;
}

}  // namespace

bool WifiCapability::can_use(uint32_t frequency_mhz) const {
  if (is_2g(frequency_mhz)) return supports_2g.value_or(true);
  if (!is_5g(frequency_mhz)) return false;
  if (supports_5g != std::optional<bool>(true)) return false;
  if (!channel_bitmap.has_value()) return true;
  const auto channel = channel_of(frequency_mhz);
  if (!channel.has_value()) return false;
  return (*channel_bitmap & (1ull << *channel)) != 0;
}

namespace data_channel {

WifiCapability parse_capability(const std::vector<uint8_t>& value) {
  ByteReader reader(value);
  WifiCapability out;
  std::map<uint32_t, uint32_t> fields;
  std::optional<uint64_t> bitmap;

  while (reader.remaining() > 0) {
    const uint32_t tag = reader.ea();
    if (tag == kTagChannelBitmap) {
      bitmap = read_bitmap(reader);
    } else {
      fields[tag] = reader.ea();
    }
  }

  auto take_flag = [&](uint32_t tag) -> std::optional<bool> {
    auto it = fields.find(tag);
    if (it == fields.end()) return std::nullopt;
    const bool value = it->second != 0;
    fields.erase(it);
    return value;
  };

  out.can_be_group_owner = take_flag(kTagGroupOwner);
  out.can_be_group_client = take_flag(kTagGroupClient);
  out.supports_2g = take_flag(kTag2g);
  out.supports_5g = take_flag(kTag5g);
  out.channel_bitmap = bitmap;
  out.dual_band = take_flag(kTagDualBand);
  auto freq = fields.find(kTagConnectedFrequency);
  if (freq != fields.end()) {
    out.connected_frequency_mhz = freq->second;
    fields.erase(freq);
  }
  out.other_fields = std::move(fields);
  return out;
}

Request parse_request(const std::vector<uint8_t>& value) {
  ByteReader reader(value);
  Request out;
  out.data_channel = reader.ea();
  const std::vector<Tlv> tlvs = parse_tlvs(reader.rest());
  const Tlv* detail = nullptr;
  for (const Tlv& tlv : tlvs) {
    if (tlv.tag == kTagDetail) {
      detail = &tlv;
      break;
    }
  }
  if (detail == nullptr) throw MalformedMessage("数据通道协商请求里没有能力串（TLV 3）");
  out.capability = parse_capability(detail->value);
  return out;
}

Result parse_result(const std::vector<uint8_t>& value) {
  ByteReader reader(value);
  Result out;
  out.data_channel = reader.ea();
  out.result = reader.ea();
  const std::vector<Tlv> tlvs = parse_tlvs(reader.rest());
  for (const Tlv& tlv : tlvs) {
    if (tlv.tag != kTagDetail) continue;
    ByteReader detail(tlv.value);
    out.role = detail.u8();
    out.frequency_mhz = detail.ea();
    if (detail.remaining() > 0) throw MalformedMessage("协商结果的 TLV 3 末尾有多余字节");
    break;
  }
  return out;
}

std::vector<uint8_t> accept_payload(uint32_t data_channel, uint32_t role, uint32_t frequency_mhz) {
  if (role > 0xFF) throw std::invalid_argument("角色是 1 字节");
  ByteWriter detail;
  detail.u8(role).ea(frequency_mhz);
  ByteWriter value;
  value.ea(data_channel).ea(kResultOk).raw(encode_tlv(kTagDetail, detail.take()));
  return encode_tlv(kCommandResponse, value.take());
}

std::vector<uint8_t> refuse_payload(uint32_t data_channel, DataChannelRefusal refusal) {
  ByteWriter value;
  value.ea(data_channel).ea(static_cast<uint32_t>(refusal));
  return encode_tlv(kCommandResponse, value.take());
}

}  // namespace data_channel
}  // namespace hicar
