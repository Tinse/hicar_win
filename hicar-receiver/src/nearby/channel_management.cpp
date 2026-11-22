#include "nearby/channel_management.h"

#include "common/error.h"
#include "nearby/tlv.h"

namespace hicar {
namespace channel_management {

namespace {

void check_utf8(const std::string&) {}  // 保留：文本按 UTF-8 原样透传，非法序列交给上层判断

uint32_t little_endian_version(uint32_t tag, const std::vector<uint8_t>& value) {
  if (value.empty() || value.size() > 4) {
    throw MalformedMessage("版本 tag " + std::to_string(tag) + " 应为 1～4 字节");
  }
  uint32_t out = 0;
  for (size_t i = value.size(); i-- > 0;) out = (out << 8) | value[i];
  return out;
}

}  // namespace

std::string text_of(const std::vector<uint8_t>& raw) {
  size_t end = raw.size();
  while (end > 0 && raw[end - 1] == 0) --end;
  std::string text(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(end));
  check_utf8(text);
  return text;
}

std::vector<Item> decode(const std::vector<uint8_t>& payload) {
  const std::vector<Tlv> tlvs = parse_tlvs(payload);
  std::vector<Item> out;
  out.reserve(tlvs.size());
  for (const Tlv& t : tlvs) {
    switch (t.tag) {
      case kTagVersionRequest:
      case kTagVersionResponse: {
        Version item;
        item.request = t.tag == kTagVersionRequest;
        item.version = little_endian_version(t.tag, t.value);
        out.emplace_back(std::move(item));
        break;
      }
      case kTagSummaryRequest:
      case kTagSummaryResponse: {
        Summary item;
        item.request = t.tag == kTagSummaryRequest;
        item.text = text_of(t.value);
        item.raw = t.value;
        out.emplace_back(std::move(item));
        break;
      }
      case kTagEncryptionRequest:
      case kTagEncryptionResponse: {
        if (t.value.empty()) throw MalformedMessage("加密开关没有值");
        Encryption item;
        item.request = t.tag == kTagEncryptionRequest;
        item.enabled = t.value[0] != 0;
        out.emplace_back(item);
        break;
      }
      case kTagBluetoothRequest:
      case kTagBluetoothResponse: {
        BluetoothAddress item;
        item.request = t.tag == kTagBluetoothRequest;
        item.text = text_of(t.value);
        item.raw = t.value;
        out.emplace_back(std::move(item));
        break;
      }
      case kTagConnectId: {
        ConnectId item;
        item.raw = t.value;
        out.emplace_back(std::move(item));
        break;
      }
      default:
        out.emplace_back(Unknown{t.tag, t.value});
        break;
    }
  }
  return out;
}

std::vector<uint8_t> connect_id_value(uint32_t connect_id) {
  if (connect_id < kConnectIdMin || connect_id > kConnectIdMax) {
    throw std::invalid_argument("connectId 应为 6 位十进制数");
  }
  const std::string text = std::to_string(connect_id);
  return std::vector<uint8_t>(text.begin(), text.end());
}

}  // namespace channel_management
}  // namespace hicar
