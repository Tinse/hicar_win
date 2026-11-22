#include "nearby/tlv.h"

#include "common/byte_buffer.h"
#include "common/error.h"

namespace hicar {

std::vector<Tlv> parse_tlvs(const uint8_t* data, size_t size) {
  ByteReader reader(data, size);
  std::vector<Tlv> out;
  while (reader.remaining() > 0) {
    Tlv item;
    item.tag = reader.ea();
    const uint32_t len = reader.ea();
    if (len > reader.remaining()) throw MalformedMessage("TLV 声明长度超过剩余字节");
    item.value = reader.bytes(len);
    out.push_back(std::move(item));
  }
  return out;
}

std::vector<Tlv> parse_tlvs(const std::vector<uint8_t>& data) { return parse_tlvs(data.data(), data.size()); }

std::vector<uint8_t> encode_tlv(uint32_t tag, const std::vector<uint8_t>& value) {
  ByteWriter w(value.size() + 16);
  w.ea(tag).ea(static_cast<uint32_t>(value.size())).raw(value);
  return w.take();
}

std::vector<uint8_t> encode_tlv(uint32_t tag) { return encode_tlv(tag, {}); }

}  // namespace hicar
