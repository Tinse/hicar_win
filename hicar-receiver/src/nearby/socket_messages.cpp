#include "nearby/socket_messages.h"

#include "common/byte_buffer.h"
#include "common/error.h"
#include "nearby/tlv.h"

namespace hicar {
namespace socket_messages {

namespace {

uint32_t read_length(ByteReader& reader, const char* what) {
  const uint32_t len = reader.ea();
  if (len > reader.remaining()) throw MalformedMessage(std::string(what) + " 长度越界");
  return len;
}

void check_tail(ByteReader& reader, const char* what) {
  if (reader.remaining() > 0) throw MalformedMessage(std::string(what) + " 末尾有多余字节");
}

}  // namespace

Request parse_request(const std::vector<uint8_t>& value) {
  ByteReader reader(value);
  Request out;
  out.channel = reader.ea();
  out.business_id = reader.ea();
  const uint32_t tag_len = read_length(reader, "标签");
  out.tag = reader.bytes(tag_len);
  out.protocol = reader.ea();
  if (reader.remaining() > 0) {
    const uint32_t uuid_len = read_length(reader, "uuid");
    out.uuid = reader.bytes(uuid_len);
  }
  check_tail(reader, "建 socket 请求");
  return out;
}

std::vector<uint8_t> encode_request(const Request& request) {
  ByteWriter writer;
  writer.ea(request.channel).ea(request.business_id).ea(static_cast<uint32_t>(request.tag.size())).raw(request.tag)
      .ea(request.protocol);
  if (request.uuid.has_value()) writer.ea(static_cast<uint32_t>(request.uuid->size())).raw(*request.uuid);
  return writer.take();
}

Response parse_response(const std::vector<uint8_t>& value) {
  ByteReader reader(value);
  Response out;
  out.status = reader.ea();
  out.port = reader.ea();
  out.channel = reader.ea();
  out.business_id = reader.ea();
  const uint32_t tag_len = read_length(reader, "标签");
  out.tag = reader.bytes(tag_len);
  out.protocol = reader.ea();
  if (reader.remaining() > 0) {
    const uint32_t uuid_len = read_length(reader, "uuid");
    out.uuid = reader.bytes(uuid_len);
  }
  check_tail(reader, "建 socket 应答");
  return out;
}

std::vector<uint8_t> response_payload(const Response& response) {
  if (response.port > 65535) throw std::invalid_argument("端口越界");
  ByteWriter writer;
  writer.ea(response.status).ea(response.port).ea(response.channel).ea(response.business_id)
      .ea(static_cast<uint32_t>(response.tag.size())).raw(response.tag).ea(response.protocol);
  if (response.uuid.has_value()) writer.ea(static_cast<uint32_t>(response.uuid->size())).raw(*response.uuid);
  return encode_tlv(kCmdCreateResponse, writer.take());
}

}  // namespace socket_messages
}  // namespace hicar
