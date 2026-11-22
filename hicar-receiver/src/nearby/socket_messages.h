#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hicar {

// 「建 socket」请求 / 应答（资源层外层类型 4、消息层外层类型 2 通用）：
//   命令 3 请求 = EA(通道) EA(业务号) EA(标签长度) 标签 EA(协议) [EA(uuid 长度) uuid]
//   命令 4 应答 = EA(状态) EA(端口) EA(通道) EA(业务号) EA(标签长度) 标签 EA(协议) [EA(uuid 长度) uuid]
namespace socket_messages {

constexpr uint32_t kOuterMessage = 2;
constexpr uint32_t kOuterResource = 4;

constexpr uint32_t kCmdCreateRequest = 3;
constexpr uint32_t kCmdCreateResponse = 4;

constexpr uint32_t kProtocolTcp = 1;
constexpr uint32_t kStatusAccepted = 0;
constexpr uint32_t kStatusRejected = 1;

struct Request {
  uint32_t channel = 0;
  uint32_t business_id = 0;
  std::vector<uint8_t> tag;
  uint32_t protocol = 0;
  std::optional<std::vector<uint8_t>> uuid;
};

struct Response {
  uint32_t status = 0;
  uint32_t port = 0;
  uint32_t channel = 0;
  uint32_t business_id = 0;
  std::vector<uint8_t> tag;
  uint32_t protocol = 0;
  std::optional<std::vector<uint8_t>> uuid;
};

Request parse_request(const std::vector<uint8_t>& value);
std::vector<uint8_t> encode_request(const Request& request);

Response parse_response(const std::vector<uint8_t>& value);

// 已包好外层 TLV(命令 4) 的完整载荷。
std::vector<uint8_t> response_payload(const Response& response);

}  // namespace socket_messages

}  // namespace hicar
