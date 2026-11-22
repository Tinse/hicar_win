#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace hicar {
namespace dmsdp {

// 控制连接上的 RTSP 风格文本消息：首行 + 原顺序头部 + 正文。
// 请求首行形如 `SET_PARAMETER * DMSDP/1.0`，响应形如 `DMSDP/1.0 200 OK`。
class DmsdpMessage {
 public:
  std::string start_line;
  std::vector<std::pair<std::string, std::string>> headers;
  std::vector<uint8_t> body;

  bool is_response() const;
  std::optional<std::string> method() const;
  std::optional<int> status_code() const;

  // 名称不区分大小写，取第一个。
  const std::string* header(const std::string& name) const;

  size_t body_size() const { return body.size(); }
};

// 格式不对抛 MalformedMessage；只拆结构，不校验方法/版本/重名/Content-Length。
DmsdpMessage parse_dmsdp_message(const std::vector<uint8_t>& payload);

std::vector<uint8_t> encode_dmsdp_message(
    const std::string& start_line,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::vector<uint8_t>& body = {});

bool has_duplicate_headers(const DmsdpMessage& message);
bool content_length_matches(const DmsdpMessage& message);

// 是否为 ASCII 十进制（非空、全是 0-9）。
bool is_ascii_decimal(const std::string& text);

}  // namespace dmsdp
}  // namespace hicar
