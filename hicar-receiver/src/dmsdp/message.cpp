#include "dmsdp/message.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "common/error.h"

namespace hicar {
namespace dmsdp {
namespace {

std::string trim_control(const std::string& text) {
  size_t begin = 0;
  size_t end = text.size();
  while (begin < end && static_cast<unsigned char>(text[begin]) <= static_cast<unsigned char>(' ')) ++begin;
  while (end > begin && static_cast<unsigned char>(text[end - 1]) <= static_cast<unsigned char>(' ')) --end;
  return text.substr(begin, end - begin);
}

}  // namespace

bool is_ascii_decimal(const std::string& text) {
  if (text.empty()) return false;
  for (const char c : text) {
    if (c < '0' || c > '9') return false;
  }
  return true;
}

bool DmsdpMessage::is_response() const {
  const size_t space = start_line.find(' ');
  return start_line.substr(0, space) == "DMSDP/1.0";
}

std::optional<std::string> DmsdpMessage::method() const {
  if (is_response()) return std::nullopt;
  const size_t space = start_line.find(' ');
  return start_line.substr(0, space);
}

std::optional<int> DmsdpMessage::status_code() const {
  if (!is_response()) return std::nullopt;
  const size_t first = start_line.find(' ');
  if (first == std::string::npos) return std::nullopt;
  const size_t second = start_line.find(' ', first + 1);
  const std::string code = start_line.substr(first + 1, second == std::string::npos ? std::string::npos
                                                                                    : second - first - 1);
  if (code.size() != 3 || !is_ascii_decimal(code)) return std::nullopt;
  return std::stoi(code);
}

const std::string* DmsdpMessage::header(const std::string& name) const {
  for (const auto& header : headers) {
    if (header.first.size() == name.size()) {
      bool equal = true;
      for (size_t i = 0; i < name.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(header.first[i])) !=
            std::tolower(static_cast<unsigned char>(name[i]))) {
          equal = false;
          break;
        }
      }
      if (equal) return &header.second;
    }
  }
  return nullptr;
}

DmsdpMessage parse_dmsdp_message(const std::vector<uint8_t>& payload) {
  // 头部区到第一个 CRLFCRLF 为止。
  size_t header_end = std::string::npos;
  for (size_t i = 0; i + 4 <= payload.size(); ++i) {
    if (payload[i] == '\r' && payload[i + 1] == '\n' && payload[i + 2] == '\r' && payload[i + 3] == '\n') {
      header_end = i;
      break;
    }
  }
  if (header_end == std::string::npos) throw MalformedMessage("控制消息缺少头部结束的空行");
  for (size_t i = 0; i < header_end; ++i) {
    if (payload[i] >= 0x80) throw MalformedMessage("控制消息头部含非 ASCII 字节");
  }

  std::string head(reinterpret_cast<const char*>(payload.data()), header_end);
  std::vector<std::string> lines;
  size_t pos = 0;
  while (pos <= head.size()) {
    const size_t next = head.find("\r\n", pos);
    if (next == std::string::npos) {
      lines.push_back(head.substr(pos));
      break;
    }
    lines.push_back(head.substr(pos, next - pos));
    pos = next + 2;
  }
  if (lines.empty()) throw MalformedMessage("控制消息缺少首行");

  DmsdpMessage message;
  message.start_line = lines[0];
  for (size_t i = 1; i < lines.size(); ++i) {
    const size_t colon = lines[i].find(':');
    if (colon == std::string::npos) throw MalformedMessage("控制消息头部缺少冒号");
    message.headers.emplace_back(trim_control(lines[i].substr(0, colon)),
                                 trim_control(lines[i].substr(colon + 1)));
  }
  message.body.assign(payload.begin() + static_cast<std::ptrdiff_t>(header_end + 4), payload.end());
  return message;
}

std::vector<uint8_t> encode_dmsdp_message(
    const std::string& start_line,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::vector<uint8_t>& body) {
  std::string head = start_line;
  head.append("\r\n");
  for (const auto& header : headers) {
    head.append(header.first).append(": ").append(header.second).append("\r\n");
  }
  head.append("\r\n");
  std::vector<uint8_t> out(head.begin(), head.end());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

bool has_duplicate_headers(const DmsdpMessage& message) {
  std::vector<std::string> seen;
  for (const auto& header : message.headers) {
    std::string lower = header.first;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (std::find(seen.begin(), seen.end(), lower) != seen.end()) return true;
    seen.push_back(std::move(lower));
  }
  return false;
}

bool content_length_matches(const DmsdpMessage& message) {
  const std::string* declared = message.header("Content-Length");
  if (declared == nullptr) return message.body.empty();
  if (!is_ascii_decimal(*declared) || declared->size() > 9) return false;
  return static_cast<size_t>(std::stoul(*declared)) == message.body.size();
}

}  // namespace dmsdp
}  // namespace hicar
