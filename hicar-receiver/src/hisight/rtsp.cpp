#include "hisight/rtsp.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>
#include <sstream>
#include <stdexcept>

namespace hicar {
namespace hisight {
namespace {

constexpr uint32_t kMaxControlPayload = 65000;
constexpr const char* kOkStatus = "RTSP/1.0 200 OK";

void fail(const std::string& message) { throw std::runtime_error(message); }

std::vector<uint8_t> ascii_bytes(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::string ascii_text(const std::vector<uint8_t>& data, size_t begin, size_t end) {
  return std::string(reinterpret_cast<const char*>(data.data()) + begin, end - begin);
}

bool is_header_name(const std::string& name) {
  if (name.empty()) return false;
  for (char c : name) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
  }
  return true;
}

}  // namespace

std::optional<std::string> RtspMessage::header(const std::string& name) const {
  std::string key;
  key.reserve(name.size());
  for (char c : name) key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  const auto it = headers.find(key);
  if (it == headers.end()) return std::nullopt;
  return it->second;
}

bool RtspMessage::is_text_parameters() const {
  const auto it = headers.find("content-type");
  if (it == headers.end()) return false;
  std::string value;
  for (char c : it->second) value.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  return value == kTextParameters;
}

void ControlFrameDecoder::append(const uint8_t* data, size_t size) {
  if (data == nullptr || size == 0) return;
  buffer_.insert(buffer_.end(), data, data + size);
}

bool ControlFrameDecoder::next(std::vector<uint8_t>* payload) {
  if (payload == nullptr || buffer_.size() < 4) return false;
  const uint32_t length = (static_cast<uint32_t>(buffer_[0]) << 24) |
                          (static_cast<uint32_t>(buffer_[1]) << 16) |
                          (static_cast<uint32_t>(buffer_[2]) << 8) |
                          static_cast<uint32_t>(buffer_[3]);
  if (length < 1 || length > kMaxControlPayload) fail("控制帧长度不在 1..65000");
  if (buffer_.size() < 4 + length) return false;
  payload->assign(buffer_.begin() + 4, buffer_.begin() + 4 + static_cast<std::ptrdiff_t>(length));
  buffer_.erase(buffer_.begin(), buffer_.begin() + 4 + static_cast<std::ptrdiff_t>(length));
  return true;
}

std::vector<uint8_t> encode_control_frame(const std::vector<uint8_t>& payload) {
  if (payload.empty() || payload.size() > kMaxControlPayload) fail("控制帧载荷必须是 1..65000 字节");
  std::vector<uint8_t> out(4 + payload.size());
  const uint32_t size = static_cast<uint32_t>(payload.size());
  out[0] = static_cast<uint8_t>(size >> 24);
  out[1] = static_cast<uint8_t>(size >> 16);
  out[2] = static_cast<uint8_t>(size >> 8);
  out[3] = static_cast<uint8_t>(size);
  std::copy(payload.begin(), payload.end(), out.begin() + 4);
  return out;
}

RtspMessage parse_rtsp(const std::vector<uint8_t>& payload) {
  struct Line {
    size_t begin = 0;
    size_t end = 0;
  };
  std::vector<Line> lines;
  size_t start = 0;
  size_t pos = 0;
  while (pos + 1 < payload.size()) {
    if (payload[pos] == 0x0D && payload[pos + 1] == 0x0A) {
      lines.push_back({start, pos});
      pos += 2;
      start = pos;
    } else {
      ++pos;
    }
  }
  const size_t tail = start;
  (void)tail;
  if (lines.empty()) fail("控制消息缺少首行结束符");

  RtspMessage message;
  message.first_line = ascii_text(payload, lines[0].begin, lines[0].end);
  if (message.first_line.find_first_of(std::string(1, static_cast<char>(0x80))) != std::string::npos) {
    // 首行必须可打印 ASCII
  }
  for (size_t i = lines[0].begin; i < lines[0].end; ++i) {
    if (payload[i] < 0x20 || payload[i] > 0x7E) fail("控制消息首行含非 ASCII 字节");
  }

  size_t index = 1;
  if (message.first_line == kOkStatus && index < lines.size()) {
    const std::string again = ascii_text(payload, lines[index].begin, lines[index].end);
    if (again == kOkStatus) ++index;
  }

  std::map<std::string, std::string> headers;
  size_t body_start = payload.size();
  bool saw_blank = false;
  for (; index < lines.size(); ++index) {
    const Line& line = lines[index];
    if (line.begin == line.end) {
      saw_blank = true;
      body_start = line.end + 2;
      ++index;
      break;
    }
    const std::string text = ascii_text(payload, line.begin, line.end);
    const size_t colon = text.find(':');
    if (colon == std::string::npos) fail("控制消息头缺冒号");
    std::string name = text.substr(0, colon);
    for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!is_header_name(name)) fail("控制消息头名不合法");
    if (headers.count(name) != 0) fail("控制消息头重复");
    headers[name] = trim_space_tab(text.substr(colon + 1));
  }

  if (!saw_blank) {
    // 有些保活/应答没有结尾空行：把剩余行也当头解析（上面已处理），正文为空。
    body_start = payload.size();
  }

  message.headers = headers;
  const auto cseq = headers.find("cseq");
  if (cseq == headers.end()) fail("控制消息缺少 CSeq");
  const long long value = parse_decimal(cseq->second, 10);
  if (value < 1 || value > 2147483647LL) fail("控制消息 CSeq 无效");
  message.cseq = static_cast<int>(value);

  auto cl = headers.find("content-length");
  if (cl != headers.end()) {
    const long long declared = parse_decimal(cl->second, 5);
    if (declared < 0) fail("控制消息 Content-Length 非十进制");
    const size_t available = payload.size() - body_start;
    if (available < static_cast<size_t>(declared)) {
      // SETUP 应答的非标准写法：Transport 行本身被 Content-Length 覆盖，已作为头解析过了。
      if (headers.count("transport") != 0 && available == 0) {
        message.body.clear();
      } else {
        fail("控制消息正文短于 Content-Length");
      }
    } else if (available == static_cast<size_t>(declared)) {
      message.body.assign(payload.begin() + static_cast<std::ptrdiff_t>(body_start), payload.end());
    } else if (available == static_cast<size_t>(declared) + 2 &&
               payload[payload.size() - 2] == 0x0D && payload[payload.size() - 1] == 0x0A) {
      message.body.assign(payload.begin() + static_cast<std::ptrdiff_t>(body_start),
                          payload.begin() + static_cast<std::ptrdiff_t>(body_start + declared));
    } else {
      fail("控制消息正文长度与 Content-Length 不一致");
    }
  }
  return message;
}

std::string request_method(const std::string& first_line) {
  const size_t first = first_line.find(' ');
  const size_t last = first_line.rfind(' ');
  if (first == std::string::npos || last == std::string::npos || last <= first) fail("请求首行格式无效");
  const std::string method = first_line.substr(0, first);
  const std::string target = first_line.substr(first + 1, last - first - 1);
  if (first_line.substr(last + 1) != "RTSP/1.0") fail("请求首行版本不是 RTSP/1.0");
  for (char c : method) {
    if (!((c >= 'A' && c <= 'Z') || c == '_')) fail("请求方法含非法字符");
  }
  if (target != "*" && target.rfind("rtsp://", 0) != 0) fail("请求目标不是 * 或 rtsp URI");
  return method;
}

long long parse_decimal(const std::string& text, size_t max_digits) {
  if (text.empty() || text.size() > max_digits) return -1;
  long long value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') return -1;
    value = value * 10 + (c - '0');
  }
  return value;
}

std::string rtsp_date(uint64_t wall_clock_millis) {
  const std::time_t seconds = static_cast<std::time_t>(wall_clock_millis / 1000);
  std::tm local{};
  localtime_s(&local, &seconds);
  static const char* weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  char text[64];
  std::snprintf(text, sizeof(text), "%04d-%02d-%02d %02d:%02d:%02d %s %s", local.tm_year + 1900,
                local.tm_mon + 1, local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec,
                local.tm_hour < 12 ? "AM" : "PM", weekdays[local.tm_wday]);
  return text;
}

std::vector<uint8_t> rtsp_announce() {
  const std::string body = "encrypt_description: encrypt_list=aes128ctr;version=1\r\n";
  const std::string text = "ANNOUNCE * RTSP/1.0\r\nCSeq: 1\r\nContent-Type: text/parameters\r\nContent-Length: " +
                           std::to_string(body.size()) + "\r\n\r\n" + body;
  return ascii_bytes(text);
}

std::vector<uint8_t> rtsp_ok(int cseq, const std::string& date, bool with_public) {
  std::string text = "RTSP/1.0 200 OK\r\nDate: " + date + "\r\nCseq: " + std::to_string(cseq) + "\r\n";
  if (with_public) text += "Public: hisight1.1, GET_PARAMETER, SET_PARAMETER\r\n";
  text += "\r\n";
  return ascii_bytes(text);
}

std::vector<uint8_t> rtsp_get_parameter_ok(int cseq, const std::string& body) {
  std::string text = "RTSP/1.0 200 OK\r\nCseq: " + std::to_string(cseq) + "\r\n";
  if (!body.empty()) {
    text += "Content-Type: text/parameters\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
  }
  text += "\r\n" + body;
  return ascii_bytes(text);
}

std::vector<uint8_t> rtsp_options(int cseq, const std::string& date) {
  return ascii_bytes("OPTIONS * RTSP/1.0\r\nDate: " + date + "\r\nCseq: " + std::to_string(cseq) +
                     "\r\nRequire: hisight1.1\r\n\r\n");
}

std::vector<uint8_t> rtsp_setup(int cseq) {
  return ascii_bytes("SETUP * RTSP/1.0\r\nCSeq: " + std::to_string(cseq) +
                     "\r\nTransport: RTP/AVP/UDP;unicast;client_port=0\r\n\r\n");
}

std::vector<uint8_t> rtsp_play(int cseq) {
  return ascii_bytes("PLAY * RTSP/1.0\r\nCSeq: " + std::to_string(cseq) +
                     "\r\nTransport: RTP/AVP/UDP;unicast;client_port=-1\r\n\r\n");
}

std::vector<uint8_t> rtsp_teardown(int cseq) {
  return ascii_bytes("TEARDOWN  RTSP/1.0\r\nCSeq: " + std::to_string(cseq) + "\r\n\r\n");
}

std::string trim_space_tab(const std::string& text) {
  size_t begin = 0;
  size_t end = text.size();
  while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) ++begin;
  while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) --end;
  return text.substr(begin, end - begin);
}

std::vector<std::string> parameter_lines(const std::vector<uint8_t>& body) {
  if (body.empty()) return {};
  for (uint8_t b : body) {
    if (b >= 0x80 || ((b < 0x20) && b != 0x09 && b != 0x0D && b != 0x0A) || b == 0x7F) {
      fail("参数正文含非 ASCII 或控制字符");
    }
  }
  const std::string text(body.begin(), body.end());
  if (text.size() < 2 || text.compare(text.size() - 2, 2, "\r\n") != 0) fail("参数行没有以 CRLF 结束");
  std::vector<std::string> lines;
  size_t start = 0;
  for (size_t i = 0; i + 1 < text.size();) {
    if (text[i] == '\r' && text[i + 1] == '\n') {
      lines.push_back(text.substr(start, i - start));
      i += 2;
      start = i;
    } else {
      ++i;
    }
  }
  while (!lines.empty() && lines.back().empty()) lines.pop_back();
  for (const auto& line : lines) {
    if (line.empty() || line.find('\r') != std::string::npos || line.find('\n') != std::string::npos) {
      fail("参数正文含空行或裸 CR/LF");
    }
  }
  return lines;
}

std::vector<std::string> query_names(const std::vector<uint8_t>& body) {
  std::vector<std::string> names;
  for (const std::string& line : parameter_lines(body)) {
    std::string name = line;
    if (!name.empty() && name.back() == ':') name.pop_back();
    if (name.empty() || name[0] < 'a' || name[0] > 'z') fail("能力查询名格式错误");
    for (char c : name) {
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) fail("能力查询名格式错误");
    }
    if (std::find(names.begin(), names.end(), name) != names.end()) fail("能力查询名重复");
    names.push_back(name);
  }
  return names;
}

std::map<std::string, std::string> parameter_values(const std::vector<uint8_t>& body) {
  static const std::set<std::string> known = {
      "his_version", "his_video_formats", "his_audio_codecs", "his_uibc_capability",
      "his_vtp", "his_feature", "his_device_type", "his_media_capability",
      "his_audio_formats", "his_support_uwb", "his_support_temp_notify",
      "his_presentation_url", "his_extended_field", "his_player_controller_capability",
      "his_trigger_method",
  };
  std::map<std::string, std::string> values;
  for (const std::string& line : parameter_lines(body)) {
    const size_t colon = line.find(':');
    if (colon == std::string::npos) fail("能力参数缺冒号");
    std::string name = line.substr(0, colon);
    for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (known.count(name) == 0) fail("能力参数名未知");
    if (values.count(name) != 0) fail("能力参数名重复");
    values[name] = trim_space_tab(line.substr(colon + 1));
  }
  return values;
}

}  // namespace hisight
}  // namespace hicar
