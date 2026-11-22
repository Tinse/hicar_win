#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace hicar {
namespace hisight {

// HiSight 控制连接的 RTSP 风格消息。头名统一小写；正文只取 Content-Length 声明的部分。
struct RtspMessage {
  std::string first_line;
  std::map<std::string, std::string> headers;
  std::vector<uint8_t> body;
  int cseq = 0;

  bool is_response() const { return first_line.rfind("RTSP/1.0 ", 0) == 0; }
  std::optional<std::string> header(const std::string& name) const;
  bool is_text_parameters() const;

  static constexpr const char* kTextParameters = "text/parameters";
};

// 控制连接分帧：BE32 载荷长度 ‖ 载荷，长度 1..65000。
class ControlFrameDecoder {
 public:
  void append(const uint8_t* data, size_t size);
  bool next(std::vector<uint8_t>* payload);  // 不够一帧返回 false
  bool has_partial() const { return !buffer_.empty(); }

 private:
  std::vector<uint8_t> buffer_;
};

std::vector<uint8_t> encode_control_frame(const std::vector<uint8_t>& payload);

// 解析手机发来的控制消息；不合法抛 std::runtime_error。
RtspMessage parse_rtsp(const std::vector<uint8_t>& payload);

// 请求首行里的方法名；格式不合法抛异常。
std::string request_method(const std::string& first_line);

// 1..max_digits 位 ASCII 十进制；格式不对返回 -1。
long long parse_decimal(const std::string& text, size_t max_digits);

// Date 头：`yyyy-MM-dd HH:mm:ss AM|PM Weekday`（本地时间）。
std::string rtsp_date(uint64_t wall_clock_millis);

// 车机发出的固定消息。
std::vector<uint8_t> rtsp_announce();
std::vector<uint8_t> rtsp_ok(int cseq, const std::string& date, bool with_public = false);
std::vector<uint8_t> rtsp_get_parameter_ok(int cseq, const std::string& body);
std::vector<uint8_t> rtsp_options(int cseq, const std::string& date);
std::vector<uint8_t> rtsp_setup(int cseq);
std::vector<uint8_t> rtsp_play(int cseq);
std::vector<uint8_t> rtsp_teardown(int cseq);

// 参数正文（GET/SET 共用）：按 CRLF 分行，末尾空行丢弃。
std::vector<std::string> parameter_lines(const std::vector<uint8_t>& body);
std::vector<std::string> query_names(const std::vector<uint8_t>& body);
std::map<std::string, std::string> parameter_values(const std::vector<uint8_t>& body);
std::string trim_space_tab(const std::string& text);

}  // namespace hisight
}  // namespace hicar
