#include "hisight/uibc.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>

#include "dmsdp/cipher.h"

namespace hicar {
namespace hisight {
namespace {

void fail(const std::string& message) { throw std::runtime_error(message); }

void put_be16(std::vector<uint8_t>& out, size_t at, uint16_t value) {
  out[at] = static_cast<uint8_t>(value >> 8);
  out[at + 1] = static_cast<uint8_t>(value);
}

}  // namespace

UibcEncoder::UibcEncoder(std::array<uint8_t, 16> key, std::set<std::string> events,
                         std::set<std::string> vendors, std::optional<int> source_device_type)
    : key_(key), events_(std::move(events)), vendors_(std::move(vendors)),
      source_device_type_(source_device_type) {}

std::array<uint8_t, 16> UibcEncoder::random_iv() {
  std::array<uint8_t, 16> iv{};
  std::random_device device;
  for (auto& byte : iv) byte = static_cast<uint8_t>(device());
  return iv;
}

std::vector<uint8_t> UibcEncoder::wrap(uint8_t category, const std::vector<uint8_t>& body) {
  std::vector<uint8_t> plain(6 + body.size(), 0xFF);
  std::copy(body.begin(), body.end(), plain.begin() + 6);
  const auto iv = random_iv();
  const auto cipher = dmsdp::aes128_ctr_crypt(key_.data(), iv.data(), plain.data(), plain.size());
  std::vector<uint8_t> packet(4 + 16 + cipher.size());
  packet[0] = 0;
  packet[1] = category;
  put_be16(packet, 2, static_cast<uint16_t>(packet.size()));
  std::copy(iv.begin(), iv.end(), packet.begin() + 4);
  std::copy(cipher.begin(), cipher.end(), packet.begin() + 20);
  return packet;
}

std::vector<uint8_t> UibcEncoder::encode_touch(TouchAction action, const std::vector<TouchPoint>& points,
                                               int width, int height) {
  const char* event = action == TouchAction::kDown ? "left_point_down"
                      : action == TouchAction::kUp ? "left_point_up"
                                                   : "left_move";
  if (events_.count(event) == 0) fail("触摸事件未经本次协商允许");
  if (width < 1 || width > 65535 || height < 1 || height > 65535) fail("视频宽高必须是 1..65535");
  if (points.empty() || points.size() > 10) fail("触点数必须是 1..10");

  std::vector<TouchPoint> sorted = points;
  std::sort(sorted.begin(), sorted.end(),
            [](const TouchPoint& a, const TouchPoint& b) { return a.id < b.id; });
  for (const auto& point : sorted) {
    if (point.id < 0 || point.id > 31 || point.x < 0 || point.x >= width || point.y < 0 ||
        point.y >= height) {
      fail("触点编号或坐标超出范围");
    }
  }
  for (size_t i = 1; i < sorted.size(); ++i) {
    if (sorted[i].id == sorted[i - 1].id) fail("触点编号重复");
  }

  if (action == TouchAction::kDown && gesture_.has_value()) fail("还有按下的触点时不能再按下");
  if (action == TouchAction::kMove && !gesture_.has_value()) fail("移动前必须先按下");
  if (action == TouchAction::kUp) {
    if (sorted.size() != 1) fail("抬起只能带一个触点");
    if (!gesture_.has_value()) fail("抬起前必须先按下");
    bool found = false;
    for (const auto& point : gesture_->points) if (point.id == sorted[0].id) found = true;
    if (!found) fail("抬起的触点不在当前按下的触点里");
  }

  const size_t n = sorted.size();
  const size_t padding = (4 + 5 * n) % 2;
  std::vector<uint8_t> body(4 + 5 * n + padding, 0);
  body[0] = static_cast<uint8_t>(action);
  put_be16(body, 1, static_cast<uint16_t>(1 + 5 * n + padding));
  body[3] = static_cast<uint8_t>(n);
  size_t at = 4;
  for (const auto& point : sorted) {
    body[at] = static_cast<uint8_t>(point.id);
    put_be16(body, at + 1, static_cast<uint16_t>(point.x));
    put_be16(body, at + 3, static_cast<uint16_t>(point.y));
    at += 5;
  }
  const auto packet = wrap(0, body);
  if (action == TouchAction::kUp) {
    gesture_.reset();
  } else {
    gesture_ = Gesture{width, height, sorted};
  }
  return packet;
}

std::vector<uint8_t> UibcEncoder::encode_key(bool down, int key_code, uint32_t meta_state) {
  const char* event = down ? "left_key_down" : "left_key_up";
  if (events_.count(event) == 0) fail("按键未经本次协商允许");
  if (key_code < 0 || key_code > 0xFFFF) fail("键码超出范围");
  static const std::set<int> basic = {4, 5, 6, 19, 20, 21, 22, 23, 24, 25, 85, 86, 87, 88, 89, 90, 126, 127};
  if (source_device_type_.value_or(0) != kSourceAndroidKeys &&
      (basic.count(key_code) == 0 || meta_state != 0)) {
    fail("手机没选源设备类型 7，只能发基础键、修饰位为 0");
  }
  if (!down && pressed_keys_.count(key_code) == 0) fail("按键抬起前必须已经按下");

  std::vector<uint8_t> body(12, 0);
  body[0] = static_cast<uint8_t>(down ? 3 : 4);
  put_be16(body, 1, 9);
  put_be16(body, 4, static_cast<uint16_t>(key_code));
  for (size_t i = 0; i < 4; ++i) body[8 + i] = static_cast<uint8_t>(meta_state >> (24 - 8 * i));
  const auto packet = wrap(0, body);
  if (down) {
    pressed_keys_[key_code] = meta_state;
  } else {
    pressed_keys_.erase(key_code);
  }
  return packet;
}

std::vector<uint8_t> UibcEncoder::encode_text(const std::string& text) {
  if (vendors_.count("input_content") == 0) fail("成文输入未经本次协商允许");
  if (text.find('\0') != std::string::npos) fail("成文输入不能含 NUL");
  if (text.empty() || text.size() > 472) fail("成文输入的字节数必须是 1..472");
  const size_t padding = (5 + text.size()) % 2;
  std::vector<uint8_t> body(5 + text.size() + padding, 0);
  put_be16(body, 1, static_cast<uint16_t>(2 + text.size() + padding));
  put_be16(body, 3, static_cast<uint16_t>(text.size()));
  std::copy(text.begin(), text.end(), body.begin() + 5);
  return wrap(2, body);
}

std::vector<std::vector<uint8_t>> UibcEncoder::release() {
  std::vector<std::vector<uint8_t>> out;
  if (gesture_.has_value() && !gesture_->points.empty()) {
    out.push_back(encode_touch(TouchAction::kUp, {gesture_->points.front()}, gesture_->width,
                               gesture_->height));
  }
  std::vector<int> codes;
  for (const auto& item : pressed_keys_) codes.push_back(item.first);
  for (auto it = codes.rbegin(); it != codes.rend(); ++it) {
    out.push_back(encode_key(false, *it, pressed_keys_[*it]));
  }
  return out;
}

void UibcEncoder::clear() {
  gesture_.reset();
  pressed_keys_.clear();
}

}  // namespace hisight
}  // namespace hicar
