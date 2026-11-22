#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace hicar {
namespace hisight {

enum class TouchAction { kDown = 0, kUp = 1, kMove = 2 };

struct TouchPoint {
  int id = 0;
  int x = 0;
  int y = 0;
};

// 回控连接（UIBC）封包：`0x00 | 类别 | BE16 包长 | IV16 || AES-128-CTR(FF×6 || 正文)`。
class UibcEncoder {
 public:
  UibcEncoder(std::array<uint8_t, 16> key, std::set<std::string> events,
              std::set<std::string> vendors, std::optional<int> source_device_type);

  std::vector<uint8_t> encode_touch(TouchAction action, const std::vector<TouchPoint>& points,
                                    int width, int height);
  std::vector<uint8_t> encode_key(bool down, int key_code, uint32_t meta_state);
  std::vector<uint8_t> encode_text(const std::string& text);
  std::vector<std::vector<uint8_t>> release();

  void clear();

  static constexpr int kSourceAndroidKeys = 7;

 private:
  std::vector<uint8_t> wrap(uint8_t category, const std::vector<uint8_t>& body);
  std::array<uint8_t, 16> random_iv();

  std::array<uint8_t, 16> key_;
  std::set<std::string> events_;
  std::set<std::string> vendors_;
  std::optional<int> source_device_type_;

  struct Gesture {
    int width = 0;
    int height = 0;
    std::vector<TouchPoint> points;
  };
  std::optional<Gesture> gesture_;
  std::map<int, uint32_t> pressed_keys_;
};

}  // namespace hisight
}  // namespace hicar
