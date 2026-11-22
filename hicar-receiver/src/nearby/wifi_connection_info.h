#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hicar {

enum class WifiMode { kHotspot, kDirect };

// WiFi 组网层（外层类型 33）tag 3 的连接串。
// 热点格式：<手机IP>##<SSID>\n<BSSID>\n<密码>\n<频率MHz>\n1##version:3##<端口>##<信道号>##hicarApIp:<车机IP>
// 直连格式：<手机IP>##<组名>\n<组主MAC>\n<密码>\n<频率MHz>##version:3##<端口>##hicarApIp:<车机IP>
class WifiConnectionInfo {
 public:
  static constexpr uint32_t kVersion = 3;

  WifiMode mode = WifiMode::kHotspot;
  std::string phone_ip;
  std::string ssid;
  std::string bssid;  // 小写、冒号分隔
  std::string passphrase;
  uint32_t frequency_mhz = 0;
  uint16_t port = 0;
  std::string car_ip;

  // 线上文本；字段不合法时抛 std::invalid_argument。
  std::string encode() const;

  // 解析（自测与诊断用）；格式不对抛 MalformedMessage。
  static WifiConnectionInfo parse(const std::string& text);

  std::optional<uint32_t> channel() const;  // 由频率换算，非法频率为 nullopt
};

// 2.4G/5G 信道频率换算：信道 → MHz（14 特殊为 2484）。
std::optional<uint32_t> frequency_of_channel(uint32_t channel);
std::optional<uint32_t> channel_of_frequency(uint32_t frequency_mhz);

// 在 /24 网段里挑一个不与 car_ip、taken 冲突的手机地址（.2～.100）。
std::string pick_phone_address(const std::string& car_ip, const std::vector<std::string>& taken = {});

}  // namespace hicar
