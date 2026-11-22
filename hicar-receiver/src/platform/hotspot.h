#pragma once

#include <cstdint>
#include <string>

namespace hicar {
namespace platform {

// Windows Mobile Hotspot（Wi-Fi Direct AP）控制。
// 不是已废弃的 hosted network：AX211 等新网卡只支持前者。
struct HotspotConfig {
  std::string ssid;
  std::string passphrase;
};

struct HotspotInfo {
  std::string ssid;
  std::string passphrase;
  std::string bssid;        // 热点网卡 MAC，小写冒号分隔（连接串里的 BSSID）
  std::string car_ip;       // ICS 网关地址，通常是 192.168.137.1
  std::string adapter_name;  // 热点虚拟网卡名，诊断用
  uint32_t frequency_mhz = 0;  // 从 WLAN BSS 列表读到的真实频率，读不到为 0
};

// 启动热点；成功返回 true 并填 info。上游取当前有 Internet 的连接（以太网）。
bool start_hotspot(const HotspotConfig& config, HotspotInfo* info, std::string* error);

// 停止本进程启动的热点。
bool stop_hotspot(std::string* error);

}  // namespace platform
}  // namespace hicar
