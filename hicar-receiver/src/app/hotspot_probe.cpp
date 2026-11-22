#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "platform/hotspot.h"

namespace {

int parse_seconds(int argc, char** argv) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], "--seconds") == 0) return std::atoi(argv[i + 1]);
  }
  return 10;
}

std::string parse_arg(int argc, char** argv, const char* name, const std::string& fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
  }
  return fallback;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace hicar::platform;

  HotspotConfig config;
  config.ssid = parse_arg(argc, argv, "--ssid", "HiCar-Windows");
  config.passphrase = parse_arg(argc, argv, "--pass", "hicar1234");

  HotspotInfo info;
  std::string error;
  if (!start_hotspot(config, &info, &error)) {
    std::fprintf(stderr, "启动热点失败：%s\n", error.c_str());
    return 1;
  }

  std::printf("热点已启动\n");
  std::printf("  SSID      : %s\n", info.ssid.c_str());
  std::printf("  密码      : %s\n", info.passphrase.c_str());
  std::printf("  BSSID     : %s\n", info.bssid.c_str());
  std::printf("  车机 IP   : %s\n", info.car_ip.c_str());
  std::printf("  虚拟网卡  : %s\n", info.adapter_name.c_str());
  if (info.frequency_mhz != 0) {
    std::printf("  频率      : %u MHz（真实信道）\n", info.frequency_mhz);
  } else {
    std::printf("  频率      : 读取失败（需要从 BSS 列表或 netsh 再确认）\n");
  }

  const int seconds = parse_seconds(argc, argv);
  std::printf("%d 秒后停止热点……\n", seconds);
  std::this_thread::sleep_for(std::chrono::seconds(seconds));

  if (!stop_hotspot(&error)) {
    std::fprintf(stderr, "停止热点失败：%s\n", error.c_str());
    return 1;
  }
  std::puts("热点已停止");
  return 0;
}
