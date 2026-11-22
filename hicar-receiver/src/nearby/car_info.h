#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hicar {

// 车机经 USB 控制传输交给手机的 91 字节结构，手机据此切成 USB 网卡，再来连车机的 IP:端口。
// 布局（多字节整数都是小端）：
//   "hwnearby" | u16 总长 91 | 9 字节固定头
//   TLV（tag、长度各 1 字节）：
//     01 03 车型编号前 3 字节   02 01 子编号   03 20 deviceId 32 字节
//     04 06 蓝牙地址 6 字节     06 0E 车机 IP 文本 14 字节   07 04 端口 u32
struct CarInfo {
  static constexpr size_t kLength = 91;
  static constexpr size_t kModelIdSize = 3;
  static constexpr size_t kDeviceIdSize = 32;
  static constexpr size_t kBluetoothSize = 6;
  static constexpr size_t kHostIpLength = 14;

  std::array<uint8_t, kModelIdSize> model_id{};
  uint8_t sub_model_id = 0;
  std::array<uint8_t, kDeviceIdSize> device_id{};
  std::array<uint8_t, kBluetoothSize> bluetooth_address{};
  std::string host_ip;  // 必须正好 14 字符，例如 192.168.66.150
  uint32_t port = 0;    // 1..65535

  std::vector<uint8_t> encode() const;

  // 布局不符时抛 MalformedMessage。
  static CarInfo parse(const std::vector<uint8_t>& data);

  static bool is_valid_host_ip(const std::string& ip);
  static bool is_valid_port(uint32_t port);
};

}  // namespace hicar
