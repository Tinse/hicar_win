#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "platform/tcp.h"

namespace hicar {
namespace platform {

struct BluetoothRadioInfo {
  uint64_t address = 0;  // BLUETOOTH_ADDRESS.ullLong
  std::array<uint8_t, 6> bytes{};  // AA:BB:CC:DD:EE:FF 顺序
  std::wstring name;
};

// 找第一块可用的本地蓝牙无线电。
std::optional<BluetoothRadioInfo> find_first_radio(std::string* error);

// 把本机蓝牙设为可被发现/可被连接（配对期间需要；失败不阻塞主流程）。
bool set_discoverable(bool enabled, std::string* error);

// RFCOMM 监听：绑定本地地址与通道号（0 = 自动挑），可发布 SDP 记录。
class RfcommListener {
 public:
  RfcommListener() = default;
  RfcommListener(RfcommListener&& other) noexcept;
  RfcommListener& operator=(RfcommListener&& other) noexcept;
  ~RfcommListener();
  RfcommListener(const RfcommListener&) = delete;
  RfcommListener& operator=(const RfcommListener&) = delete;

  // channel 传 0 时从 1 开始找一个空闲通道。
  bool listen(uint64_t local_address, uint8_t channel, std::string* error);
  uint8_t channel() const { return channel_; }
  uintptr_t native() const { return handle_; }
  bool valid() const { return handle_ != TcpSocket::kInvalid; }

  std::optional<TcpSocket> accept(std::string* error);
  void close();

  // 用 WSASetService 发布 SDP 记录（服务 UUID FE35，RFCOMM 通道 = 本监听通道）。
  bool publish_sdp(std::string* error);

 private:
  uintptr_t handle_ = TcpSocket::kInvalid;
  uint64_t local_address_ = 0;
  uint8_t channel_ = 0;
};

// 车机蓝牙地址文本（大写、冒号分隔）。
std::string format_bluetooth_address(const std::array<uint8_t, 6>& address);

// HiCar 的 BLE 发现广播（FDEE service data）。真实车机先靠这条广播让手机
// 在 HiCar 里弹窗，二维码只是 BLE 不可用时的兜底。广播失败不阻塞 RFCOMM。
class BleAdvertiser {
 public:
  BleAdvertiser();
  BleAdvertiser(BleAdvertiser&& other) noexcept;
  BleAdvertiser& operator=(BleAdvertiser&& other) noexcept;
  ~BleAdvertiser();
  BleAdvertiser(const BleAdvertiser&) = delete;
  BleAdvertiser& operator=(const BleAdvertiser&) = delete;

  // model4 是“车型 3 字节 + 子型号 1 字节”，sequence 每轮加一。
  bool start(const std::array<uint8_t, 4>& model4, uint8_t sequence, const std::string& local_name,
             std::string* error);
  void stop();
  bool running() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace platform
}  // namespace hicar
