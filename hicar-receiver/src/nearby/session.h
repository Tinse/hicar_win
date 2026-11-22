#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <variant>
#include <vector>

#include "identity/host_identity.h"
#include "nearby/cipher.h"
#include "nearby/data_channel.h"
#include "nearby/frame.h"
#include "nearby/socket_messages.h"
#include "nearby/wifi_connection_info.h"

namespace hicar {

enum class NearbyLink { kUsb, kBluetooth, kWifi };

// 要发出去的帧（已编码成线上字节）。
struct SendFrame {
  std::vector<uint8_t> bytes;
};

struct HandshakeCompleted {
  uint32_t peer_version = 0;
  std::optional<std::string> peer_summary;
  bool encrypted = false;
};

// 手机请求车机为某个业务新开一条 TCP（业务 19 = hicarAuth，20 = DMSDP）。
struct SocketRequested {
  uint32_t outer_type = 0;
  uint32_t channel = 0;
  socket_messages::Request request;
};

struct SocketRequestRejected {
  uint32_t channel = 0;
  uint32_t business_id = 0;
  std::string tag_text;
  std::string reason;
};

struct InputDiscarded {
  std::string reason;
  size_t size = 0;
};

struct UnhandledMessage {
  uint32_t outer_type = 0;
  std::optional<uint32_t> tag;
  std::vector<uint8_t> payload;
};

struct HandshakeTimedOut {};

struct PeerBluetoothAddress {
  std::string text;
};

// 蓝牙控制通道上：手机要 WiFi 数据通道（资源层命令 1）。
struct DataChannelRequested {
  uint32_t data_channel = 0;
  WifiCapability capability;
};

// 手机对协商结果的回执（资源层命令 7）。
struct DataChannelResult {
  uint32_t data_channel = 0;
  uint32_t result = 0;
  std::optional<uint32_t> role;
  std::optional<uint32_t> frequency_mhz;
};

// WiFi 组网层（外层类型 33）：手机回的 WiFi MAC，或 busy。
struct WifiPeerAddress {
  std::string mac;  // 小写、冒号分隔
};

struct WifiPeerBusy {};

struct WifiDisconnectRequested {};

struct WifiDisconnectAnswered {};

using NearbyAction =
    std::variant<SendFrame, HandshakeCompleted, SocketRequested, SocketRequestRejected, InputDiscarded,
                 UnhandledMessage, HandshakeTimedOut, PeerBluetoothAddress, DataChannelRequested,
                 DataChannelResult, WifiPeerAddress, WifiPeerBusy, WifiDisconnectRequested, WifiDisconnectAnswered>;

// nearby 层入口：车机在一条控制通道上的协议状态机，不做 I/O。
// 时间由调用方传入（单调毫秒），同一会话的调用必须串行。
class NearbySession {
 public:
  static constexpr uint32_t kBusinessAuth = 19;
  static constexpr uint32_t kBusinessDmsdp = 20;
  static constexpr uint32_t kChannelUsb = 6;
  static constexpr uint32_t kChannelBluetooth = 2;
  static constexpr uint32_t kChannelWifi = 3;
  static constexpr uint64_t kHandshakeTimeoutMillis = 5000;

  NearbySession(HostIdentity host, NearbyKeyMaterial keys,
                std::optional<std::array<uint8_t, 6>> bluetooth_address, NearbyLink link = NearbyLink::kUsb,
                uint64_t rng_seed = 0);

  // 连接建立后立刻调用：发明文 connectId，开始握手计时。WiFi 通道另外先当一次发起方。
  std::vector<NearbyAction> start(uint64_t now_millis);

  // 喂入控制通道读到的字节（可半帧、可多帧）。
  std::vector<NearbyAction> feed(const std::vector<uint8_t>& data);

  // 到 next_tick_at() 时调用，握手超时给出 HandshakeTimedOut 并作废会话。
  std::vector<NearbyAction> on_tick(uint64_t now_millis);

  std::optional<uint64_t> next_tick_at() const { return deadline_; }

  std::vector<NearbyAction> accept_socket(const SocketRequested& request, uint32_t port);
  std::vector<NearbyAction> reject_socket(const SocketRequested& request);

  // 蓝牙控制通道上为认证开 RFCOMM 子通道：回通道号 + 16 字节服务 UUID。
  std::vector<NearbyAction> accept_rfcomm_socket(const SocketRequested& request, uint32_t channel);

  // 蓝牙控制通道上应答数据通道协商（车机当组主），频率必须真实可用。
  std::vector<NearbyAction> accept_data_channel(const DataChannelRequested& request, uint32_t frequency_mhz);
  std::vector<NearbyAction> reject_data_channel(const DataChannelRequested& request, DataChannelRefusal refusal);

  // WiFi 组网层：要手机 MAC、下发连接串、请求断开（只在蓝牙控制通道上）。
  std::vector<NearbyAction> request_wifi_peer_address();
  std::vector<NearbyAction> send_wifi_connection_info(const WifiConnectionInfo& info);
  std::vector<NearbyAction> request_wifi_disconnect();

  const std::string& device_id() const { return device_id_hex_; }
  const std::string& bluetooth_address_text() const { return bluetooth_text_; }
  bool handshake_complete() const { return handshake_complete_; }
  bool encrypted() const { return encrypted_; }
  bool closed() const { return closed_; }

 private:
  void handle_frame(const NearbyFrame& frame, std::vector<NearbyAction>& out);
  void handle_channel_management(const std::vector<uint8_t>& payload, std::vector<NearbyAction>& out);
  void handle_socket_layer(uint32_t outer_type, const std::vector<uint8_t>& payload,
                           std::vector<NearbyAction>& out);
  void handle_wifi_link(const std::vector<uint8_t>& payload, std::vector<NearbyAction>& out);
  std::vector<NearbyAction> respond(const SocketRequested& request, uint32_t status, uint32_t port,
                                    uint32_t protocol, const std::optional<std::vector<uint8_t>>& uuid = std::nullopt);
  void send(uint32_t outer_type, const std::vector<uint8_t>& payload, std::vector<NearbyAction>& out);
  std::vector<uint8_t> next_seed();
  uint32_t next_connect_id();

  NearbyLink link_;
  HostIdentity host_;
  NearbyFrameCipher cipher_;
  NearbyFrameDecoder decoder_;
  std::mt19937_64 rng_;

  std::string device_id_hex_;
  std::string bluetooth_text_;
  std::vector<uint8_t> own_device_id_text_;
  std::vector<uint8_t> own_address_text_;

  bool started_ = false;
  bool closed_ = false;
  bool handshake_complete_ = false;
  std::optional<uint64_t> deadline_;

  bool encrypted_ = false;
  uint32_t seen_ = 0;
  std::optional<uint32_t> peer_version_;
  std::optional<std::vector<uint8_t>> peer_summary_;
  std::optional<std::vector<uint8_t>> peer_device_id_;
  std::optional<std::string> peer_bluetooth_;
  bool sent_bluetooth_request_ = false;
};

}  // namespace hicar
