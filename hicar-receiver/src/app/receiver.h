#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "auth/session.h"
#include "dmsdp/audio_stream.h"
#include "dmsdp/session.h"
#include "hisight/receiver.h"
#include "identity/host_identity.h"
#include "nearby/cipher.h"
#include "nearby/session.h"
#include "platform/bluetooth.h"
#include "platform/app_window.h"
#include "platform/audio_player.h"
#include "platform/frame_window.h"
#include "platform/hotspot.h"
#include "platform/mf_decoder.h"
#include "platform/tcp.h"

namespace hicar {

struct ReceiverConfig {
  std::string bind_ip = "0.0.0.0";  // 有线时填车机在 USB 网卡上的 IP
  uint16_t control_port = 32400;
  std::optional<std::array<uint8_t, 6>> bluetooth_address;
  NearbyLink link = NearbyLink::kUsb;
  HostIdentity host;
  NearbyKeyMaterial keys;
};

// 控制通道接收端：TCP 监听 + 每连接一个 NearbySession + 按需为业务 19/20 开子监听。
// 只做协议与 I/O，不含认证、视频和音频（后续里程碑接入）。
class Receiver {
 public:
  explicit Receiver(ReceiverConfig config);
  ~Receiver();

  bool start(std::string* error);
  void stop() { stop_requested_ = true; }
  int run();

  const std::string& device_id() const { return device_id_; }
  uint16_t control_port() const { return control_port_; }
  const std::string& pin_code() const { return pin_code_; }
  const std::string& pairing_qr_text() const { return pairing_qr_text_; }

 private:
  struct ControlConnection {
    platform::TcpSocket socket;
    std::unique_ptr<NearbySession> session;
  };

  struct DataConnection {
    platform::TcpSocket socket;
    uint32_t business_id = 0;
    size_t total = 0;
    bool greeted = false;
    bool dmsdp_control = false;
    std::shared_ptr<dmsdp::DmsdpSession> dmsdp;
    std::unique_ptr<auth::AuthSession> auth;
  };

  struct ListenerSlot {
    platform::TcpSocket socket;
    uint32_t business_id = 0;
    uint16_t port = 0;
    bool audio = false;
    std::shared_ptr<dmsdp::DmsdpSession> dmsdp;
  };

  struct AudioConnection {
    platform::TcpSocket socket;
    std::shared_ptr<dmsdp::DmsdpSession> dmsdp;
    std::unique_ptr<dmsdp::AudioStreamDecoder> decoder;
    size_t total = 0;
  };

  // 蓝牙控制通道上的 RFCOMM 子监听（认证用）。
  struct RfcommSlot {
    platform::RfcommListener listener;
    uint32_t business_id = 0;
  };

  // HiSight 投屏：控制/视频/回控三条到手机的 TCP。
  struct HisightConnection {
    platform::TcpSocket control;
    platform::TcpSocket video;
    platform::TcpSocket remote;
    std::unique_ptr<hisight::HisightReceiver> receiver;
    std::unique_ptr<platform::MfH264Decoder> decoder;
    std::unique_ptr<platform::FrameWindow> window;
    std::string phone_ip;
    uint32_t port = 0;
    bool closing = false;
  };

  void accept_control();
  void accept_control_rfcomm();
  void add_control(platform::TcpSocket socket, NearbyLink link);
  void accept_wifi_control();
  void start_wifi_stage();
  void reply_data_channel();
  void send_wifi_connection_info();
  void service_control(ControlConnection& connection);
  void dispatch(const std::vector<NearbyAction>& actions, ControlConnection& connection);
  std::optional<uint16_t> open_data_listener(uint32_t business_id, std::string* error);
  std::optional<uint8_t> open_rfcomm_listener(uint32_t business_id, std::string* error);
  void service_data(DataConnection& connection);
  void start_auth(DataConnection& connection);
  void start_dmsdp(DataConnection& connection);
  void service_dmsdp(DataConnection& connection, const uint8_t* data, size_t size);
  void handle_dmsdp_outputs(DataConnection& connection,
                            const std::vector<dmsdp::DmsdpOutput>& outputs);
  std::optional<uint16_t> open_dmsdp_control_listener(
      const std::shared_ptr<dmsdp::DmsdpSession>& session, std::string* error);
  std::optional<uint16_t> open_audio_listener(std::string* error);
  void service_audio(AudioConnection& connection);
  void close_audio_connections();
  void ensure_app_window();
  void request_app_list(bool force);
  void start_car_app(const std::string& package_name);
  void handle_car_data(uint32_t data_type, const std::vector<uint8_t>& data);
  void service_auth(DataConnection& connection, const uint8_t* data, size_t size);
  void handle_auth_outputs(DataConnection& connection, const std::vector<auth::AuthOutput>& outputs);
  void start_hisight(const std::string& phone_ip, uint32_t port);
  void service_hisight(HisightConnection& connection);
  void process_hisight_actions(HisightConnection& connection,
                               const std::vector<hisight::HsAction>& actions);
  void close_hisight(HisightConnection& connection, bool send_teardown);
  void tick();
  void refresh_device_id();
  static uint64_t now_millis();

  ReceiverConfig config_;
  platform::WinsockInit winsock_;
  platform::TcpSocket control_listener_;
  platform::RfcommListener bt_listener_;
  uint64_t bt_local_address_ = 0;
  uint16_t control_port_ = 0;
  std::vector<std::unique_ptr<ControlConnection>> controls_;
  std::vector<std::unique_ptr<ListenerSlot>> data_listeners_;
  std::vector<std::unique_ptr<RfcommSlot>> rfcomm_listeners_;
  std::vector<std::unique_ptr<DataConnection>> data_connections_;
  std::vector<std::unique_ptr<AudioConnection>> audio_connections_;
  std::unique_ptr<platform::AudioPlayer> audio_player_;
  std::unique_ptr<platform::AppWindow> app_window_;
  std::shared_ptr<dmsdp::DmsdpSession> app_dmsdp_;
  bool app_list_requested_ = false;
  bool foreground_registered_ = false;
  std::string device_id_;
  std::string pin_code_;
  std::string pairing_qr_text_;
  auth::MemoryTrustStore trust_store_{"hicar_trust.json"};
  auth::SystemRandom auth_random_;
  std::optional<auth::Bytes> auth_session_key_;

  // 无线数据面（M6-b）：认证成功后开热点，手机入网后连 WiFi 控制监听（通道 3）。
  platform::TcpSocket wifi_control_listener_;
  platform::HotspotInfo hotspot_;
  uint16_t wifi_control_port_ = 0;
  bool hotspot_active_ = false;
  bool wifi_stage_started_ = false;
  std::string wifi_ssid_;
  std::string wifi_passphrase_;
  std::optional<DataChannelRequested> pending_data_channel_;
  ControlConnection* data_channel_control_ = nullptr;
  bool awaiting_wifi_mac_ = false;
  bool wifi_connection_sent_ = false;
  std::vector<std::unique_ptr<HisightConnection>> hisight_;
  std::atomic<bool> stop_requested_{false};
};

}  // namespace hicar
