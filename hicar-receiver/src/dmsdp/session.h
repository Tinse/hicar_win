#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "auth/crypto.h"
#include "dmsdp/framing.h"
#include "dmsdp/message.h"

namespace hicar {
namespace dmsdp {

enum class DmsdpChannel { kSession, kControl, kAudio, kMic, kFileControl, kFileData };

struct DmsdpDisplay {
  int width = 1280;
  int height = 720;
  double density = 1.0;
  int dpi = 160;
  int fps = 30;
  int video_width = 1280;
  int video_height = 720;
  int codec = 1;  // 1=H.264, 2=H.265
  std::optional<int> gop;
  std::optional<int> bitrate;
};

struct DmsdpService {
  uint32_t service_type = 0;
  std::string service_id;
  std::string properties_json = "{}";
  std::string status_json = "{}";
};

struct DmsdpConfig {
  std::string device_id;      // 64 位大写十六进制
  std::string device_name;    // 同时作 deviceName / btName
  std::string bluetooth_mac;  // AA:BB:CC:DD:EE:FF（大写）
  std::string local_ip;
  std::string phone_ip;
  std::string full_model;     // 8 位车型编号，属性 2003
  std::optional<DmsdpDisplay> display;
  std::optional<DmsdpService> speaker;
  std::optional<DmsdpService> mic;
  std::vector<DmsdpService> additional_services;
  bool advertise_udp_keep_alive = true;
  int keep_alive_retry = 160;
  int platform = 0;
};

struct DmsdpAction {
  enum class Kind {
    kSend,
    kOpenControlListener,
    kOpenKeepAliveSocket,
    kSendDatagram,
    kOpenAudioListener,
    kCloseAudioTransport,
  };
  Kind kind = Kind::kSend;
  DmsdpChannel channel = DmsdpChannel::kSession;
  std::vector<uint8_t> bytes;
  uint16_t port = 0;
};

struct DmsdpEvent {
  enum class Kind {
    kEncryptionEnabled,
    kPeerDeviceInfo,
    kPeerServiceInfo,
    kServiceStatusChanged,
    kServicesRequested,
    kDisplayPortAnnounced,
    kTimeSyncRequested,
    kKeepAliveTimeout,
    kUnhandledControlMessage,
    kUnhandledDeviceData,
    kUnsupportedDeviceCommand,
    kAudioSessionEstablished,
    kAudioSessionTornDown,
    kCarData,
  };

  Kind kind = Kind::kUnhandledControlMessage;
  bool flag = false;
  uint32_t number = 0;
  uint32_t number2 = 0;
  int32_t signed_number = 0;
  std::string text;   // 设备 ID / 服务 ID / 首行
  std::string text2;  // 时间同步的 high|low
  std::string json;   // 设备或服务 JSON
  std::vector<uint8_t> data;
};

using DmsdpOutput = std::variant<DmsdpAction, DmsdpEvent>;

// DMSDP 设备会话：纯协议状态机，不做 socket/线程/定时器。
class DmsdpSession {
 public:
  DmsdpSession(DmsdpConfig config, const std::array<uint8_t, 16>& session_key,
               auth::RandomSource* random);

  std::vector<DmsdpOutput> feed(DmsdpChannel channel, const uint8_t* data, size_t size,
                                uint64_t now_millis);
  std::vector<DmsdpOutput> on_connected(DmsdpChannel channel, uint64_t now_millis);
  std::vector<DmsdpOutput> control_listener_ready(uint16_t port, uint64_t now_millis);
  std::vector<DmsdpOutput> audio_listener_ready(uint16_t port, uint64_t now_millis);
  std::vector<DmsdpOutput> on_datagram(const uint8_t* data, size_t size, uint64_t now_millis);
  std::vector<DmsdpOutput> on_tick(uint64_t now_millis);
  std::vector<DmsdpOutput> close();

  std::optional<uint64_t> next_tick_at() const;
  bool encrypted() const { return control_state_ == ControlState::kEncrypted; }
  bool failed() const { return failed_; }
  bool closed() const { return closed_; }

  // 加密后发一条设备记录（不含 11 字节头）。
  std::vector<DmsdpOutput> send_device_data(uint32_t module, int32_t type,
                                            const std::vector<uint8_t>& data);

 private:
  enum class ControlState { kNotConnected, kPlaintext, kEncrypted, kClosed };

  struct UdpKeepAliveState {
    bool extended = false;
    uint32_t period = 2;
    uint32_t round = 0;
    uint32_t received = 0;
    std::optional<uint64_t> next_at;
  };

  std::vector<DmsdpOutput> feed_session(const uint8_t* data, size_t size);
  std::vector<DmsdpOutput> feed_control(const uint8_t* data, size_t size, uint64_t now);
  std::vector<DmsdpOutput> on_plain_payload(const std::vector<uint8_t>& payload, uint64_t now);
  std::vector<DmsdpOutput> on_crypto_selection(const DmsdpMessage& message, uint64_t now);
  std::vector<DmsdpOutput> on_encrypted_payload(const std::vector<uint8_t>& payload, uint64_t now);
  std::vector<DmsdpOutput> on_audio_trigger(const DmsdpMessage& message, uint64_t now);
  std::vector<DmsdpOutput> on_audio_setup_response(const DmsdpMessage& message, uint64_t now);
  std::vector<DmsdpOutput> send_audio_setup(uint16_t port);
  std::vector<DmsdpOutput> on_device_record(uint32_t module, int32_t type,
                                            const std::vector<uint8_t>& data, uint64_t now);
  std::vector<DmsdpOutput> handle_device_command(const std::vector<uint8_t>& data);
  std::vector<DmsdpOutput> send_text(const std::vector<uint8_t>& text);
  std::vector<DmsdpOutput> send_request(const std::string& method,
                                        const std::vector<std::pair<std::string, std::string>>& headers);
  std::vector<DmsdpOutput> send_record(uint32_t module, int32_t type,
                                       const std::vector<uint8_t>& data);
  std::vector<uint8_t> seal(const std::vector<uint8_t>& plain);
  std::vector<uint8_t> open(const std::vector<uint8_t>& sealed);
  void check_usable() const;
  std::vector<DmsdpService> local_services() const;
  std::string local_device_json() const;
  std::string service_json(const DmsdpService& service) const;
  void remember_phone_time(const DmsdpMessage& message, uint64_t now);

  DmsdpConfig config_;
  std::array<uint8_t, 16> key_{};
  auth::RandomSource* random_ = nullptr;
  SessionFrameDecoder session_decoder_;
  ControlFrameDecoder control_decoder_;
  ControlState control_state_ = ControlState::kNotConnected;
  uint16_t control_port_ = 0;
  uint32_t pending_negotiations_ = 0;
  bool listener_requested_ = false;
  uint32_t next_cseq_ = 1;
  bool failed_ = false;
  bool closed_ = false;

  bool tcp_keep_alive_active_ = false;
  uint64_t tcp_next_at_ = 0;
  bool tcp_alive_ = false;
  bool tcp_started_ = false;
  int tcp_misses_ = 0;

  bool udp_keep_alive_active_ = false;
  UdpKeepAliveState udp_;

  bool local_info_sent_ = false;
  std::string peer_device_id_;
  std::optional<int64_t> phone_time_us_;
  uint64_t phone_time_at_millis_ = 0;

  bool audio_active_ = false;
  bool audio_setup_sent_ = false;
  std::string audio_session_id_;
  uint16_t audio_port_ = 0;
  uint32_t audio_setup_cseq_ = 0;
};

}  // namespace dmsdp
}  // namespace hicar
