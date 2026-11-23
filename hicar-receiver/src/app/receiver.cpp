#include <winsock2.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <random>

#include "app/receiver.h"
#include "auth/json.h"
#include "common/hex.h"
#include "identity/device_id.h"

namespace hicar {

namespace {

// 把事件写成一行日志。
void log_event(const NearbyAction& action) {
  if (const auto* handshake = std::get_if<HandshakeCompleted>(&action)) {
    std::printf("[控制通道] 握手完成：对端版本 %u，摘要 %s，加密 %s\n", handshake->peer_version,
                handshake->peer_summary.has_value() ? handshake->peer_summary->c_str() : "(无)",
                handshake->encrypted ? "开" : "关");
  } else if (const auto* request = std::get_if<SocketRequested>(&action)) {
    const std::string tag(request->request.tag.begin(), request->request.tag.end());
    std::printf("[控制通道] 手机请求建 socket：外层 %u，通道 %u，业务 %u，标签 \"%s\"，协议 0x%X\n",
                request->outer_type, request->channel, request->request.business_id, tag.c_str(),
                request->request.protocol);
  } else if (const auto* rejected = std::get_if<SocketRequestRejected>(&action)) {
    std::printf("[控制通道] 拒绝建 socket：业务 %u，标签 \"%s\"，原因 %s\n", rejected->business_id,
                rejected->tag_text.c_str(), rejected->reason.c_str());
  } else if (const auto* discarded = std::get_if<InputDiscarded>(&action)) {
    std::printf("[控制通道] 丢弃输入：%s（%zu 字节）\n", discarded->reason.c_str(), discarded->size);
  } else if (const auto* unhandled = std::get_if<UnhandledMessage>(&action)) {
    std::printf("[控制通道] 未处理：外层 %u，tag %s，载荷 %s\n", unhandled->outer_type,
                unhandled->tag.has_value() ? std::to_string(*unhandled->tag).c_str() : "(无)",
                to_hex(unhandled->payload).c_str());
  } else if (const auto* timeout = std::get_if<HandshakeTimedOut>(&action)) {
    (void)timeout;
    std::printf("[控制通道] 握手超时，关闭连接\n");
  } else if (const auto* bluetooth = std::get_if<PeerBluetoothAddress>(&action)) {
    std::printf("[控制通道] 对端蓝牙地址：%s\n", bluetooth->text.c_str());
  }
}

void print_hex_dump(const std::vector<uint8_t>& data, size_t limit) {
  const size_t shown = data.size() < limit ? data.size() : limit;
  std::string text = to_hex(data.data(), shown);
  std::printf("        %s%s\n", text.c_str(), data.size() > shown ? " …" : "");
}

std::string format_mac(const std::array<uint8_t, 6>& address) {
  char text[18];
  std::snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1],
                address[2], address[3], address[4], address[5]);
  return text;
}

}  // namespace

Receiver::Receiver(ReceiverConfig config) : config_(std::move(config)) {
  std::random_device random;
  const uint32_t suffix = random() % 10000u;
  const uint32_t secret = random() % 100000000u;
  char ssid[32];
  std::snprintf(ssid, sizeof(ssid), "HiCar-Windows-%04u", suffix);
  wifi_ssid_ = ssid;
  char pass[16];
  std::snprintf(pass, sizeof(pass), "%08u", secret);
  wifi_passphrase_ = pass;
  refresh_device_id();
}

void Receiver::refresh_device_id() {
  std::array<uint8_t, 6> address{};
  if (config_.bluetooth_address.has_value()) address = *config_.bluetooth_address;
  device_id_ = device_id_hex(derive_device_id(config_.host.model_id, config_.host.sub_model_id, address));
}

void Receiver::refresh_pairing_code() {
  std::random_device device;
  const uint32_t value = 100000 + device() % 900000;
  pin_code_ = std::to_string(value);
  pairing_qr_text_ = "hicar://car/connect?devicename=HiCar-Windows&moduleid=000480&submoduleid=00&mac=" +
                     platform::format_bluetooth_address(*config_.bluetooth_address) + "&ability=4&pin=" +
                     pin_code_;
  pairing_pin_expires_ms_ = now_millis() + 120000;  // 与 HiCar 车机一致：连接码 2 分钟有效
  std::printf("  连接码已刷新：%s（2 分钟内有效）\n", pin_code_.c_str());
  std::printf("  二维码内容：%s\n", pairing_qr_text_.c_str());
  if (qr_window_ != nullptr) {
    std::string image_path;
    std::string error;
    if (!qr_window_->show(pairing_qr_text_, pin_code_, &image_path, &error)) {
      std::fprintf(stderr, "[配对] 二维码刷新失败：%s\n", error.c_str());
    }
  }
}

Receiver::~Receiver() {
  std::string ignored;
  ble_advertiser_.stop();
  if (qr_window_ != nullptr) qr_window_->close();
  if (hotspot_active_) platform::stop_hotspot(&ignored);
  if (config_.link == NearbyLink::kBluetooth) platform::set_discoverable(false, &ignored);
}

bool Receiver::start(std::string* error) {
  if (!winsock_.ok()) {
    if (error != nullptr) *error = "WSAStartup 失败";
    return false;
  }

  if (config_.link == NearbyLink::kBluetooth) {
    auto radio = platform::find_first_radio(error);
    if (!radio.has_value()) return false;
    // 蓝牙链路必须用本机真实 radio 地址：二维码里的 mac、deviceId 派生和 RFCOMM
    // 监听都要一致。之前默认参数 02:12:34:56:78:9A 会覆盖真实地址，手机照着
    // 二维码去连一个不存在的 MAC，表现就是扫码后一直连不上。
    config_.bluetooth_address = radio->bytes;
    refresh_device_id();
    bt_local_address_ = radio->address;

    if (!bt_listener_.listen(radio->address, 0, error)) return false;
    if (!bt_listener_.publish_sdp(error)) return false;

    std::printf("HiCar 接收端已启动（蓝牙控制通道）\n");
    std::printf("  蓝牙地址：%s\n", platform::format_bluetooth_address(radio->bytes).c_str());
    std::printf("  RFCOMM 通道：%u，SDP 已发布（UUID 0000FE35）\n", bt_listener_.channel());
    std::printf("  本机 deviceId：%s\n", device_id_.c_str());

    // 本次配对用的 6 位连接码；二维码内容是手机扫码后直接连蓝牙的参数。
    refresh_pairing_code();
    std::printf("  连接码：%s\n", pin_code_.c_str());
    std::printf("  二维码内容：%s\n", pairing_qr_text_.c_str());

    std::string bt_error;
    if (!platform::set_discoverable(true, &bt_error)) {
      std::fprintf(stderr, "[配对] 蓝牙可发现设置失败（不影响已启动的 RFCOMM 监听）：%s\n",
                   bt_error.c_str());
    }

    std::array<uint8_t, 4> model4{};
    for (size_t i = 0; i < model4.size() - 1; ++i) model4[i] = config_.host.model_id[i];
    model4[3] = config_.host.sub_model_id;
    if (config_.disable_ble) {
      std::printf("  BLE 发现广播已关闭：扫码连接模式\n");
    } else {
      std::random_device ble_device;
      std::string ble_error;
      if (ble_advertiser_.start(model4, static_cast<uint8_t>(ble_device() & 0xFF), "HiCar-Windows", &ble_error)) {
        std::printf("  BLE 发现广播已开：FDEE service data（手机 HiCar 应能直接弹窗）\n");
      } else {
        std::fprintf(stderr, "[配对] BLE 广播未启动（仍可用二维码）：%s\n", ble_error.c_str());
      }
    }

    qr_window_ = std::make_unique<platform::QrWindow>();
    std::string qr_image_path;
    std::string qr_error;
    if (qr_window_->show(pairing_qr_text_, pin_code_, &qr_image_path, &qr_error)) {
      if (!qr_image_path.empty()) std::printf("  二维码图片：%s\n", qr_image_path.c_str());
    } else {
      std::fprintf(stderr, "[配对] 二维码窗口打开失败：%s\n", qr_error.c_str());
    }
    std::fflush(stdout);
    return true;
  }

  auto listener = platform::TcpSocket::listen_on(config_.bind_ip, config_.control_port, error);
  if (!listener.has_value()) return false;
  control_port_ = listener->local_port();
  control_listener_ = std::move(*listener);

  std::printf("HiCar 接收端已启动\n");
  std::printf("  监听：%s:%u（控制通道）\n", config_.bind_ip.c_str(), control_port_);
  std::printf("  本机 deviceId：%s\n", device_id_.c_str());
  std::printf("  链路：%s\n", config_.link == NearbyLink::kUsb ? "USB"
                            : config_.link == NearbyLink::kBluetooth ? "蓝牙" : "WiFi");
  return true;
}

int Receiver::run() {
  while (!stop_requested_) {
    fd_set read_set;
    FD_ZERO(&read_set);
    SOCKET max_socket = 0;
    int has = 0;
    auto add_handle = [&](SOCKET handle) {
      if (handle == INVALID_SOCKET) return;
      FD_SET(handle, &read_set);
      if (handle > max_socket) max_socket = handle;
      has = 1;
    };
    auto add = [&](const platform::TcpSocket& socket) {
      if (!socket.valid()) return;
      add_handle(static_cast<SOCKET>(socket.native()));
    };
    add(control_listener_);
    add(wifi_control_listener_);
    if (bt_listener_.valid()) add_handle(static_cast<SOCKET>(bt_listener_.native()));
    for (const auto& connection : controls_) add(connection->socket);
    for (const auto& slot : data_listeners_) add(slot->socket);
    for (const auto& slot : rfcomm_listeners_) {
      if (slot->listener.valid()) add_handle(static_cast<SOCKET>(slot->listener.native()));
    }
    for (const auto& connection : data_connections_) add(connection->socket);
    for (const auto& connection : audio_connections_) add(connection->socket);
    if (!has) break;


    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 20 * 1000;
    const int ready = select(0, &read_set, nullptr, nullptr, &timeout);
    if (ready < 0) {
      std::fprintf(stderr, "select 失败: %d\n", WSAGetLastError());
      return 1;
    }

    if (ready > 0 && FD_ISSET(static_cast<SOCKET>(control_listener_.native()), &read_set)) accept_control();

    if (wifi_control_listener_.valid() &&
        FD_ISSET(static_cast<SOCKET>(wifi_control_listener_.native()), &read_set)) {
      accept_wifi_control();
    }

    if (bt_listener_.valid() &&
        FD_ISSET(static_cast<SOCKET>(bt_listener_.native()), &read_set)) {
      accept_control_rfcomm();
    }

    for (auto& slot : rfcomm_listeners_) {
      if (!slot->listener.valid()) continue;
      const SOCKET handle = static_cast<SOCKET>(slot->listener.native());
      if (!FD_ISSET(handle, &read_set)) continue;
      std::string error;
      auto accepted = slot->listener.accept(&error);
      if (!accepted.has_value()) {
        std::fprintf(stderr, "[业务 %u] RFCOMM accept 失败：%s\n", slot->business_id, error.c_str());
        continue;
      }
      auto connection = std::make_unique<DataConnection>();
      connection->socket = std::move(*accepted);
      connection->business_id = slot->business_id;
      std::printf("[业务 %u] 蓝牙子通道已建立\n", slot->business_id);
      if (connection->business_id == NearbySession::kBusinessAuth) start_auth(*connection);
      data_connections_.push_back(std::move(connection));
    }

    for (auto& slot : data_listeners_) {
      if (!slot->socket.valid()) continue;
      if (!FD_ISSET(static_cast<SOCKET>(slot->socket.native()), &read_set)) continue;
      std::string error;
      auto accepted = slot->socket.accept(&error);
      if (!accepted.has_value()) {
        std::fprintf(stderr, "[业务 %u] accept 失败：%s\n", slot->business_id, error.c_str());
        continue;
      }
      auto connection = std::make_unique<DataConnection>();
      connection->socket = std::move(*accepted);
      connection->business_id = slot->business_id;
      if (slot->audio) {
        auto audio = std::make_unique<AudioConnection>();
        audio->socket = std::move(connection->socket);
        audio->dmsdp = slot->dmsdp;
        if (auth_session_key_.has_value() && auth_session_key_->size() == 16) {
          std::array<uint8_t, 16> key{};
          for (size_t i = 0; i < 16; ++i) key[i] = (*auth_session_key_)[i];
          audio->decoder = std::make_unique<dmsdp::AudioStreamDecoder>(key);
        }
        if (!audio_player_) {
          audio_player_ = std::make_unique<platform::AudioPlayer>();
          std::string audio_error;
          if (!audio_player_->open(&audio_error)) {
            std::fprintf(stderr, "[DMSDP] 音频输出打开失败：%s\n", audio_error.c_str());
            audio_player_.reset();
          }
        }
        std::printf("[DMSDP] 扬声器数据连接已建立：%s\n", audio->socket.peer_ip().c_str());
        audio_connections_.push_back(std::move(audio));
        continue;
      }
      if (slot->dmsdp) {
        connection->dmsdp = slot->dmsdp;
        connection->dmsdp_control = true;
        std::puts("[DMSDP] 控制连接已建立");
        const auto outputs = connection->dmsdp->on_connected(dmsdp::DmsdpChannel::kControl,
                                                             now_millis());
        handle_dmsdp_outputs(*connection, outputs);
      } else {
        std::printf("[业务 %u] 子连接已建立\n", slot->business_id);
        if (connection->business_id == NearbySession::kBusinessAuth) {
          start_auth(*connection);
        } else if (connection->business_id == NearbySession::kBusinessDmsdp) {
          start_dmsdp(*connection);
        }
      }
      data_connections_.push_back(std::move(connection));
    }

    for (auto& connection : controls_) {
      if (!connection->socket.valid()) continue;
      if (FD_ISSET(static_cast<SOCKET>(connection->socket.native()), &read_set)) service_control(*connection);
    }

    for (auto& connection : data_connections_) {
      if (!connection->socket.valid()) continue;
      if (FD_ISSET(static_cast<SOCKET>(connection->socket.native()), &read_set)) service_data(*connection);
    }

    for (auto& connection : audio_connections_) {
      if (!connection->socket.valid()) continue;
      if (FD_ISSET(static_cast<SOCKET>(connection->socket.native()), &read_set)) service_audio(*connection);
    }

    tick();

    // 清理已关闭的控制连接
    for (auto it = controls_.begin(); it != controls_.end();) {
      if (!(*it)->socket.valid()) it = controls_.erase(it);
      else ++it;
    }
    for (auto it = data_connections_.begin(); it != data_connections_.end();) {
      if (!(*it)->socket.valid()) it = data_connections_.erase(it);
      else ++it;
    }
    for (auto it = audio_connections_.begin(); it != audio_connections_.end();) {
      if (!(*it)->socket.valid()) it = audio_connections_.erase(it);
      else ++it;
    }
    if (app_dmsdp_ && find_dmsdp_connection(app_dmsdp_, true) == nullptr &&
        find_dmsdp_connection(app_dmsdp_, false) == nullptr) {
      app_dmsdp_.reset();
      app_list_requested_ = false;
      foreground_registered_ = false;
      app_list_retry_at_ms_ = 0;
      app_count_ = 0;
      if (app_window_) app_window_->set_status("DMSDP 会话已断开");
    }
  }
  std::puts("接收端已停止");
  return 0;
}

void Receiver::accept_control() {
  std::string error;
  auto accepted = control_listener_.accept(&error);
  if (!accepted.has_value()) {
    std::fprintf(stderr, "控制连接 accept 失败：%s\n", error.c_str());
    return;
  }
  add_control(std::move(*accepted), config_.link);
}

void Receiver::accept_control_rfcomm() {
  std::string error;
  auto accepted = bt_listener_.accept(&error);
  if (!accepted.has_value()) {
    std::fprintf(stderr, "蓝牙控制连接 accept 失败：%s\n", error.c_str());
    return;
  }
  std::puts("[蓝牙] 手机已连接 RFCOMM 控制通道");
  add_control(std::move(*accepted), NearbyLink::kBluetooth);
}

void Receiver::start_wifi_stage() {
  if (wifi_stage_started_ || config_.link != NearbyLink::kBluetooth) return;
  wifi_stage_started_ = true;

  std::puts("[无线] 认证成功，正在启动 Windows 移动热点…");
  platform::HotspotConfig config;
  config.ssid = wifi_ssid_;
  config.passphrase = wifi_passphrase_;
  platform::HotspotInfo info;
  std::string error;
  if (!platform::start_hotspot(config, &info, &error)) {
    // 上次进程异常退出可能留下热点；接管前先关掉旧热点再重开，避免“已在运行”死锁。
    if (error.find("已在运行") != std::string::npos) {
      std::string stop_error;
      platform::stop_hotspot(&stop_error);
      std::printf("[无线] 已清理遗留热点，重新启动\n");
    }
    if (!platform::start_hotspot(config, &info, &error)) {
      std::fprintf(stderr, "[无线] 热点启动失败：%s\n", error.c_str());
      wifi_stage_started_ = false;
      return;
    }
  }
  hotspot_ = info;
  hotspot_active_ = true;
  std::printf("[无线] 热点已启动：SSID \"%s\"，密码 \"%s\"，BSSID %s，频率 %u MHz，车机 IP %s\n",
              hotspot_.ssid.c_str(), hotspot_.passphrase.c_str(), hotspot_.bssid.c_str(),
              hotspot_.frequency_mhz, hotspot_.car_ip.c_str());

  auto listener = platform::TcpSocket::listen_on(hotspot_.car_ip, 0, &error);
  if (!listener.has_value()) {
    std::fprintf(stderr, "[无线] Wi-Fi 控制监听失败（%s）：%s\n", hotspot_.car_ip.c_str(), error.c_str());
    platform::stop_hotspot(nullptr);
    hotspot_active_ = false;
    wifi_stage_started_ = false;
    return;
  }
  wifi_control_port_ = listener->local_port();
  wifi_control_listener_ = std::move(*listener);
  std::printf("[无线] Wi-Fi 控制监听已开：%s:%u（通道 3）\n", hotspot_.car_ip.c_str(),
              wifi_control_port_);

  reply_data_channel();
}

void Receiver::reply_data_channel() {
  if (!pending_data_channel_.has_value() || !hotspot_active_ || data_channel_control_ == nullptr) return;
  const DataChannelRequested request = *pending_data_channel_;
  pending_data_channel_.reset();
  uint32_t frequency = hotspot_.frequency_mhz;
  if (frequency == 0) frequency = 2437;
  try {
    const auto actions = data_channel_control_->session->accept_data_channel(request, frequency);
    std::printf("[无线] 已应答数据通道 %u：组主，频率 %u MHz\n", request.data_channel, frequency);
    dispatch(actions, *data_channel_control_);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[无线] 应答数据通道失败：%s\n", e.what());
  }
}

void Receiver::send_wifi_connection_info() {
  if (!awaiting_wifi_mac_ || data_channel_control_ == nullptr || wifi_control_port_ == 0) return;
  awaiting_wifi_mac_ = false;

  WifiConnectionInfo info;
  info.mode = WifiMode::kHotspot;
  info.phone_ip = pick_phone_address(hotspot_.car_ip);
  info.ssid = hotspot_.ssid;
  info.bssid = hotspot_.bssid;
  info.passphrase = hotspot_.passphrase;
  info.frequency_mhz = hotspot_.frequency_mhz == 0 ? 2437 : hotspot_.frequency_mhz;
  info.port = wifi_control_port_;
  info.car_ip = hotspot_.car_ip;
  try {
    const auto actions = data_channel_control_->session->send_wifi_connection_info(info);
    wifi_connection_sent_ = true;
    std::printf("[无线] 已下发连接串：手机 IP %s，端口 %u，信道 %u，车机 IP %s\n", info.phone_ip.c_str(),
                info.port, info.channel().value_or(0), info.car_ip.c_str());
    dispatch(actions, *data_channel_control_);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[无线] 下发连接串失败：%s\n", e.what());
  }
}

void Receiver::accept_wifi_control() {
  std::string error;
  auto accepted = wifi_control_listener_.accept(&error);
  if (!accepted.has_value()) {
    std::fprintf(stderr, "[无线] Wi-Fi 控制连接 accept 失败：%s\n", error.c_str());
    return;
  }
  std::printf("[无线] 手机已连入 Wi-Fi 控制通道：%s\n", accepted->peer_ip().c_str());
  add_control(std::move(*accepted), NearbyLink::kWifi);
}

void Receiver::add_control(platform::TcpSocket socket, NearbyLink link) {
  auto connection = std::make_unique<ControlConnection>();
  connection->socket = std::move(socket);
  connection->socket.set_nonblocking(true, nullptr);
  connection->session = std::make_unique<NearbySession>(config_.host, config_.keys, config_.bluetooth_address,
                                                        link);
  const char* label = link == NearbyLink::kBluetooth ? "蓝牙" : (link == NearbyLink::kWifi ? "Wi-Fi" : "TCP");
  std::printf("[控制通道] 开始握手（%s）\n", label);

  const auto actions = connection->session->start(now_millis());
  dispatch(actions, *connection);
  controls_.push_back(std::move(connection));
}

void Receiver::service_control(ControlConnection& connection) {
  uint8_t buffer[4096];
  std::string error;
  const auto got = connection.socket.recv_some(buffer, sizeof(buffer), &error);
  if (!got.has_value()) {
    if (!error.empty()) {
      std::fprintf(stderr, "控制通道读失败：%s\n", error.c_str());
      connection.socket.close();
    }
    return;  // would-block
  }
  if (*got == 0) {
    std::puts("[控制通道] 对端关闭连接");
    connection.socket.close();
    return;
  }
  const auto actions = connection.session->feed(std::vector<uint8_t>(buffer, buffer + *got));
  dispatch(actions, connection);
}

void Receiver::dispatch(const std::vector<NearbyAction>& actions, ControlConnection& connection) {
  for (const auto& action : actions) {
    if (const auto* send = std::get_if<SendFrame>(&action)) {
      std::string error;
      if (!connection.socket.send_all(send->bytes.data(), send->bytes.size(), &error)) {
        std::fprintf(stderr, "控制通道写失败：%s\n", error.c_str());
        connection.socket.close();
        return;
      }
      continue;
    }
    if (const auto* request = std::get_if<SocketRequested>(&action)) {
      const uint32_t business = request->request.business_id;
      const bool wants_rfcomm =
          config_.link == NearbyLink::kBluetooth && (request->request.protocol & 1) == 0;
      if (wants_rfcomm) {
        std::string error;
        const auto channel = open_rfcomm_listener(business, &error);
        if (channel.has_value()) {
          std::printf("[控制通道] 业务 %u 开 RFCOMM 子通道 %u\n", business, *channel);
          const auto replies = connection.session->accept_rfcomm_socket(*request, *channel);
          for (const auto& reply : replies) {
            if (const auto* send = std::get_if<SendFrame>(&reply)) {
              std::string send_error;
              if (!connection.socket.send_all(send->bytes.data(), send->bytes.size(), &send_error)) {
                std::fprintf(stderr, "控制通道写失败：%s\n", send_error.c_str());
                connection.socket.close();
                return;
              }
            }
          }
        } else {
          std::fprintf(stderr, "业务 %u 开 RFCOMM 子通道失败：%s\n", business, error.c_str());
          const auto replies = connection.session->reject_socket(*request);
          for (const auto& reply : replies) {
            if (const auto* send = std::get_if<SendFrame>(&reply)) {
              connection.socket.send_all(send->bytes.data(), send->bytes.size(), nullptr);
            }
          }
        }
        continue;
      }
      if (business == NearbySession::kBusinessAuth || business == NearbySession::kBusinessDmsdp) {
        std::string error;
        const auto port = open_data_listener(business, &error);
        if (port.has_value()) {
          std::printf("[控制通道] 业务 %u 接受，子监听端口 %u\n", business, *port);
          const auto replies = connection.session->accept_socket(*request, *port);
          for (const auto& reply : replies) {
            if (const auto* send = std::get_if<SendFrame>(&reply)) {
              std::string send_error;
              if (!connection.socket.send_all(send->bytes.data(), send->bytes.size(), &send_error)) {
                std::fprintf(stderr, "控制通道写失败：%s\n", send_error.c_str());
                connection.socket.close();
                return;
              }
            }
          }
        } else {
          std::fprintf(stderr, "业务 %u 开子监听失败：%s\n", business, error.c_str());
          const auto replies = connection.session->reject_socket(*request);
          for (const auto& reply : replies) {
            if (const auto* send = std::get_if<SendFrame>(&reply)) {
              connection.socket.send_all(send->bytes.data(), send->bytes.size(), nullptr);
            }
          }
        }
      } else {
        std::printf("[控制通道] 未知业务 %u，拒绝\n", business);
        const auto replies = connection.session->reject_socket(*request);
        for (const auto& reply : replies) {
          if (const auto* send = std::get_if<SendFrame>(&reply)) {
            connection.socket.send_all(send->bytes.data(), send->bytes.size(), nullptr);
          }
        }
      }
      continue;
    }
    if (const auto* requested = std::get_if<DataChannelRequested>(&action)) {
      std::printf("[无线] 手机请求 WiFi 数据通道 %u（能力：2.4G %s，5G %s）\n", requested->data_channel,
                  requested->capability.supports_2g.value_or(false) ? "是" : "否",
                  requested->capability.supports_5g.value_or(false) ? "是" : "否");
      pending_data_channel_ = *requested;
      data_channel_control_ = &connection;
      if (hotspot_active_) {
        reply_data_channel();
      } else {
        start_wifi_stage();
      }
      continue;
    }
    if (const auto* result = std::get_if<DataChannelResult>(&action)) {
      std::printf("[无线] 数据通道 %u 结果：%u%s\n", result->data_channel, result->result,
                  result->frequency_mhz.has_value()
                      ? ("，频率 " + std::to_string(*result->frequency_mhz) + " MHz").c_str()
                      : "");
      if (result->result == data_channel::kResultOk) {
        const auto requests = connection.session->request_wifi_peer_address();
        awaiting_wifi_mac_ = true;
        dispatch(requests, connection);
      } else {
        std::fprintf(stderr, "[无线] 手机拒绝了数据通道（结果 %u）\n", result->result);
      }
      continue;
    }
    if (const auto* peer = std::get_if<WifiPeerAddress>(&action)) {
      std::printf("[无线] 手机 WiFi MAC：%s\n", peer->mac.c_str());
      send_wifi_connection_info();
      continue;
    }
    if (std::get_if<WifiPeerBusy>(&action) != nullptr) {
      std::fprintf(stderr, "[无线] 手机 WiFi 忙，稍后重试\n");
      continue;
    }
    if (std::get_if<WifiDisconnectRequested>(&action) != nullptr) {
      std::puts("[无线] 手机请求断开 WiFi 组网");
      continue;
    }
    if (std::get_if<HandshakeTimedOut>(&action) != nullptr) {
      log_event(action);
      connection.socket.close();
      return;
    }
    log_event(action);
  }
}

std::optional<uint16_t> Receiver::open_data_listener(uint32_t business_id, std::string* error) {
  for (const auto& slot : data_listeners_) {
    if (slot->business_id == business_id && slot->socket.valid()) return slot->port;
  }
  auto listener = platform::TcpSocket::listen_on(config_.bind_ip, 0, error);
  if (!listener.has_value()) return std::nullopt;
  auto slot = std::make_unique<ListenerSlot>();
  slot->port = listener->local_port();
  slot->business_id = business_id;
  slot->socket = std::move(*listener);
  const uint16_t port = slot->port;
  data_listeners_.push_back(std::move(slot));
  return port;
}

std::optional<uint8_t> Receiver::open_rfcomm_listener(uint32_t business_id, std::string* error) {
  for (const auto& slot : rfcomm_listeners_) {
    if (slot->business_id == business_id && slot->listener.valid()) return slot->listener.channel();
  }
  if (bt_local_address_ == 0) {
    if (error != nullptr) *error = "本机蓝牙地址未知";
    return std::nullopt;
  }
  auto slot = std::make_unique<RfcommSlot>();
  slot->business_id = business_id;
  if (!slot->listener.listen(bt_local_address_, 0, error)) return std::nullopt;
  const uint8_t channel = slot->listener.channel();
  rfcomm_listeners_.push_back(std::move(slot));
  return channel;
}

void Receiver::service_data(DataConnection& connection) {
  uint8_t buffer[8192];
  std::string error;
  const auto got = connection.socket.recv_some(buffer, sizeof(buffer), &error);
  if (!got.has_value()) {
    if (!error.empty()) {
      std::fprintf(stderr, "[业务 %u] 读失败：%s\n", connection.business_id, error.c_str());
      connection.socket.close();
    }
    return;
  }
  if (*got == 0) {
    std::printf("[业务 %u] 对端关闭，累计 %zu 字节\n", connection.business_id, connection.total);
    if (connection.dmsdp != nullptr && !connection.dmsdp_control) {
      (void)connection.dmsdp->close();
    }
    if (connection.auth != nullptr) {
      const auto outputs = connection.auth->on_connection_closed();
      handle_auth_outputs(connection, outputs);
    }
    connection.socket.close();
    return;
  }
  connection.total += *got;
  if (connection.dmsdp != nullptr) {
    service_dmsdp(connection, buffer, *got);
    return;
  }
  if (connection.auth != nullptr) {
    service_auth(connection, buffer, *got);
    return;
  }
  std::printf("[业务 %u] 收到 %zu 字节（累计 %zu）\n", connection.business_id, *got, connection.total);
  std::vector<uint8_t> chunk(buffer, buffer + *got);
  print_hex_dump(chunk, 96);
}

void Receiver::start_auth(DataConnection& connection) {
  auth::AuthSessionConfig session_config;
  session_config.envelope_version = "A_3@20200617200000";
  session_config.usb_connection = config_.link == NearbyLink::kUsb;
  if (config_.link == NearbyLink::kBluetooth && !pin_code_.empty()) {
    session_config.pin = auth::Bytes(pin_code_.begin(), pin_code_.end());
  }
  const std::string full_model =
      to_hex_upper(config_.host.model_id.data(), config_.host.model_id.size()) +
      to_hex_upper(&config_.host.sub_model_id, 1);
  session_config.device_info = {
      {"CONNECT_ABILITY_KEY", session_config.usb_connection ? "2" : "1"},
      {"CAR_MODE_ID", full_model},
      {"CAR_BRAND", config_.host.brand},
  };

  auth::AccessoryAuthConfig auth_config;
  auth_config.service_package = "com.huawei.authagent";
  auth_config.service_type = "SFXTEST";
  auth_config.self_auth_id.assign(device_id_.begin(), device_id_.end());

  connection.auth = std::make_unique<auth::AuthSession>(session_config, auth_config, trust_store_,
                                                        auth_random_);
  std::printf("[业务 19] 认证会话已建立（%s，%s）\n",
              session_config.usb_connection ? "有线" : "无线",
              session_config.pin.has_value() ? "有连接码" : "自动连接码");
}

void Receiver::start_dmsdp(DataConnection& connection) {
  if (!auth_session_key_.has_value() || auth_session_key_->size() != 16) {
    std::fprintf(stderr, "[业务 20] 没有 16 字节会话密钥，先完成认证再连 DMSDP\n");
    connection.socket.close();
    return;
  }
  std::array<uint8_t, 16> key{};
  for (size_t i = 0; i < 16; ++i) key[i] = (*auth_session_key_)[i];

  dmsdp::DmsdpConfig cfg;
  cfg.device_id = device_id_;
  cfg.device_name = config_.host.device_name;
  cfg.bluetooth_mac = config_.bluetooth_address.has_value()
                          ? format_mac(*config_.bluetooth_address)
                          : "00:00:00:00:00:00";
  cfg.local_ip = hotspot_active_ ? hotspot_.car_ip
                                 : (config_.bind_ip == "0.0.0.0" ? "127.0.0.1" : config_.bind_ip);
  cfg.phone_ip = connection.socket.peer_ip();
  if (cfg.phone_ip.empty()) cfg.phone_ip = "127.0.0.1";
  dmsdp::DmsdpDisplay display;
  display.width = 1280;
  display.height = 720;
  display.video_width = 1280;
  display.video_height = 720;
  display.dpi = 160;
  display.fps = 30;
  display.density = 1.0;
  cfg.display = display;
  dmsdp::DmsdpService speaker;
  speaker.service_type = 4;
  speaker.service_id = "speaker1";
  speaker.properties_json =
      R"({"2005":"","2004":"","2003":"","2102":"{\"codecs\":[1],\"currentVolume\":{\"a\":false},\"extendInfo\":{},\"profiles\":[{\"sampleRate\":48000,\"channel\":12,\"format\":1}],\"soundEffect\":0}"})";
  cfg.speaker = speaker;
  cfg.advertise_udp_keep_alive = false;

  connection.dmsdp = std::make_shared<dmsdp::DmsdpSession>(cfg, key, &auth_random_);
  app_dmsdp_ = connection.dmsdp;
  app_list_requested_ = false;
  foreground_registered_ = false;
  app_count_ = 0;
  app_list_retry_at_ms_ = 0;
  app_list_retries_ = 0;
  codec_ability_advertised_ = false;
  codec_blocking_reported_ = false;
  codec_fast_streak_ = 0;
  ensure_app_window();
  if (app_window_) {
    app_window_->set_apps({});
    app_window_->set_status("等待手机返回融合桌面应用列表…");
  }
  std::printf("[业务 20] DMSDP 会话已建立：本机 %s，手机 %s\n", cfg.local_ip.c_str(),
              cfg.phone_ip.c_str());
}

void Receiver::service_dmsdp(DataConnection& connection, const uint8_t* data, size_t size) {
  const auto channel = connection.dmsdp_control ? dmsdp::DmsdpChannel::kControl
                                                : dmsdp::DmsdpChannel::kSession;
  try {
    const auto outputs = connection.dmsdp->feed(channel, data, size, now_millis());
    handle_dmsdp_outputs(connection, outputs);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[DMSDP] 协议错误：%s\n", e.what());
    connection.socket.close();
  }
}

DataConnection* Receiver::find_dmsdp_connection(
    const std::shared_ptr<dmsdp::DmsdpSession>& session, bool control) {
  if (session == nullptr) return nullptr;
  for (auto& candidate : data_connections_) {
    if (candidate->dmsdp == session && candidate->dmsdp_control == control &&
        candidate->socket.valid()) {
      return candidate.get();
    }
  }
  return nullptr;
}

void Receiver::handle_dmsdp_outputs(DataConnection& connection,
                                    const std::vector<dmsdp::DmsdpOutput>& outputs) {
  for (const auto& output : outputs) {
    if (const auto* action = std::get_if<dmsdp::DmsdpAction>(&output)) {
      switch (action->kind) {
        case dmsdp::DmsdpAction::Kind::kSend: {
          const bool to_control = action->channel == dmsdp::DmsdpChannel::kControl;
          // 定时保活和协议应答可能由 session 连接产生，但必须写到同一会话的
          // control 连接；不能按“当前 connection 的类型”直接丢弃。
          DataConnection* target = nullptr;
          if (connection.dmsdp_control == to_control && connection.socket.valid()) {
            // 当前连接优先，避免会话建立过程中 control 连接还没进 data_connections_。
            target = &connection;
          }
          if (target == nullptr) {
            target = find_dmsdp_connection(connection.dmsdp, to_control);
          }
          if (target == nullptr) {
            std::fprintf(stderr, "[DMSDP] 目标 %s 连接不存在，丢弃 %zu 字节\n",
                         to_control ? "control" : "session", action->bytes.size());
            continue;
          }
          std::string error;
          if (!target->socket.send_all(action->bytes.data(), action->bytes.size(), &error)) {
            std::fprintf(stderr, "[DMSDP] 写 %s 失败：%s\n", to_control ? "control" : "session",
                         error.c_str());
            target->socket.close();
            return;
          }
          break;
        }
        case dmsdp::DmsdpAction::Kind::kOpenControlListener: {
          if (connection.dmsdp_control) continue;
          std::string error;
          const auto port = open_dmsdp_control_listener(connection.dmsdp, &error);
          if (!port.has_value()) {
            std::fprintf(stderr, "[DMSDP] 开控制监听失败：%s\n", error.c_str());
            connection.socket.close();
            return;
          }
          std::printf("[DMSDP] 控制监听端口 %u\n", *port);
          const auto replies =
              connection.dmsdp->control_listener_ready(*port, now_millis());
          handle_dmsdp_outputs(connection, replies);
          break;
        }
        case dmsdp::DmsdpAction::Kind::kOpenKeepAliveSocket:
          std::printf("[DMSDP] 手机选择 UDP 保活端口 %u（暂未实现）\n", action->port);
          break;
        case dmsdp::DmsdpAction::Kind::kSendDatagram:
          break;
        case dmsdp::DmsdpAction::Kind::kOpenAudioListener: {
          // 音频触发是在加密控制连接上收到的，因此不能要求当前连接是 session。
          std::string error;
          const auto port = open_audio_listener(&error);
          if (!port.has_value()) {
            std::fprintf(stderr, "[DMSDP] 开音频监听失败：%s\n", error.c_str());
            continue;
          }
          std::printf("[DMSDP] 扬声器监听端口 %u\n", *port);
          const auto replies = connection.dmsdp->audio_listener_ready(*port, now_millis());
          handle_dmsdp_outputs(connection, replies);
          break;
        }
        case dmsdp::DmsdpAction::Kind::kCloseAudioTransport:
          std::puts("[DMSDP] 手机拆除音频数据会话");
          close_audio_connections();
          break;
      }
      continue;
    }
    const auto* event = std::get_if<dmsdp::DmsdpEvent>(&output);
    if (event == nullptr) continue;
    switch (event->kind) {
      case dmsdp::DmsdpEvent::Kind::kEncryptionEnabled:
        std::printf("[DMSDP] 控制连接已加密（%s）\n", event->flag ? "UDP 保活" : "TCP 保活");
        break;
      case dmsdp::DmsdpEvent::Kind::kPeerDeviceInfo:
        std::printf("[DMSDP] 手机设备信息：deviceId=%s，deviceType=%d\n", event->text.c_str(),
                    event->signed_number);
        break;
      case dmsdp::DmsdpEvent::Kind::kPeerServiceInfo:
        std::printf("[DMSDP] 手机服务：type=%u，id=%s\n", event->number, event->text.c_str());
        break;
      case dmsdp::DmsdpEvent::Kind::kServiceStatusChanged:
        std::printf("[DMSDP] 服务状态：动作 %d，id=%s\n", event->signed_number, event->text.c_str());
        break;
      case dmsdp::DmsdpEvent::Kind::kServicesRequested:
        std::printf("[DMSDP] 手机请求服务，掩码 0x%X，已应答 %u 条\n", event->number, event->number2);
        if ((event->number & 8u) != 0) request_app_list(false);
        break;
      case dmsdp::DmsdpEvent::Kind::kDisplayPortAnnounced:
        std::printf("[DMSDP] 手机 HiSight 端口：%u\n", event->number);
        start_hisight(connection.socket.peer_ip(), event->number);
        break;
      case dmsdp::DmsdpEvent::Kind::kTimeSyncRequested:
        std::printf("[DMSDP] 时间同步：server=%s，phoneUs=%s\n", event->text.c_str(),
                    event->text2.c_str());
        break;
      case dmsdp::DmsdpEvent::Kind::kKeepAliveTimeout:
        std::fprintf(stderr, "[DMSDP] 保活超时\n");
        break;
      case dmsdp::DmsdpEvent::Kind::kUnhandledControlMessage:
        std::printf("[DMSDP] 未处理控制消息：%s\n", event->text.c_str());
        break;
      case dmsdp::DmsdpEvent::Kind::kUnhandledDeviceData:
        std::printf("[DMSDP] 未处理设备消息：module=%u，type=%d\n", event->number,
                    event->signed_number);
        break;
      case dmsdp::DmsdpEvent::Kind::kUnsupportedDeviceCommand:
        std::printf("[DMSDP] 未支持设备命令：module=%u，命令=%u\n", event->number, event->number2);
        break;
      case dmsdp::DmsdpEvent::Kind::kAudioSessionEstablished:
        std::printf("[DMSDP] 音频数据会话已建立：id=%s，端口 %u\n", event->text.c_str(),
                    event->number);
        break;
      case dmsdp::DmsdpEvent::Kind::kAudioSessionTornDown:
        std::puts("[DMSDP] 音频数据会话已结束");
        break;
      case dmsdp::DmsdpEvent::Kind::kCarData:
        handle_car_data(event->number, event->data);
        break;
    }
  }
}

std::optional<uint16_t> Receiver::open_dmsdp_control_listener(
    const std::shared_ptr<dmsdp::DmsdpSession>& session, std::string* error) {
  auto listener = platform::TcpSocket::listen_on(config_.bind_ip, 0, error);
  if (!listener.has_value()) return std::nullopt;
  auto slot = std::make_unique<ListenerSlot>();
  slot->socket = std::move(*listener);
  slot->port = slot->socket.local_port();
  slot->business_id = 0xFFFFFFFEu;
  slot->dmsdp = session;
  const uint16_t port = slot->port;
  data_listeners_.push_back(std::move(slot));
  return port;
}

std::optional<uint16_t> Receiver::open_audio_listener(std::string* error) {
  const std::string bind_ip = hotspot_active_ ? hotspot_.car_ip : "0.0.0.0";
  auto listener = platform::TcpSocket::listen_on(bind_ip, 0, error);
  if (!listener.has_value()) return std::nullopt;
  auto slot = std::make_unique<ListenerSlot>();
  slot->socket = std::move(*listener);
  slot->port = slot->socket.local_port();
  slot->business_id = 0xFFFFFFFDu;
  slot->audio = true;
  slot->dmsdp = nullptr;  // 音频数据连接不需要额外发 DMSDP 消息
  const uint16_t port = slot->port;
  data_listeners_.push_back(std::move(slot));
  return port;
}

void Receiver::service_audio(AudioConnection& connection) {
  uint8_t buffer[65536];
  std::string error;
  const auto got = connection.socket.recv_some(buffer, sizeof(buffer), &error);
  if (!got.has_value()) {
    if (!error.empty()) {
      std::fprintf(stderr, "[DMSDP] 音频连接读失败：%s\n", error.c_str());
      connection.socket.close();
    }
    return;
  }
  if (*got == 0) {
    std::printf("[DMSDP] 音频连接关闭，累计 %zu 字节\n", connection.total);
    connection.socket.close();
    return;
  }
  connection.total += *got;
  if (connection.decoder == nullptr) return;
  std::vector<dmsdp::AudioChunk> chunks;
  try {
    connection.decoder->feed(buffer, *got, &chunks);
  } catch (...) {
    return;
  }
  if (chunks.empty()) return;
  static bool logged = false;
  if (!logged) {
    std::printf("[DMSDP] 音频分帧：%s，首包 PT=%u，SSRC=0x%08X%s\n",
                connection.decoder->framing_name(), chunks.front().payload_type,
                chunks.front().ssrc, chunks.front().aac ? "（AAC）" : "（PCM）");
    logged = true;
  }
  if (audio_player_) {
    for (const auto& chunk : chunks) {
      if (!chunk.aac) audio_player_->write(chunk.data.data(), chunk.data.size());
    }
  }
}

void Receiver::close_audio_connections() {
  for (auto& connection : audio_connections_) connection->socket.close();
  audio_connections_.clear();
}

void Receiver::ensure_app_window() {
  if (app_window_) return;
  app_window_ = std::make_unique<platform::AppWindow>();
  std::string error;
  if (!app_window_->create(&error)) {
    std::fprintf(stderr, "[应用中心] 创建窗口失败：%s\n", error.c_str());
    app_window_.reset();
    return;
  }
  app_window_->set_status("等待手机返回融合桌面应用列表…");
  app_window_->set_start_sink([this](const std::string& package_name) {
    if (package_name == "__refresh__") {
      app_list_retries_ = 0;
      request_app_list(true);
    } else {
      start_car_app(package_name);
    }
  });
}

bool Receiver::send_app_data(int32_t data_type, const std::string& json, const char* what) {
  if (!app_dmsdp_) {
    std::fprintf(stderr, "[应用中心] %s：DMSDP 会话未建立\n", what);
    return false;
  }
  DataConnection* control = find_dmsdp_connection(app_dmsdp_, true);
  if (control == nullptr) {
    std::fprintf(stderr, "[应用中心] %s：控制连接未建立\n", what);
    return false;
  }
  try {
    const auto outputs = app_dmsdp_->send_device_data(
        1, data_type, std::vector<uint8_t>(json.begin(), json.end()));
    handle_dmsdp_outputs(*control, outputs);
    return true;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[应用中心] %s 失败：%s\n", what, e.what());
    return false;
  }
}

void Receiver::request_app_list(bool force) {
  if (!app_dmsdp_) return;
  if (!force && app_list_requested_) return;
  if (!force) app_list_retries_ = 0;
  const std::string model = to_hex_upper(config_.host.model_id.data(), config_.host.model_id.size()) +
                            to_hex_upper(&config_.host.sub_model_id, 1);
  const std::string json = "{\"RequestData\":\"all\",\"RequestCaller\":\"" + model + "\"}";
  if (!send_app_data(528, json, "请求应用列表")) {
    if (app_window_) app_window_->set_status("应用列表请求失败");
    return;
  }
  app_list_requested_ = true;
  app_list_retry_at_ms_ = now_millis() + 3000;
  if (!foreground_registered_) {
    if (send_app_data(537, "{\"action\":\"registerForegroundAppChange\"}", "订阅前台应用")) {
      foreground_registered_ = true;
      std::puts("[应用中心] 已发送 dataType 537（订阅前台应用）");
    }
  }
  if (app_window_) app_window_->set_status("已请求应用列表，等待手机返回…");
  std::puts("[应用中心] 已发送 dataType 528（融合桌面应用列表）");
}

void Receiver::start_car_app(const std::string& package_name) {
  const std::string json =
      "{\"RequestApp\":{\"Action\":\"start\",\"AppPackage\":\"" + package_name + "\"}}";
  if (send_app_data(529, json, "启动应用")) {
    if (app_window_) app_window_->set_status("已请求手机启动 " + package_name + "，等待应答…");
    std::printf("[应用中心] 已发送 dataType 529：启动 %s\n", package_name.c_str());
  }
}

void Receiver::handle_car_data(uint32_t data_type, const std::vector<uint8_t>& data) {
  const std::string text(data.begin(), data.end());
  if (data_type == 528) {
    const auto parsed = auth::parse_json(text);
    if (!parsed.has_value()) {
      std::fprintf(stderr, "[应用中心] 应用列表不是 JSON：%s\n", text.c_str());
      return;
    }
    std::vector<platform::CarApp> apps;
    std::vector<std::string> seen;
    std::function<void(const auth::JsonValue&, int)> walk = [&](const auth::JsonValue& value, int depth) {
      if (depth > 8 || apps.size() >= 60) return;
      if (value.is_object()) {
        const auto* package = value.find("packageName");
        if (package == nullptr) package = value.find("pkgName");
        if (package == nullptr) package = value.find("package_name");
        if (package == nullptr) package = value.find("mPackageName");
        if (package != nullptr && package->is_string() && !package->text.empty()) {
          if (std::find(seen.begin(), seen.end(), package->text) == seen.end()) {
            seen.push_back(package->text);
            platform::CarApp app;
            app.package_name = package->text;
            const auto* name = value.find("appName");
            if (name == nullptr) name = value.find("name");
            if (name == nullptr) name = value.find("mName");
            if (name != nullptr && name->is_string()) app.name = name->text;
            apps.push_back(std::move(app));
          }
        }
        for (const auto& member : value.object) walk(member.second, depth + 1);
      } else if (value.type == auth::JsonValue::Type::Array) {
        for (const auto& entry : value.array) walk(entry, depth + 1);
      }
    };
    walk(*parsed, 0);
    app_count_ = apps.size();
    if (app_count_ != 0) {
      app_list_requested_ = false;
      app_list_retries_ = 0;
    }
    app_list_retry_at_ms_ = app_count_ == 0 ? now_millis() + 3000
                                           : 0;
    if (app_window_) {
      app_window_->set_apps(apps);
      app_window_->set_status("已获取 " + std::to_string(apps.size()) + " 个融合桌面应用");
    }
    std::printf("[应用中心] 应用列表：%zu 个\n", apps.size());
    for (const auto& app : apps) {
      std::printf("  - %s (%s)\n", app.name.c_str(), app.package_name.c_str());
    }
    return;
  }
  if (data_type == 529) {
    const auto parsed = auth::parse_json(text);
    int code = -1;
    std::string description;
    std::string package;
    if (parsed.has_value() && parsed->is_object()) {
      std::function<void(const auth::JsonValue&, int)> walk = [&](const auth::JsonValue& value, int depth) {
        if (depth > 6) return;
        if (value.is_object()) {
          const auto* resp = value.find("RespCode");
          if (resp != nullptr && resp->is_number()) {
            const auto number = resp->as_int();
            if (number.has_value()) code = static_cast<int>(*number);
          }
          const auto* desc = value.find("Description");
          if (desc != nullptr && desc->is_string()) description = desc->text;
          const auto* app = value.find("AppPackage");
          if (app != nullptr && app->is_string()) package = app->text;
          for (const auto& member : value.object) walk(member.second, depth + 1);
        } else if (value.type == auth::JsonValue::Type::Array) {
          for (const auto& entry : value.array) walk(entry, depth + 1);
        }
      };
      walk(*parsed, 0);
    }
    std::string message;
    if (code == 100000) {
      message = "启动成功（100000）";
    } else if (code == 100002) {
      message = "应用不存在或未安装（100002）" + (package.empty() ? "" : "：" + package);
    } else if (code == 100001) {
      message = "手机拒绝启动（100001）" + (description.empty() ? "" : "：" + description);
    } else {
      message = "启动应答 code=" + std::to_string(code) +
                (description.empty() ? "" : "，" + description);
    }
    std::printf("[应用中心] %s\n", message.c_str());
    if (app_window_) app_window_->set_status(message);
    return;
  }
  if (data_type == 532) {
    // 融合桌面 HiCar 前后台切换/投屏授权。只记录，不把它当成投屏开关；
    // 投屏仍由 DMSDP 显示端口通告驱动。若应用列表还没回来，稍后再请求一次。
    std::printf("[应用中心] 融合桌面投屏授权：%s\n", text.c_str());
    if (app_count_ == 0 && app_list_requested_ && app_list_retries_ < 2) {
      app_list_retry_at_ms_ = now_millis() + 1000;
    }
    return;
  }
  if (data_type == 535) {
    const auto parsed = auth::parse_json(text);
    bool support = false;
    bool blocking = false;
    if (parsed.has_value() && parsed->is_object()) {
      std::function<void(const auth::JsonValue&, int)> walk = [&](const auth::JsonValue& value, int depth) {
        if (depth > 4) return;
        if (value.is_object()) {
          const auto* is_support = value.find("isSupport");
          if (is_support != nullptr && is_support->is_bool()) support = is_support->boolean;
          else if (is_support != nullptr && is_support->is_number()) {
            const auto n = is_support->as_int();
            if (n.has_value()) support = *n != 0;
          }
          const auto* is_blocking = value.find("isBlocking");
          if (is_blocking != nullptr && is_blocking->is_bool()) blocking = is_blocking->boolean;
          else if (is_blocking != nullptr && is_blocking->is_number()) {
            const auto n = is_blocking->as_int();
            if (n.has_value()) blocking = *n != 0;
          }
          for (const auto& member : value.object) walk(member.second, depth + 1);
        }
      };
      walk(*parsed, 0);
    }
    codec_ability_advertised_ = support;
    std::printf("[应用中心] 视频解码能力：手机支持动态帧数=%s，当前阻塞=%s\n",
                support ? "是" : "否", blocking ? "是" : "否");
    return;
  }
  if (data_type == 533 || data_type == 537) {
    const auto parsed = auth::parse_json(text);
    std::string package;
    int app_type = 0;
    if (parsed.has_value()) {
      std::function<void(const auth::JsonValue&, int)> walk = [&](const auth::JsonValue& value, int depth) {
        if (depth > 6 || !package.empty()) return;
        if (value.is_object()) {
          const auto* name = value.find("packageName");
          if (name != nullptr && name->is_string()) {
            package = name->text;
            const auto* type = value.find("appType");
            if (type != nullptr && type->is_number()) {
              const auto number = type->as_int();
              if (number.has_value()) app_type = static_cast<int>(*number);
            }
          }
          for (const auto& member : value.object) walk(member.second, depth + 1);
        } else if (value.type == auth::JsonValue::Type::Array) {
          for (const auto& entry : value.array) walk(entry, depth + 1);
        }
      };
      walk(*parsed, 0);
    }
    const char* kind = data_type == 533 ? "前台娱乐应用" : "前台应用";
    if (package.empty()) {
      if (app_window_) app_window_->set_status(std::string(kind) + "：无（HiCar 桌面）");
      std::printf("[应用中心] %s：无\n", kind);
      return;
    }
    std::string label = package;
    if (package == "com.huawei.himovie") label = "华为视频";
    else if (package == "com.android.mediacenter") label = "华为音乐";
    if (app_window_) {
      app_window_->set_status(std::string(kind) + "：" + label + "（类型 " + std::to_string(app_type) + "）");
    }
    std::printf("[应用中心] %s：%s（type %d）\n", kind, label.c_str(), app_type);
    return;
  }
  std::printf("[应用中心] 收到 dataType %u：%s\n", data_type, text.c_str());
}

void Receiver::service_auth(DataConnection& connection, const uint8_t* data, size_t size) {
  const std::string_view chunk(reinterpret_cast<const char*>(data), size);
  const auto outputs = connection.auth->feed(chunk);
  handle_auth_outputs(connection, outputs);
}



void Receiver::handle_auth_outputs(DataConnection& connection,
                                   const std::vector<auth::AuthOutput>& outputs) {
  for (const auto& output : outputs) {
    switch (output.kind) {
      case auth::AuthOutput::Kind::Send: {
        std::string error;
        if (!connection.socket.send_all(output.bytes.data(), output.bytes.size(), &error)) {
          std::fprintf(stderr, "[业务 19] 写失败：%s\n", error.c_str());
          connection.socket.close();
          return;
        }
        break;
      }
      case auth::AuthOutput::Kind::Note:
        if (!output.note.empty()) std::printf("[业务 19] %s\n", output.note.c_str());
        break;
      case auth::AuthOutput::Kind::Succeeded:
        auth_session_key_ = output.session_key;
        ble_advertiser_.stop();
        if (qr_window_ != nullptr) qr_window_->close();
        std::printf("[业务 19] 认证成功：%s，会话密钥 %zu 字节已保存\n",
                    output.note.c_str(), output.session_key.size());
        if (config_.link == NearbyLink::kBluetooth && !wifi_stage_started_) {
          start_wifi_stage();
        }
        break;
      case auth::AuthOutput::Kind::Failed:
        if (output.error == -1) {
          std::fprintf(stderr, "[业务 19] 手机要求免码回连，但本机没有它的配对记录\n");
        } else if (output.error == -2) {
          std::fprintf(stderr, "[业务 19] 手机声明的连接方式与本会话不一致\n");
        } else if (output.error == -3) {
          std::fprintf(stderr, "[业务 19] 认证未完成，连接已断开\n");
        } else {
          std::fprintf(stderr, "[业务 19] 认证失败，认证库错误码 %d\n", output.error);
        }
        break;
    }
  }
}

void Receiver::start_hisight(const std::string& phone_ip, uint32_t port) {
  if (!auth_session_key_.has_value() || auth_session_key_->size() != 16 || port == 0) {
    std::fprintf(stderr, "[HiSight] 缺少会话密钥或端口，无法连接\n");
    return;
  }
  for (const auto& existing : hisight_) {
    if (!existing->closing && existing->phone_ip == phone_ip && existing->port == port) return;
  }

  std::string error;
  auto control = platform::TcpSocket::connect_to(phone_ip, static_cast<uint16_t>(port), &error);
  if (!control.has_value()) {
    std::fprintf(stderr, "[HiSight] 连接控制端口 %s:%u 失败：%s\n", phone_ip.c_str(), port, error.c_str());
    return;
  }
  control->set_nonblocking(true, nullptr);
  std::printf("[HiSight] 控制连接已建立 %s:%u\n", phone_ip.c_str(), port);

  auto connection = std::make_unique<HisightConnection>();
  connection->phone_ip = phone_ip;
  connection->port = port;
  connection->control = std::move(*control);
  HisightConnection* raw = connection.get();

  hisight::HisightConfig config;
  config.screen_width = 1280;
  config.screen_height = 720;
  config.video_width = 1280;
  config.video_height = 720;
  config.fps = 30;
  config.dpi = 160;
  config.touch_input = true;
  config.key_input = true;
  config.media_key_input = true;

  connection->receiver = std::make_unique<hisight::HisightReceiver>(
      std::array<uint8_t, 16>{auth_session_key_->at(0), auth_session_key_->at(1), auth_session_key_->at(2),
                              auth_session_key_->at(3), auth_session_key_->at(4), auth_session_key_->at(5),
                              auth_session_key_->at(6), auth_session_key_->at(7), auth_session_key_->at(8),
                              auth_session_key_->at(9), auth_session_key_->at(10), auth_session_key_->at(11),
                              auth_session_key_->at(12), auth_session_key_->at(13), auth_session_key_->at(14),
                              auth_session_key_->at(15)},
      config, [this, raw](const hisight::AccessUnit& unit) {
        if (!raw->decoder) return;
        raw->decoder->decode(unit.data, unit.size, unit.pts_90k);
        const uint64_t decode_us = raw->decoder->last_decode_micros();
        if (decode_us == 0 || !codec_ability_advertised_) return;
        // 30fps 的单帧预算是 33ms；超过预算就请求手机降帧，恢复后再请求升帧。
        if (decode_us > 35000 && !codec_blocking_reported_) {
          codec_blocking_reported_ = true;
          codec_fast_streak_ = 0;
          send_app_data(535, "{\"isBlocking\":true}", "上报视频解码阻塞");
        } else if (codec_blocking_reported_ && decode_us < 15000) {
          if (++codec_fast_streak_ >= 30) {
            codec_blocking_reported_ = false;
            codec_fast_streak_ = 0;
            send_app_data(535, "{\"isBlocking\":false}", "上报视频解码恢复");
          }
        } else if (!codec_blocking_reported_) {
          codec_fast_streak_ = 0;
        }
      });

  hisight_.push_back(std::move(connection));
  const auto actions = raw->receiver->start(now_millis());
  process_hisight_actions(*raw, actions);
}

void Receiver::process_hisight_actions(HisightConnection& connection,
                                       const std::vector<hisight::HsAction>& actions) {
  for (const auto& action : actions) {
    switch (action.kind) {
      case hisight::HsAction::Kind::kSend: {
        platform::TcpSocket* socket = nullptr;
        if (action.channel == hisight::HsChannel::kControl) socket = &connection.control;
        else if (action.channel == hisight::HsChannel::kVideo) socket = &connection.video;
        else socket = &connection.remote;
        if (socket == nullptr || !socket->valid()) {
          std::fprintf(stderr, "[HiSight] 发送时通道 %d 未建立，丢弃\n", static_cast<int>(action.channel));
          continue;
        }
        std::string error;
        if (!socket->send_all(action.bytes.data(), action.bytes.size(), &error)) {
          std::fprintf(stderr, "[HiSight] 通道 %d 写失败：%s\n", static_cast<int>(action.channel), error.c_str());
          close_hisight(connection, false);
        }
        break;
      }
      case hisight::HsAction::Kind::kConnect: {
        std::string error;
        auto socket = platform::TcpSocket::connect_to(connection.phone_ip, static_cast<uint16_t>(action.port),
                                                       &error);
        if (!socket.has_value()) {
          std::fprintf(stderr, "[HiSight] 连接 %s:%d 失败：%s\n", connection.phone_ip.c_str(), action.port,
                       error.c_str());
          close_hisight(connection, true);
          break;
        }
        socket->set_nonblocking(true, nullptr);
        std::printf("[HiSight] %s连接已建立：%s:%d\n",
                    action.channel == hisight::HsChannel::kVideo ? "视频" : "回控",
                    connection.phone_ip.c_str(), action.port);
        if (action.channel == hisight::HsChannel::kVideo) {
          connection.video = std::move(*socket);
          const auto replies = connection.receiver->on_video_connected();
          process_hisight_actions(connection, replies);
        } else if (action.channel == hisight::HsChannel::kRemoteControl) {
          connection.remote = std::move(*socket);
          const auto replies = connection.receiver->on_remote_control_connected();
          process_hisight_actions(connection, replies);
        }
        break;
      }
      case hisight::HsAction::Kind::kStreamNegotiated: {
        connection.decoder = std::make_unique<platform::MfH264Decoder>(
            [&connection](const uint8_t* bgra, int width, int height) {
              ++connection.video_frames;
              if (connection.video_frames == 1 || connection.video_frames % 30 == 0) {
                std::printf("[HiSight] 解码帧 %llu（%dx%d）\n",
                            static_cast<unsigned long long>(connection.video_frames), width, height);
              }
              if (connection.window) connection.window->set_frame(bgra, width, height);
            });
        std::string decode_error;
        if (!connection.decoder->open(action.width, action.height, action.fps, &decode_error)) {
          std::fprintf(stderr, "[HiSight] 打开 H.264 解码器失败：%s\n", decode_error.c_str());
          connection.decoder.reset();
        }
        connection.window = std::make_unique<platform::FrameWindow>();
        std::string window_error;
        if (!connection.window->create(action.width, action.height,
                                       "HiCar 投屏 - 华为视频 / 华为音乐", &window_error)) {
          std::fprintf(stderr, "[HiSight] 创建投屏窗口失败：%s\n", window_error.c_str());
          connection.window.reset();
        }
        if (connection.window) {
          connection.window->set_sinks(
              [this, &connection](int touch_action, int id, int x, int y) {
                if (!connection.receiver || !connection.window) return;
                hisight::TouchAction action = touch_action == 0 ? hisight::TouchAction::kDown
                                                : touch_action == 1 ? hisight::TouchAction::kUp
                                                                   : hisight::TouchAction::kMove;
                const auto replies = connection.receiver->send_touch(
                    action, {{id, x, y}}, connection.window->video_width(), connection.window->video_height());
                process_hisight_actions(connection, replies);
              },
              [this, &connection](bool down, int code) {
                if (!connection.receiver) return;
                process_hisight_actions(connection, connection.receiver->send_key(down, code, 0));
              },
              [this, &connection]() { close_hisight(connection, true); });
        }
        std::printf("[HiSight] 协商完成：%dx%d @%dfps，触摸 %s，按键 %s\n", action.width, action.height,
                    action.fps, action.touch_input ? "可用" : "不可用", action.key_input ? "可用" : "不可用");
        break;
      }
      case hisight::HsAction::Kind::kPlayAccepted:
        std::puts("[HiSight] 手机已接受 PLAY，开始推流");
        break;
      case hisight::HsAction::Kind::kCloseAll:
        connection.control.close();
        connection.video.close();
        connection.remote.close();
        if (connection.window) connection.window->close();
        connection.closing = true;
        break;
      case hisight::HsAction::Kind::kEnded:
        std::printf("[HiSight] 投屏结束（原因 %d）\n", static_cast<int>(action.reason));
        break;
    }
  }
}

void Receiver::service_hisight(HisightConnection& connection) {
  if (connection.closing) return;
  if (connection.control.valid()) {
    uint8_t buffer[4096];
    std::string error;
    const auto got = connection.control.recv_some(buffer, sizeof(buffer), &error);
    if (got.has_value()) {
      if (*got == 0) {
        const auto actions = connection.receiver->on_control_closed();
        process_hisight_actions(connection, actions);
      } else {
        try {
          const auto actions = connection.receiver->feed_control(buffer, *got, now_millis());
          process_hisight_actions(connection, actions);
        } catch (const std::exception& e) {
          std::fprintf(stderr, "[HiSight] 控制消息错误：%s\n", e.what());
          close_hisight(connection, true);
        }
      }
    } else if (!error.empty()) {
      std::fprintf(stderr, "[HiSight] 控制连接读失败：%s\n", error.c_str());
      close_hisight(connection, false);
    }
  }
  if (!connection.closing && connection.video.valid()) {
    uint8_t buffer[65536];
    std::string error;
    const auto got = connection.video.recv_some(buffer, sizeof(buffer), &error);
    if (got.has_value()) {
      if (*got == 0) {
        try {
          const auto actions = connection.receiver->on_video_closed();
          process_hisight_actions(connection, actions);
        } catch (const std::exception& e) {
          std::fprintf(stderr, "[HiSight] 视频收尾失败：%s\n", e.what());
          close_hisight(connection, false);
        }
      } else {
        connection.video_total += *got;
        if (connection.video_total <= static_cast<size_t>(*got) ||
            connection.video_total / (1024 * 1024) != (connection.video_total - *got) / (1024 * 1024)) {
          std::printf("[HiSight] 视频已收 %zu 字节，解码帧 %llu\n", connection.video_total,
                      static_cast<unsigned long long>(connection.video_frames));
        }
        try {
          connection.receiver->feed_video(buffer, *got);
        } catch (const std::exception& e) {
          std::fprintf(stderr, "[HiSight] 视频流错误：%s\n", e.what());
          close_hisight(connection, false);
        }
      }
    } else if (!error.empty()) {
      close_hisight(connection, false);
    }
  }
  if (!connection.closing && connection.remote.valid()) {
    uint8_t buffer[256];
    std::string error;
    const auto got = connection.remote.recv_some(buffer, sizeof(buffer), &error);
    if (got.has_value() && *got > 0) {
      std::fprintf(stderr, "[HiSight] 回控连接收到未定义数据，关闭\n");
      close_hisight(connection, false);
    } else if (!got.has_value() && !error.empty()) {
      close_hisight(connection, false);
    }
  }
}

void Receiver::close_hisight(HisightConnection& connection, bool send_teardown) {
  if (connection.closing) return;
  if (send_teardown && connection.receiver) {
    const auto actions = connection.receiver->shutdown();
    process_hisight_actions(connection, actions);
  }
  connection.control.close();
  connection.video.close();
  connection.remote.close();
  if (connection.window) connection.window->close();
  connection.closing = true;
}

void Receiver::tick() {
  const uint64_t now = now_millis();
  for (auto& connection : controls_) {
    if (!connection->socket.valid()) continue;
    const auto actions = connection->session->on_tick(now);
    dispatch(actions, *connection);
  }
  for (auto& connection : data_connections_) {
    if (connection->dmsdp == nullptr || connection->dmsdp_control || !connection->socket.valid()) {
      continue;
    }
    try {
      const auto outputs = connection->dmsdp->on_tick(now);
      handle_dmsdp_outputs(*connection, outputs);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "[DMSDP] 定时任务失败：%s\n", e.what());
    }
  }
  if (audio_player_) audio_player_->pump();
  if (app_dmsdp_ && app_list_requested_ && app_count_ == 0 && app_list_retry_at_ms_ != 0 &&
      now >= app_list_retry_at_ms_ && app_list_retries_ < 2) {
    ++app_list_retries_;
    std::printf("[应用中心] 应用列表未返回，重试 %d/2\n", app_list_retries_);
    request_app_list(true);
    if (app_list_retries_ >= 2) {
      app_list_retry_at_ms_ = 0;
      if (app_window_) app_window_->set_status("手机未返回融合桌面应用列表（可能不支持 528）");
    }
  }
  if (app_window_) {
    app_window_->pump();
    if (app_window_->closed()) app_window_.reset();
  }
  for (auto& connection : hisight_) {
    if (connection->closing) continue;
    if (connection->window) connection->window->pump();
    service_hisight(*connection);
  }
  hisight_.erase(std::remove_if(hisight_.begin(), hisight_.end(),
                                [](const std::unique_ptr<HisightConnection>& connection) {
                                  return connection->closing;
                                }),
                 hisight_.end());

  // 连接码 2 分钟过期后刷新二维码；但只要有控制/数据连接正在握手，就不能换 PIN，
  // 否则手机手里还是旧码，PAKE 必然失败。等连接结束后下一轮再刷新。
  bool busy = false;
  for (const auto& connection : controls_) {
    if (connection->socket.valid()) busy = true;
  }
  for (const auto& connection : data_connections_) {
    if (connection->socket.valid()) busy = true;
  }
  if (!busy && !auth_session_key_.has_value() && qr_window_ != nullptr &&
      qr_window_->visible() && now >= pairing_pin_expires_ms_) {
    refresh_pairing_code();
  }
}

uint64_t Receiver::now_millis() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
}

}  // namespace hicar
