#include "dmsdp/session.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#include "auth/json.h"
#include "common/byte_buffer.h"
#include "common/ea.h"
#include "common/error.h"
#include "dmsdp/cipher.h"

namespace hicar {
namespace dmsdp {
namespace {

constexpr const char* kVersion = "DMSDP/1.0";
constexpr const char* kOk = "DMSDP/1.0 200 OK";
constexpr uint32_t kModuleDevice = 3;
constexpr uint32_t kModuleDisplay = 5;
constexpr int32_t kTypeDeviceData = -1;
constexpr uint32_t kCmdDeviceInfo = 101;
constexpr uint32_t kCmdServiceInfo = 102;
constexpr uint32_t kCmdServiceStatus = 103;
constexpr uint32_t kCmdServiceRequest = 104;
constexpr uint32_t kCmdDisconnectType = 105;
constexpr uint32_t kCmdDisplayPort = 101;

uint32_t read_u32be(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

int32_t read_i32be(const uint8_t* data) { return static_cast<int32_t>(read_u32be(data)); }

std::vector<uint8_t> bytes_of(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::string json_of(const std::vector<uint8_t>& data) {
  return std::string(data.begin(), data.end());
}

auth::JsonValue parse_object(const std::vector<uint8_t>& body, const char* what) {
  const auto parsed = auth::parse_json(json_of(body));
  if (!parsed.has_value() || !parsed->is_object()) {
    throw MalformedMessage(std::string(what) + " 不是 JSON 对象");
  }
  return *parsed;
}

std::string require_string(const auth::JsonValue& object, const char* field) {
  const auto* value = object.find(field);
  if (value == nullptr || !value->is_string() || value->text.empty()) {
    throw MalformedMessage(std::string("JSON 缺少有效的 ") + field);
  }
  return value->text;
}

int64_t require_int(const auth::JsonValue& object, const char* field) {
  const auto* value = object.find(field);
  if (value == nullptr || !value->is_number()) {
    throw MalformedMessage(std::string("JSON 缺少整数 ") + field);
  }
  const auto parsed = value->as_int();
  if (!parsed.has_value()) throw MalformedMessage(std::string("JSON 的 ") + field + " 不是整数");
  return *parsed;
}

EaDecoded decode_ea(const std::vector<uint8_t>& data, size_t offset, const char* what) {
  const EaDecoded decoded = ea_decode(data.data(), data.size(), offset, data.size());
  if (decoded.status != EaStatus::kOk) throw MalformedMessage(std::string(what) + " 的 EA 不完整");
  return decoded;
}

std::string double_text(double value) {
  char text[32];
  std::snprintf(text, sizeof(text), "%.6g", value);
  return text;
}

}  // namespace

DmsdpSession::DmsdpSession(DmsdpConfig config, const std::array<uint8_t, 16>& session_key,
                           auth::RandomSource* random)
    : config_(std::move(config)), key_(session_key), random_(random) {
  if (config_.device_id.empty() || config_.device_id.size() > 64) {
    throw std::invalid_argument("deviceId 必须是 1～64 个字符");
  }
  if (config_.bluetooth_mac.size() != 17) throw std::invalid_argument("bluetoothMac 格式不对");
  if (random_ == nullptr) throw std::invalid_argument("random 不能为空");
}

void DmsdpSession::check_usable() const {
  if (failed_) throw std::logic_error("会话已因协议错误作废");
  if (closed_) throw std::logic_error("会话已关闭");
}

std::vector<uint8_t> DmsdpSession::seal(const std::vector<uint8_t>& plain) {
  const auto iv = random_->bytes(16);
  if (iv.size() != 16) throw std::logic_error("随机源没有给出 16 字节 IV");
  return seal_control_payload(key_.data(), iv.data(), plain);
}

std::vector<uint8_t> DmsdpSession::open(const std::vector<uint8_t>& sealed) {
  return open_control_payload(key_.data(), sealed);
}

std::vector<DmsdpOutput> DmsdpSession::feed(DmsdpChannel channel, const uint8_t* data, size_t size,
                                            uint64_t now_millis) {
  check_usable();
  if (channel == DmsdpChannel::kSession) {
    try {
      return feed_session(data, size);
    } catch (...) {
      failed_ = true;
      throw;
    }
  }
  if (channel == DmsdpChannel::kControl) {
    if (control_state_ != ControlState::kPlaintext && control_state_ != ControlState::kEncrypted) {
      throw std::logic_error("控制连接不在可收数据的状态");
    }
    try {
      return feed_control(data, size, now_millis);
    } catch (...) {
      failed_ = true;
      throw;
    }
  }
  return {};
}

std::vector<DmsdpOutput> DmsdpSession::feed_session(const uint8_t* data, size_t size) {
  session_decoder_.append(data, size);
  std::vector<DmsdpOutput> out;
  while (const auto frame = session_decoder_.next()) {
    if (frame->module != kSessionModule || frame->payload.size() != kNegotiationBytes ||
        frame->payload[0] != 0) {
      throw MalformedMessage("业务 20 首轮协商与已知格式不符");
    }
    if (control_port_ != 0) {
      DmsdpAction action;
      action.kind = DmsdpAction::Kind::kSend;
      action.channel = DmsdpChannel::kSession;
      action.bytes = negotiation_reply(control_port_);
      out.push_back(std::move(action));
    } else {
      ++pending_negotiations_;
      if (!listener_requested_) {
        listener_requested_ = true;
        DmsdpAction action;
        action.kind = DmsdpAction::Kind::kOpenControlListener;
        out.push_back(std::move(action));
      }
    }
  }
  return out;
}

std::vector<DmsdpOutput> DmsdpSession::control_listener_ready(uint16_t port, uint64_t /*now*/) {
  check_usable();
  if (port == 0 || (control_port_ != 0 && control_port_ != port)) {
    throw std::invalid_argument("控制监听端口非法或更换");
  }
  control_port_ = port;
  std::vector<DmsdpOutput> out;
  for (uint32_t i = 0; i < pending_negotiations_; ++i) {
    DmsdpAction action;
    action.kind = DmsdpAction::Kind::kSend;
    action.channel = DmsdpChannel::kSession;
    action.bytes = negotiation_reply(port);
    out.push_back(std::move(action));
  }
  pending_negotiations_ = 0;
  return out;
}

std::vector<DmsdpOutput> DmsdpSession::on_connected(DmsdpChannel channel, uint64_t /*now*/) {
  check_usable();
  if (channel != DmsdpChannel::kControl) return {};
  if (control_state_ != ControlState::kNotConnected) throw std::logic_error("控制连接只能建立一次");
  control_state_ = ControlState::kPlaintext;
  return send_request("OPTIONS", {{"CryptoVer", "1"},
                                  {"CryptoAbility", "222"},
                                  {"CryptoAlg", "aes128-ctr"},
                                  {"UdpKA", config_.advertise_udp_keep_alive ? "1" : "0"},
                                  {"KaRetry", std::to_string(config_.keep_alive_retry)},
                                  {"LowDelay", "1"}});
}

std::vector<DmsdpOutput> DmsdpSession::feed_control(const uint8_t* data, size_t size, uint64_t now) {
  control_decoder_.append(data, size);
  std::vector<DmsdpOutput> out;
  while (const auto frame = control_decoder_.next()) {
    if (control_state_ == ControlState::kEncrypted) {
      if (!frame->encrypted) throw MalformedMessage("加密之后又收到明文控制帧");
      const auto plain = open(frame->payload);
      const auto part = on_encrypted_payload(plain, now);
      out.insert(out.end(), part.begin(), part.end());
    } else {
      if (frame->encrypted) throw MalformedMessage("加密协商完成前收到密文控制帧");
      const auto part = on_plain_payload(frame->payload, now);
      out.insert(out.end(), part.begin(), part.end());
    }
  }
  return out;
}

std::vector<DmsdpOutput> DmsdpSession::on_plain_payload(const std::vector<uint8_t>& payload,
                                                        uint64_t now) {
  if (is_device_record(payload)) throw MalformedMessage("加密协商完成前收到设备消息");
  const DmsdpMessage message = parse_dmsdp_message(payload);
  if (message.is_response()) {
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kUnhandledControlMessage;
    event.text = message.start_line;
    return {event};
  }
  if (message.method() == std::optional<std::string>("SET_PARAMETER")) {
    return on_crypto_selection(message, now);
  }
  throw MalformedMessage("加密协商完成前收到不支持的明文请求");
}

std::vector<DmsdpOutput> DmsdpSession::on_crypto_selection(const DmsdpMessage& message, uint64_t now) {
  if (has_duplicate_headers(message)) throw MalformedMessage("加密选择请求有重名头部");
  if (!content_length_matches(message)) throw MalformedMessage("加密选择请求的 Content-Length 与正文不符");
  const auto* ver = message.header("CryptoVer");
  const auto* ability = message.header("CryptoSwitch");
  const auto* alg = message.header("CryptoAlg");
  if (ver == nullptr || *ver != "1" || ability == nullptr || *ability != "222" || alg == nullptr ||
      *alg != "aes128-ctr") {
    throw MalformedMessage("手机选择了不支持的加密方式");
  }
  const auto* cseq = message.header("CSeq");
  if (cseq == nullptr || !is_ascii_decimal(*cseq)) throw MalformedMessage("加密选择请求缺少有效 CSeq");

  const auto* udp_ka = message.header("UdpKA");
  const bool want_udp = udp_ka != nullptr && *udp_ka == "1";
  if (udp_ka != nullptr && *udp_ka != "0" && *udp_ka != "1") {
    throw MalformedMessage("手机选择了不支持的保活方式");
  }
  uint16_t udp_port = 0;
  if (want_udp) {
    const auto* port = message.header("UdpKAport");
    if (port == nullptr || !is_ascii_decimal(*port) || port->size() > 5) {
      throw MalformedMessage("手机选择 UDP 保活但没给有效端口");
    }
    const int value = std::stoi(*port);
    if (value < 1 || value > 65535) throw MalformedMessage("手机选择 UDP 保活但没给有效端口");
    udp_port = static_cast<uint16_t>(value);
  }

  std::vector<DmsdpOutput> out;
  {
    const auto reply = encode_dmsdp_message(
        kOk, {{"CSeq", *cseq}, {"CryptoVer", "1"}, {"CryptoSwitch", "222"},
              {"CryptoAlg", "aes128-ctr"}, {"Platform", std::to_string(config_.platform)}});
    DmsdpAction action;
    action.kind = DmsdpAction::Kind::kSend;
    action.channel = DmsdpChannel::kControl;
    action.bytes = encode_control_frame(kControlPlain, reply);
    out.push_back(std::move(action));
  }
  control_state_ = ControlState::kEncrypted;
  if (want_udp) {
    udp_keep_alive_active_ = true;
    udp_ = {};
    udp_.next_at = now + 1000;
    DmsdpAction action;
    action.kind = DmsdpAction::Kind::kOpenKeepAliveSocket;
    action.port = udp_port;
    out.push_back(std::move(action));
  } else {
    tcp_keep_alive_active_ = true;
    tcp_next_at_ = now + 1000;
    tcp_alive_ = false;
    tcp_started_ = false;
    tcp_misses_ = 0;
  }
  DmsdpEvent event;
  event.kind = DmsdpEvent::Kind::kEncryptionEnabled;
  event.flag = want_udp;
  out.push_back(std::move(event));
  return out;
}

bool is_keep_alive_request(const DmsdpMessage& message) {
  if (message.start_line != "GET_PARAMETER * DMSDP/1.0") return false;
  const auto* cseq = message.header("CSeq");
  if (cseq == nullptr || !is_ascii_decimal(*cseq) || *cseq == "0") return false;
  return message.body.empty() && content_length_matches(message) && !has_duplicate_headers(message);
}

std::vector<DmsdpOutput> DmsdpSession::on_encrypted_payload(const std::vector<uint8_t>& payload,
                                                            uint64_t now) {
  if (is_device_record(payload)) {
    std::vector<DmsdpOutput> out;
    for (const auto& record : parse_device_records(payload)) {
      const auto part = on_device_record(record.module, record.type, record.data, now);
      out.insert(out.end(), part.begin(), part.end());
    }
    return out;
  }

  const DmsdpMessage message = parse_dmsdp_message(payload);
  if (is_keep_alive_request(message)) {
    tcp_alive_ = true;
    tcp_started_ = true;
    return {};
  }
  if (message.is_response()) {
    const auto* cseq = message.header("CSeq");
    if (cseq != nullptr && audio_setup_cseq_ != 0 && is_ascii_decimal(*cseq) &&
        static_cast<uint32_t>(std::stoul(*cseq)) == audio_setup_cseq_) {
      return on_audio_setup_response(message, now);
    }
  }
  if (message.method() == std::optional<std::string>("SET_PARAMETER")) {
    const auto* service_id = message.header("ServiceID");
    const auto* service_type = message.header("ServiceType");
    if (service_id != nullptr && *service_id == "speaker1" && service_type != nullptr &&
        *service_type == "3") {
      return on_audio_trigger(message, now);
    }
    const auto* server = message.header("TimeServerPort");
    const auto* high = message.header("TimeUsHigh");
    const auto* low = message.header("TimeUsLow");
    if (server != nullptr && high != nullptr && low != nullptr) {
      const auto* cseq = message.header("CSeq");
      if (cseq == nullptr || !is_ascii_decimal(*cseq) || !content_length_matches(message) ||
          has_duplicate_headers(message)) {
        throw MalformedMessage("时间同步请求格式不对");
      }
      remember_phone_time(message, now);
      std::vector<DmsdpOutput> out;
      const auto reply = encode_dmsdp_message(kOk, {{"CSeq", *cseq}});
      DmsdpAction action;
      action.kind = DmsdpAction::Kind::kSend;
      action.channel = DmsdpChannel::kControl;
      action.bytes = encode_control_frame(kControlEncrypted, seal(reply));
      out.push_back(std::move(action));
      DmsdpEvent event;
      event.kind = DmsdpEvent::Kind::kTimeSyncRequested;
      event.text = *server;
      event.text2 = *high + "|" + *low;
      out.push_back(std::move(event));
      return out;
    }
  }
  DmsdpEvent event;
  event.kind = DmsdpEvent::Kind::kUnhandledControlMessage;
  event.text = message.start_line;
  return {event};
}

std::vector<DmsdpOutput> DmsdpSession::on_audio_trigger(const DmsdpMessage& message, uint64_t /*now*/) {
  if (has_duplicate_headers(message)) throw MalformedMessage("音频数据会话请求有重名头部");
  if (!content_length_matches(message)) throw MalformedMessage("音频数据会话请求正文长度不符");
  const auto* cseq = message.header("CSeq");
  if (cseq == nullptr || !is_ascii_decimal(*cseq)) throw MalformedMessage("音频数据会话请求缺少有效 CSeq");
  const auto* session_id = message.header("DataSessionID");
  if (session_id == nullptr || session_id->empty()) throw MalformedMessage("音频数据会话缺少 DataSessionID");

  std::string trigger;
  const auto* trigger_header = message.header("msdp_trigger_method");
  if (trigger_header != nullptr) trigger = *trigger_header;
  if (trigger.empty() && !message.body.empty()) {
    const std::string body(message.body.begin(), message.body.end());
    const size_t pos = body.find("msdp_trigger_method");
    if (pos != std::string::npos) {
      const size_t colon = body.find(':', pos);
      if (colon != std::string::npos) {
        size_t begin = colon + 1;
        while (begin < body.size() && (body[begin] == ' ' || body[begin] == '\t')) ++begin;
        size_t end = begin;
        while (end < body.size() && body[end] != '\r' && body[end] != '\n') ++end;
        trigger.assign(body.begin() + static_cast<std::ptrdiff_t>(begin), body.begin() + static_cast<std::ptrdiff_t>(end));
        while (!trigger.empty() && (trigger.back() == ' ' || trigger.back() == '\t')) trigger.pop_back();
      }
    }
  }
  if (trigger.empty()) throw MalformedMessage("音频数据会话缺少 msdp_trigger_method");

  std::vector<DmsdpOutput> out;
  {
    const auto reply = encode_dmsdp_message(
        kOk, {{"ServiceID", "speaker1"}, {"ServiceType", "3"}, {"DataSessionID", *session_id},
              {"CSeq", *cseq}});
    const auto part = send_text(reply);
    out.insert(out.end(), part.begin(), part.end());
  }

  if (trigger == "OPTIONS") {
    const bool same = audio_active_ && audio_session_id_ == *session_id;
    if (!same) {
      audio_active_ = true;
      audio_session_id_ = *session_id;
      audio_setup_sent_ = false;
      audio_port_ = 0;
      DmsdpAction action;
      action.kind = DmsdpAction::Kind::kOpenAudioListener;
      out.push_back(std::move(action));
    } else if (audio_port_ != 0 && !audio_setup_sent_) {
      const auto part = send_audio_setup(audio_port_);
      out.insert(out.end(), part.begin(), part.end());
    }
    return out;
  }

  if (trigger == "TEARDOWN") {
    const bool was_active = audio_active_;
    audio_active_ = false;
    audio_setup_sent_ = false;
    audio_session_id_.clear();
    audio_port_ = 0;
    DmsdpAction action;
    action.kind = DmsdpAction::Kind::kCloseAudioTransport;
    out.push_back(std::move(action));
    if (was_active) {
      DmsdpEvent event;
      event.kind = DmsdpEvent::Kind::kAudioSessionTornDown;
      out.push_back(std::move(event));
    }
    return out;
  }

  return out;
}

std::vector<DmsdpOutput> DmsdpSession::on_audio_setup_response(const DmsdpMessage& message,
                                                              uint64_t /*now*/) {
  std::vector<DmsdpOutput> out;
  const auto status = message.status_code();
  if (!status.has_value() || *status != 200) {
    audio_setup_sent_ = false;
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kAudioSessionTornDown;
    out.push_back(std::move(event));
    return out;
  }
  audio_setup_cseq_ = 0;
  DmsdpEvent event;
  event.kind = DmsdpEvent::Kind::kAudioSessionEstablished;
  event.text = audio_session_id_;
  event.number = audio_port_;
  out.push_back(std::move(event));
  return out;
}

std::vector<DmsdpOutput> DmsdpSession::audio_listener_ready(uint16_t port, uint64_t /*now*/) {
  check_usable();
  if (port == 0) throw std::invalid_argument("音频监听端口非法");
  audio_port_ = port;
  if (!audio_active_) return {};
  return send_audio_setup(port);
}

std::vector<DmsdpOutput> DmsdpSession::send_audio_setup(uint16_t port) {
  if (!audio_active_ || audio_session_id_.empty()) return {};
  audio_setup_cseq_ = next_cseq_++;
  const std::string transport = "RTP/AVP/UDP;unicast;client_port=" + std::to_string(port) + "--1";
  const auto message = encode_dmsdp_message(
      "SETUP * DMSDP/1.0",
      {{"ServiceID", "speaker1"}, {"ServiceType", "3"}, {"DataSessionID", audio_session_id_},
       {"CSeq", std::to_string(audio_setup_cseq_)}, {"Simple", "1"}, {"CryptoVer", "1"},
       {"CryptoAbility", "222"}, {"CryptoAlg", "aes128-ctr"}, {"Fillp", "0"}, {"TCP", "1"},
       {"Codec", "0"}, {"Transport", transport}});
  audio_setup_sent_ = true;
  return send_text(message);
}

void DmsdpSession::remember_phone_time(const DmsdpMessage& message, uint64_t now) {
  const auto* high_text = message.header("TimeUsHigh");
  const auto* low_text = message.header("TimeUsLow");
  if (high_text == nullptr || low_text == nullptr) return;
  try {
    const int64_t high = std::stoll(*high_text);
    const int64_t low = std::stoll(*low_text);
    if (high < 0 || high > 0x7FFFFFFFLL) return;
    phone_time_us_ = (high << 32) | (low & 0xFFFFFFFFLL);
    phone_time_at_millis_ = now;
  } catch (const std::exception&) {
    return;
  }
}

std::vector<DmsdpOutput> DmsdpSession::on_device_record(uint32_t module, int32_t type,
                                                        const std::vector<uint8_t>& data,
                                                        uint64_t /*now*/) {
  std::vector<DmsdpOutput> out;
  if (type == kTypeDeviceData && module == kModuleDevice) {
    return handle_device_command(data);
  }
  if (type == kTypeDeviceData && module == kModuleDisplay) {
    if (data.empty()) throw MalformedMessage("显示消息为空");
    const auto command = decode_ea(data, 0, "显示命令");
    if (command.value == kCmdDisplayPort) {
      const auto port = decode_ea(data, command.size, "显示端口");
      if (command.size + port.size != data.size() || port.value < 1 || port.value > 65535) {
        throw MalformedMessage("显示端口 EA 有多余数据或超出范围");
      }
      DmsdpEvent event;
      event.kind = DmsdpEvent::Kind::kDisplayPortAnnounced;
      event.number = port.value;
      return {event};
    }
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kUnsupportedDeviceCommand;
    event.number = module;
    event.number2 = command.value;
    event.data.assign(data.begin() + static_cast<std::ptrdiff_t>(command.size), data.end());
    return {event};
  }
  if (module == 1 && type != kTypeDeviceData) {
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kCarData;
    event.number = static_cast<uint32_t>(type);
    event.data = data;
    return {event};
  }
  DmsdpEvent event;
  event.kind = DmsdpEvent::Kind::kUnhandledDeviceData;
  event.number = module;
  event.signed_number = type;
  event.data = data;
  out.push_back(std::move(event));
  return out;
}

std::vector<DmsdpOutput> DmsdpSession::handle_device_command(const std::vector<uint8_t>& data) {
  if (data.empty()) throw MalformedMessage("设备命令为空");
  const auto command = decode_ea(data, 0, "设备命令");
  std::vector<uint8_t> body(data.begin() + static_cast<std::ptrdiff_t>(command.size), data.end());
  std::vector<DmsdpOutput> out;

  if (command.value == kCmdDeviceInfo) {
    const auto device = parse_object(body, "设备信息 101");
    const std::string device_id = require_string(device, "deviceId");
    const int64_t device_type = require_int(device, "deviceType");
    if (!peer_device_id_.empty() && peer_device_id_ != device_id) {
      throw MalformedMessage("同一连接里手机的设备 ID 变了");
    }
    peer_device_id_ = device_id;
    if (!local_info_sent_) {
      const std::string json = local_device_json();
      std::vector<uint8_t> payload;
      payload.push_back(0xE5);  // EA(101) = 0xE5
      payload.insert(payload.end(), json.begin(), json.end());
      const auto reply = send_record(kModuleDevice, kTypeDeviceData, payload);
      out.insert(out.end(), reply.begin(), reply.end());
      local_info_sent_ = true;
    }
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kPeerDeviceInfo;
    event.text = device_id;
    event.signed_number = static_cast<int32_t>(device_type);
    event.json = json_of(body);
    out.push_back(std::move(event));
    return out;
  }

  if (command.value == kCmdServiceInfo) {
    const auto service = parse_object(body, "服务 JSON");
    require_string(service, "deviceId");
    const std::string id = require_string(service, "serviceId");
    const int64_t type = require_int(service, "serviceType");
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kPeerServiceInfo;
    event.number = static_cast<uint32_t>(type);
    event.text = id;
    event.json = json_of(body);
    out.push_back(std::move(event));
    return out;
  }

  if (command.value == kCmdServiceStatus) {
    if (body.size() <= 4) throw MalformedMessage("服务状态 103 缺少动作或服务 JSON");
    const int32_t action = read_i32be(body.data());
    std::vector<uint8_t> service_body(body.begin() + 4, body.end());
    const auto service = parse_object(service_body, "服务 JSON");
    require_string(service, "deviceName");
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kServiceStatusChanged;
    event.signed_number = action;
    event.number = static_cast<uint32_t>(require_int(service, "serviceType"));
    event.text = require_string(service, "serviceId");
    event.json = json_of(service_body);
    out.push_back(std::move(event));
    return out;
  }

  if (command.value == kCmdServiceRequest) {
    if (body.size() != 4) throw MalformedMessage("服务请求 104 必须是 4 字节掩码");
    const uint32_t mask = read_u32be(body.data());
    uint32_t answered = 0;
    for (const auto& service : local_services()) {
      if ((mask & service.service_type) == 0) continue;
      std::vector<uint8_t> payload;
      payload.push_back(0xE6);  // EA(102) = 0xE6
      const std::string json = service_json(service);
      payload.insert(payload.end(), json.begin(), json.end());
      const auto reply = send_record(kModuleDevice, kTypeDeviceData, payload);
      out.insert(out.end(), reply.begin(), reply.end());
      ++answered;
    }
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kServicesRequested;
    event.number = mask;
    event.number2 = answered;
    out.push_back(std::move(event));
    return out;
  }

  if (command.value == kCmdDisconnectType) {
    if (body.size() != 4) throw MalformedMessage("断开类型 105 必须是 4 字节整数");
    DmsdpEvent event;
    event.kind = DmsdpEvent::Kind::kUnhandledDeviceData;
    event.number = kModuleDevice;
    event.signed_number = read_i32be(body.data());
    event.text = "105";
    out.push_back(std::move(event));
    return out;
  }

  DmsdpEvent event;
  event.kind = DmsdpEvent::Kind::kUnsupportedDeviceCommand;
  event.number = kModuleDevice;
  event.number2 = command.value;
  event.data = body;
  out.push_back(std::move(event));
  return out;
}

std::vector<DmsdpService> DmsdpSession::local_services() const {
  std::vector<DmsdpService> services;
  if (config_.display.has_value()) {
    const auto& display = *config_.display;
    DmsdpService service;
    service.service_type = 8;
    service.service_id = "display1";
    service.properties_json = "{\"4001\":" + double_text(display.density) +
                              ",\"1009\":" + std::to_string(display.width) +
                              ",\"1010\":" + std::to_string(display.height) + "}";
    services.push_back(std::move(service));
  }
  if (config_.speaker.has_value()) services.push_back(*config_.speaker);
  if (config_.mic.has_value()) services.push_back(*config_.mic);
  for (const auto& service : config_.additional_services) services.push_back(service);
  return services;
}

std::string DmsdpSession::local_device_json() const {
  std::string json = "{\"deviceId\":\"" + auth::escape_json_string(config_.device_id) + "\"";
  json += ",\"deviceName\":\"" + auth::escape_json_string(config_.device_name) + "\"";
  json += ",\"deviceType\":4";
  json += ",\"bluetoothMac\":\"" + auth::escape_json_string(config_.bluetooth_mac) + "\"";
  json += ",\"btName\":\"" + auth::escape_json_string(config_.device_name) + "\"";
  json += ",\"localIp\":\"" + auth::escape_json_string(config_.local_ip) + "\"";
  json += ",\"remoteIp\":\"" + auth::escape_json_string(config_.phone_ip) + "\"";
  json += ",\"port\":-1,\"businessId\":1,\"properties\":{";
  if (config_.display.has_value()) {
    const auto& display = *config_.display;
    json += "\"1005\":" + std::to_string(display.video_width);
    json += ",\"1006\":" + std::to_string(display.video_height);
    json += ",\"1012\":" + std::to_string(display.width);
    json += ",\"1013\":" + std::to_string(display.height);
    json += ",\"1011\":" + std::to_string(display.dpi);
    json += ",\"1015\":" + std::to_string(display.fps);
    json += ",\"1014\":" + std::to_string(display.codec);
    if (display.gop.has_value()) json += ",\"1016\":" + std::to_string(*display.gop);
    if (display.bitrate.has_value()) json += ",\"1017\":" + std::to_string(*display.bitrate);
    json += ",";
  }
  json += "\"2003\":\"" + auth::escape_json_string(config_.full_model) + "\"}}";
  return json;
}

std::string DmsdpSession::service_json(const DmsdpService& service) const {
  std::string json = "{\"deviceId\":\"" + auth::escape_json_string(config_.device_id) + "\"";
  json += ",\"deviceName\":\"" + auth::escape_json_string(config_.device_name) + "\"";
  json += ",\"serviceType\":" + std::to_string(service.service_type);
  json += ",\"serviceId\":\"" + auth::escape_json_string(service.service_id) + "\"";
  json += ",\"properties\":" + service.properties_json;
  json += ",\"status\":" + service.status_json + "}";
  return json;
}

std::vector<DmsdpOutput> DmsdpSession::send_request(
    const std::string& method, const std::vector<std::pair<std::string, std::string>>& headers) {
  std::vector<std::pair<std::string, std::string>> all = headers;
  all.emplace_back("CSeq", std::to_string(next_cseq_));
  ++next_cseq_;
  return send_text(encode_dmsdp_message(method + " * " + kVersion, all));
}

std::vector<DmsdpOutput> DmsdpSession::send_text(const std::vector<uint8_t>& text) {
  DmsdpAction action;
  action.kind = DmsdpAction::Kind::kSend;
  action.channel = DmsdpChannel::kControl;
  if (control_state_ == ControlState::kEncrypted) {
    action.bytes = encode_control_frame(kControlEncrypted, seal(text));
  } else {
    action.bytes = encode_control_frame(kControlPlain, text);
  }
  return {std::move(action)};
}

std::vector<DmsdpOutput> DmsdpSession::send_record(uint32_t module, int32_t type,
                                                   const std::vector<uint8_t>& data) {
  if (control_state_ != ControlState::kEncrypted) throw std::logic_error("控制连接还没有加密");
  const auto record = encode_device_record(module, type, data);
  DmsdpAction action;
  action.kind = DmsdpAction::Kind::kSend;
  action.channel = DmsdpChannel::kControl;
  action.bytes = encode_control_frame(kControlEncrypted, seal(record));
  return {std::move(action)};
}

std::vector<DmsdpOutput> DmsdpSession::send_device_data(uint32_t module, int32_t type,
                                                        const std::vector<uint8_t>& data) {
  check_usable();
  return send_record(module, type, data);
}

std::optional<uint64_t> DmsdpSession::next_tick_at() const {
  if (failed_ || closed_ || control_state_ != ControlState::kEncrypted) return std::nullopt;
  std::optional<uint64_t> next;
  if (tcp_keep_alive_active_) next = tcp_next_at_;
  if (udp_keep_alive_active_ && udp_.next_at.has_value()) {
    if (!next.has_value() || *udp_.next_at < *next) next = *udp_.next_at;
  }
  return next;
}

std::vector<DmsdpOutput> DmsdpSession::on_tick(uint64_t now) {
  if (failed_ || closed_) return {};
  std::vector<DmsdpOutput> out;
  if (control_state_ != ControlState::kEncrypted) return out;

  if (tcp_keep_alive_active_ && now >= tcp_next_at_) {
    if (tcp_alive_) {
      tcp_misses_ = 0;
      tcp_alive_ = false;
    } else {
      ++tcp_misses_;
      if (tcp_misses_ >= 10) {
        tcp_keep_alive_active_ = false;
        DmsdpEvent event;
        event.kind = DmsdpEvent::Kind::kKeepAliveTimeout;
        out.push_back(std::move(event));
        return out;
      }
    }
    tcp_next_at_ = now + 1000;
    if (tcp_started_) {
      const auto part = send_request("GET_PARAMETER", {});
      out.insert(out.end(), part.begin(), part.end());
    }
  }

  if (udp_keep_alive_active_ && udp_.next_at.has_value() && now >= *udp_.next_at) {
    const uint32_t window = udp_.period * static_cast<uint32_t>(config_.keep_alive_retry) / 2;
    if (udp_.round > window) {
      if (udp_.received == 0) {
        udp_keep_alive_active_ = false;
        DmsdpEvent event;
        event.kind = DmsdpEvent::Kind::kKeepAliveTimeout;
        out.push_back(std::move(event));
        return out;
      }
      udp_.round = 0;
      udp_.received = 0;
    }
    ++udp_.round;
    udp_.next_at = now + static_cast<uint64_t>(udp_.period) * 500;
    if (udp_.round % 2 == 0) {
      std::vector<uint8_t> plain(16, 0);
      plain[5] = 0x0A;
      if (udp_.extended) {
        plain[6] = 0x0A;
        plain[7] = 0xDE;
        plain[8] = 0;
        plain[9] = 0;
        plain[10] = 0;
        plain[11] = 30;
      }
      DmsdpAction action;
      action.kind = DmsdpAction::Kind::kSendDatagram;
      action.bytes = encode_control_frame(kControlEncrypted, seal(plain));
      out.push_back(std::move(action));
    }
  }
  return out;
}

std::vector<DmsdpOutput> DmsdpSession::on_datagram(const uint8_t* data, size_t size, uint64_t /*now*/) {
  check_usable();
  if (!udp_keep_alive_active_ || size < 3 + 16 + 16) return {};
  if (data[0] != kControlEncrypted) throw MalformedMessage("UDP 保活不是加密帧");
  const uint16_t declared = static_cast<uint16_t>((static_cast<uint16_t>(data[1]) << 8) | data[2]);
  if (declared != size - 3) throw MalformedMessage("UDP 保活长度字段与数据报不符");
  const std::vector<uint8_t> sealed(data + 3, data + size);
  const auto plain = open(sealed);
  if (plain.size() != 16) throw MalformedMessage("UDP 保活明文不是 16 字节");
  static const uint8_t prefix[6] = {0, 0, 0, 0, 0, 0x0A};
  if (!std::equal(prefix, prefix + 6, plain.begin())) throw MalformedMessage("UDP 保活明文前缀不对");
  const bool extended = plain[6] == 0x0A && plain[7] == 0xDE && read_u32be(&plain[8]) == 30;
  udp_.extended = extended;
  udp_.period = extended ? 30 : 2;
  ++udp_.received;
  return {};
}

std::vector<DmsdpOutput> DmsdpSession::close() {
  if (closed_) return {};
  closed_ = true;
  tcp_keep_alive_active_ = false;
  udp_keep_alive_active_ = false;
  return {};
}

}  // namespace dmsdp
}  // namespace hicar
