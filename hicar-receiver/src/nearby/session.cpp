#include "nearby/session.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>

#include "common/byte_buffer.h"
#include "common/error.h"
#include "common/hex.h"
#include "identity/device_id.h"
#include "nearby/channel_management.h"
#include "nearby/data_channel.h"
#include "nearby/tlv.h"
#include "nearby/wifi_connection_info.h"

namespace hicar {

namespace {

constexpr uint32_t kSeenVersion = 1;
constexpr uint32_t kSeenSummary = 2;
constexpr uint32_t kSeenEncryption = 4;
constexpr uint32_t kSeenAll = kSeenVersion | kSeenSummary | kSeenEncryption;

constexpr uint32_t kOuterWifiLink = 33;
constexpr uint32_t kTagWifiPeerMac = 2;
constexpr uint32_t kTagWifiDisconnect = 5;
constexpr uint32_t kTagWifiDisconnectAck = 6;
constexpr uint32_t kMessageProbe = 1;
constexpr uint32_t kMessageProbeAck = 2;

// 手机没带 uuid 时的 RFCOMM 子通道 UUID：0000FE36-0000-1000-8000-00805F9B34FB
const std::vector<uint8_t> kDefaultSubchannelUuid = {0x00, 0x00, 0xFE, 0x36, 0x00, 0x00, 0x10, 0x00,
                                                     0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};

std::optional<std::string> parse_peer_mac(const std::vector<uint8_t>& value) {
  for (uint8_t b : value) {
    if (b < 0x20 || b > 0x7E) throw MalformedMessage("手机 MAC 不是可打印 ASCII");
  }
  std::string text(value.begin(), value.end());
  if (text == "busy") return std::nullopt;
  const bool ok = text.size() == 17 && text[2] == ':' && text[5] == ':' && text[8] == ':' && text[11] == ':' &&
                  text[14] == ':';
  if (!ok) throw MalformedMessage("手机 MAC 格式不对");
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return text;
}

std::string format_bluetooth(const std::array<uint8_t, 6>& address) {
  char text[18];
  std::snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1], address[2],
                address[3], address[4], address[5]);
  return std::string(text);
}

bool is_unavailable_bluetooth(const std::array<uint8_t, 6>& address) {
  return address == std::array<uint8_t, 6>{0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
}

}  // namespace

NearbySession::NearbySession(HostIdentity host, NearbyKeyMaterial keys,
                             std::optional<std::array<uint8_t, 6>> bluetooth_address, NearbyLink link,
                             uint64_t rng_seed)
    : link_(link),
      host_(std::move(host)),
      cipher_(keys),
      decoder_(NearbyFrameDecoder::kDefaultMaxPayload),
      rng_(rng_seed != 0 ? rng_seed : std::random_device{}()) {
  std::array<uint8_t, 6> address{};
  if (bluetooth_address.has_value()) address = *bluetooth_address;
  bluetooth_text_ = format_bluetooth(address);

  const std::array<uint8_t, 32> id = derive_device_id(host_.model_id, host_.sub_model_id, address);
  device_id_hex_ = device_id_hex(id);
  own_device_id_text_.assign(device_id_hex_.begin(), device_id_hex_.end());
  own_address_text_.assign(bluetooth_text_.begin(), bluetooth_text_.end());
}

std::vector<NearbyAction> NearbySession::start(uint64_t now_millis) {
  if (started_) throw std::logic_error("start 只能调用一次");
  started_ = true;
  deadline_ = now_millis + kHandshakeTimeoutMillis;

  std::vector<NearbyAction> out;
  const std::vector<uint8_t> payload =
      encode_tlv(channel_management::kTagConnectId, channel_management::connect_id_value(next_connect_id()));
  send(channel_management::kOuterType, payload, out);

  if (link_ == NearbyLink::kWifi) {
    const std::vector<uint8_t> request =
        ByteWriter()
            .raw(encode_tlv(channel_management::kTagVersionRequest, {2}))
            .raw(encode_tlv(channel_management::kTagSummaryRequest, own_device_id_text_))
            .raw(encode_tlv(channel_management::kTagEncryptionRequest, {1}))
            .take();
    send(channel_management::kOuterType, request, out);
  }
  return out;
}

std::vector<NearbyAction> NearbySession::feed(const std::vector<uint8_t>& data) {
  if (!started_) throw std::logic_error("先调用 start");
  if (closed_) return {};
  decoder_.feed(data);

  std::vector<NearbyAction> out;
  while (true) {
    try {
      const auto frame = decoder_.next();
      if (!frame.has_value()) break;
      handle_frame(*frame, out);
    } catch (const MalformedMessage& e) {
      out.push_back(InputDiscarded{e.what(), decoder_.buffered()});
      break;
    }
  }
  return out;
}

std::vector<NearbyAction> NearbySession::on_tick(uint64_t now_millis) {
  if (!deadline_.has_value()) return {};
  if (now_millis < *deadline_) return {};
  deadline_.reset();
  closed_ = true;
  decoder_.clear();
  return {HandshakeTimedOut{}};
}

std::vector<NearbyAction> NearbySession::accept_socket(const SocketRequested& request, uint32_t port) {
  if (closed_) throw std::logic_error("控制通道已作废");
  if (port < 1 || port > 65535) throw std::invalid_argument("端口必须在 1～65535 之间");
  return respond(request, socket_messages::kStatusAccepted, port, socket_messages::kProtocolTcp);
}

std::vector<NearbyAction> NearbySession::reject_socket(const SocketRequested& request) {
  if (closed_) throw std::logic_error("控制通道已作废");
  return respond(request, socket_messages::kStatusRejected, 0, 0);
}

std::vector<NearbyAction> NearbySession::accept_rfcomm_socket(const SocketRequested& request, uint32_t channel) {
  if (closed_) throw std::logic_error("控制通道已作废");
  if (link_ != NearbyLink::kBluetooth) throw std::logic_error("只有蓝牙控制通道上才开 RFCOMM 子通道");
  if (channel < 1 || channel > 30) throw std::invalid_argument("RFCOMM 通道号必须在 1～30 之间");
  std::optional<std::vector<uint8_t>> uuid = request.request.uuid;
  if (!uuid.has_value()) uuid = kDefaultSubchannelUuid;
  if (uuid->size() != 16) throw std::invalid_argument("RFCOMM 服务 UUID 应为 16 字节");
  return respond(request, socket_messages::kStatusAccepted, channel, request.request.protocol, uuid);
}

std::vector<NearbyAction> NearbySession::accept_data_channel(const DataChannelRequested& request,
                                                             uint32_t frequency_mhz) {
  if (closed_) throw std::logic_error("控制通道已作废");
  if (!channel_of_frequency(frequency_mhz).has_value()) throw std::invalid_argument("不是 WiFi 信道频率");
  std::vector<NearbyAction> out;
  send(socket_messages::kOuterResource,
       data_channel::accept_payload(request.data_channel, data_channel::kRoleGroupOwner, frequency_mhz), out);
  return out;
}

std::vector<NearbyAction> NearbySession::reject_data_channel(const DataChannelRequested& request,
                                                             DataChannelRefusal refusal) {
  if (closed_) throw std::logic_error("控制通道已作废");
  std::vector<NearbyAction> out;
  send(socket_messages::kOuterResource, data_channel::refuse_payload(request.data_channel, refusal), out);
  return out;
}

std::vector<NearbyAction> NearbySession::request_wifi_peer_address() {
  if (closed_) throw std::logic_error("控制通道已作废");
  if (link_ != NearbyLink::kBluetooth) throw std::logic_error("这条消息只在蓝牙控制通道上发");
  if (!handshake_complete_) throw std::logic_error("控制通道握手还没完成");
  std::vector<NearbyAction> out;
  send(kOuterWifiLink, encode_tlv(1), out);
  return out;
}

std::vector<NearbyAction> NearbySession::send_wifi_connection_info(const WifiConnectionInfo& info) {
  if (closed_) throw std::logic_error("控制通道已作废");
  if (link_ != NearbyLink::kBluetooth) throw std::logic_error("这条消息只在蓝牙控制通道上发");
  if (!handshake_complete_) throw std::logic_error("控制通道握手还没完成");
  const std::string text = info.encode();
  std::vector<NearbyAction> out;
  send(kOuterWifiLink, encode_tlv(3, std::vector<uint8_t>(text.begin(), text.end())), out);
  return out;
}

std::vector<NearbyAction> NearbySession::request_wifi_disconnect() {
  if (closed_) throw std::logic_error("控制通道已作废");
  if (link_ != NearbyLink::kWifi) throw std::logic_error("断开请求在 WiFi 控制通道上发");
  if (!handshake_complete_) throw std::logic_error("控制通道握手还没完成");
  std::vector<NearbyAction> out;
  send(kOuterWifiLink, encode_tlv(kTagWifiDisconnect), out);
  return out;
}

void NearbySession::handle_frame(const NearbyFrame& frame, std::vector<NearbyAction>& out) {
  try {
    const std::vector<uint8_t> payload = cipher_.open(frame);
    switch (frame.outer_type()) {
      case channel_management::kOuterType:
        handle_channel_management(payload, out);
        break;
      case socket_messages::kOuterMessage:
      case socket_messages::kOuterResource:
        handle_socket_layer(frame.outer_type(), payload, out);
        break;
      case kOuterWifiLink:
        if (link_ == NearbyLink::kUsb) {
          out.push_back(UnhandledMessage{frame.outer_type(), std::nullopt, payload});
        } else {
          handle_wifi_link(payload, out);
        }
        break;
      default:
        out.push_back(UnhandledMessage{frame.outer_type(), std::nullopt, payload});
        break;
    }
  } catch (const MalformedMessage& e) {
    out.push_back(InputDiscarded{e.what(), frame.payload().size()});
  }
}

void NearbySession::handle_channel_management(const std::vector<uint8_t>& payload,
                                              std::vector<NearbyAction>& out) {
  const std::vector<channel_management::Item> items = channel_management::decode(payload);
  ByteWriter replies;
  for (const auto& item : items) {
    if (const auto* version = std::get_if<channel_management::Version>(&item)) {
      peer_version_ = version->version;
      seen_ |= kSeenVersion;
      if (version->request) replies.raw(encode_tlv(channel_management::kTagVersionResponse, {2}));
    } else if (const auto* summary = std::get_if<channel_management::Summary>(&item)) {
      seen_ |= kSeenSummary;
      if (summary->request) {
        peer_summary_ = summary->raw;
        replies.raw(encode_tlv(channel_management::kTagSummaryResponse, own_device_id_text_));
      } else {
        peer_device_id_ = summary->raw;
      }
    } else if (const auto* encryption = std::get_if<channel_management::Encryption>(&item)) {
      encrypted_ = encryption->enabled;
      seen_ |= kSeenEncryption;
      if (encryption->request) {
        const uint8_t value = encryption->enabled ? 1 : 0;
        replies.raw(encode_tlv(channel_management::kTagEncryptionResponse, std::vector<uint8_t>{value}));
      }
    } else if (const auto* address = std::get_if<channel_management::BluetoothAddress>(&item)) {
      peer_bluetooth_ = address->text;
      out.push_back(PeerBluetoothAddress{address->text});
      if (address->request) replies.raw(encode_tlv(channel_management::kTagBluetoothResponse, own_address_text_));
    } else if (const auto* id = std::get_if<channel_management::ConnectId>(&item)) {
      (void)id;
    } else if (const auto* unknown = std::get_if<channel_management::Unknown>(&item)) {
      out.push_back(UnhandledMessage{channel_management::kOuterType, unknown->tag, unknown->value});
    }
  }

  // 有线：握手信息够了但还不知道对端蓝牙地址时，先单独发一帧 tag 7 报本机地址。
  const bool peer_known = peer_summary_.has_value() || peer_device_id_.has_value();
  if (link_ == NearbyLink::kUsb && encrypted_ && peer_known && !peer_bluetooth_.has_value() &&
      !sent_bluetooth_request_) {
    sent_bluetooth_request_ = true;
    send(channel_management::kOuterType,
         encode_tlv(channel_management::kTagBluetoothRequest, own_address_text_), out);
  }
  if (replies.size() > 0) send(channel_management::kOuterType, replies.take(), out);

  if (!handshake_complete_ && seen_ == kSeenAll) {
    handshake_complete_ = true;
    deadline_.reset();
    std::optional<std::string> summary;
    if (peer_summary_.has_value()) summary = channel_management::text_of(*peer_summary_);
    out.push_back(HandshakeCompleted{peer_version_.value_or(0), summary, encrypted_});
  }
}

void NearbySession::handle_socket_layer(uint32_t outer_type, const std::vector<uint8_t>& payload,
                                        std::vector<NearbyAction>& out) {
  const std::vector<Tlv> tlvs = parse_tlvs(payload);
  const bool bluetooth = link_ == NearbyLink::kBluetooth;
  for (const Tlv& tlv : tlvs) {
    // 蓝牙控制通道专属：消息层探活、资源层数据通道协商。
    if (bluetooth && outer_type == socket_messages::kOuterMessage && tlv.tag == kMessageProbe) {
      send(socket_messages::kOuterMessage, encode_tlv(kMessageProbeAck), out);
      continue;
    }
    if (bluetooth && outer_type == socket_messages::kOuterResource && tlv.tag == data_channel::kCommandRequest) {
      const data_channel::Request request = data_channel::parse_request(tlv.value);
      out.push_back(DataChannelRequested{request.data_channel, request.capability});
      continue;
    }
    if (bluetooth && outer_type == socket_messages::kOuterResource && tlv.tag == data_channel::kCommandResult) {
      const data_channel::Result result = data_channel::parse_result(tlv.value);
      out.push_back(DataChannelResult{result.data_channel, result.result, result.role, result.frequency_mhz});
      continue;
    }

    if (tlv.tag != socket_messages::kCmdCreateRequest) {
      out.push_back(UnhandledMessage{outer_type, tlv.tag, tlv.value});
      continue;
    }
    socket_messages::Request request;
    try {
      request = socket_messages::parse_request(tlv.value);
    } catch (const MalformedMessage& e) {
      out.push_back(InputDiscarded{e.what(), tlv.value.size()});
      continue;
    }
    const bool wants_rfcomm = bluetooth && (request.protocol & socket_messages::kProtocolTcp) == 0;
    uint32_t channel = request.channel;
    if (bluetooth && channel == 0) channel = kChannelBluetooth;

    std::string refusal;
    if (!handshake_complete_) {
      refusal = "控制通道握手还没完成";
    } else if (wants_rfcomm && request.uuid.has_value() && request.uuid->size() != 16) {
      refusal = "RFCOMM 子通道请求里的 uuid 不是 16 字节";
    } else if (!wants_rfcomm && (request.protocol & socket_messages::kProtocolTcp) == 0) {
      refusal = "对端请求的协议里没有 TCP";
    }

    if (refusal.empty()) {
      out.push_back(SocketRequested{outer_type, channel, request});
    } else {
      SocketRequested normalized{outer_type, channel, request};
      auto replies = respond(normalized, socket_messages::kStatusRejected, 0, 0);
      out.insert(out.end(), replies.begin(), replies.end());
      out.push_back(SocketRequestRejected{channel, request.business_id,
                                          std::string(request.tag.begin(), request.tag.end()), refusal});
    }
  }
}

void NearbySession::handle_wifi_link(const std::vector<uint8_t>& payload, std::vector<NearbyAction>& out) {
  const std::vector<Tlv> tlvs = parse_tlvs(payload);
  for (const Tlv& tlv : tlvs) {
    switch (tlv.tag) {
      case kTagWifiPeerMac: {
        const std::optional<std::string> mac = parse_peer_mac(tlv.value);
        if (mac.has_value()) out.push_back(WifiPeerAddress{*mac});
        else out.push_back(WifiPeerBusy{});
        break;
      }
      case kTagWifiDisconnect:
        send(kOuterWifiLink, encode_tlv(kTagWifiDisconnectAck), out);
        out.push_back(WifiDisconnectRequested{});
        break;
      case kTagWifiDisconnectAck:
        out.push_back(WifiDisconnectAnswered{});
        break;
      default:
        out.push_back(UnhandledMessage{kOuterWifiLink, tlv.tag, tlv.value});
        break;
    }
  }
}

std::vector<NearbyAction> NearbySession::respond(const SocketRequested& request, uint32_t status, uint32_t port,
                                                 uint32_t protocol,
                                                 const std::optional<std::vector<uint8_t>>& uuid) {
  socket_messages::Response response;
  response.status = status;
  response.port = port;
  response.channel = request.channel;
  response.business_id = request.request.business_id;
  response.tag = request.request.tag;
  response.protocol = protocol;
  response.uuid = uuid;

  std::vector<NearbyAction> out;
  send(request.outer_type, socket_messages::response_payload(response), out);
  return out;
}

void NearbySession::send(uint32_t outer_type, const std::vector<uint8_t>& payload,
                         std::vector<NearbyAction>& out) {
  if (encrypted_) {
    out.push_back(SendFrame{cipher_.seal(outer_type, payload, next_seed()).encode()});
  } else {
    out.push_back(SendFrame{NearbyFrame::plain(outer_type, payload).encode()});
  }
}

std::vector<uint8_t> NearbySession::next_seed() {
  std::vector<uint8_t> seed(NearbyFrame::kSeedLength);
  for (size_t i = 0; i < seed.size(); i += 8) {
    const uint64_t value = rng_();
    const size_t chunk = std::min<size_t>(8, seed.size() - i);
    for (size_t j = 0; j < chunk; ++j) seed[i + j] = static_cast<uint8_t>(value >> (8 * j));
  }
  return seed;
}

uint32_t NearbySession::next_connect_id() {
  constexpr uint32_t kSpan = channel_management::kConnectIdMax - channel_management::kConnectIdMin + 1;
  return channel_management::kConnectIdMin + static_cast<uint32_t>(rng_() % kSpan);
}

}  // namespace hicar
