#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "common/byte_buffer.h"
#include "common/error.h"
#include "nearby/channel_management.h"
#include "nearby/data_channel.h"
#include "nearby/frame.h"
#include "nearby/session.h"
#include "nearby/tlv.h"
#include "nearby/wifi_connection_info.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<uint8_t> bytes_of(std::initializer_list<uint8_t> list) { return std::vector<uint8_t>(list); }

hicar::NearbyKeyMaterial test_keys() {
  hicar::NearbyKeyMaterial keys;
  keys.const_a = bytes_of({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F});
  keys.const_b = bytes_of({0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                           0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF});
  keys.root_key = bytes_of({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F});
  return keys;
}

std::vector<std::vector<uint8_t>> frames_of(const std::vector<hicar::NearbyAction>& actions) {
  std::vector<std::vector<uint8_t>> out;
  for (const auto& action : actions) {
    if (const auto* send = std::get_if<hicar::SendFrame>(&action)) out.push_back(send->bytes);
  }
  return out;
}

std::optional<hicar::NearbyFrame> decode_first(const std::vector<uint8_t>& wire) {
  hicar::NearbyFrameDecoder decoder;
  decoder.feed(wire);
  return decoder.next();
}

std::vector<uint8_t> phone_frame(const hicar::NearbyFrameCipher& cipher, uint32_t outer,
                                 const std::vector<uint8_t>& payload, bool encrypted) {
  if (!encrypted) return hicar::NearbyFrame::plain(outer, payload).encode();
  return cipher.seal(outer, payload, bytes_of({1, 2, 3, 4, 5, 6, 7, 8})).encode();
}

}  // namespace

int main() {
  using namespace hicar;

  // WiFi 能力解析 + 频率规则
  {
    const std::vector<uint8_t> capability =
        ByteWriter().ea(1).ea(1).ea(2).ea(1).ea(3).ea(1).ea(4).ea(1).ea(7).ea(2412).take();
    const WifiCapability parsed = data_channel::parse_capability(capability);
    check(parsed.can_be_group_owner == std::optional<bool>(true), "组主能力");
    check(parsed.can_be_group_client == std::optional<bool>(true), "组成员能力");
    check(parsed.connected_frequency_mhz == std::optional<uint32_t>(2412), "当前频率");
    check(parsed.can_use(2412), "2.4G 可用");
    const WifiCapability no_5g = data_channel::parse_capability(ByteWriter().ea(3).ea(1).ea(7).ea(2412).take());
    check(!no_5g.can_use(5745), "未声明 5G 时 5G 不可用");
    check(!parsed.can_use(1234), "非信道频率不可用");
  }

  // 连接串往返
  {
    WifiConnectionInfo info;
    info.mode = WifiMode::kHotspot;
    info.phone_ip = "192.168.66.151";
    info.ssid = "My WiFi";
    info.bssid = "AA:BB:CC:DD:EE:FF";
    info.passphrase = "12345678";
    info.frequency_mhz = 2412;
    info.port = 32400;
    info.car_ip = "192.168.66.150";
    const std::string text = info.encode();
    check(text.rfind("192.168.66.151##My WiFi\n", 0) == 0, "连接串前缀");
    check(text.find("##version:3##32400##1##hicarApIp:192.168.66.150") != std::string::npos, "连接串尾部");
    const WifiConnectionInfo back = WifiConnectionInfo::parse(text);
    check(back.ssid == info.ssid && back.bssid == "aa:bb:cc:dd:ee:ff" && back.passphrase == info.passphrase &&
              back.frequency_mhz == 2412 && back.port == 32400 && back.car_ip == info.car_ip,
          "连接串解析");

    check(pick_phone_address("192.168.66.150", {"192.168.66.2"}) == "192.168.66.3", "挑选手机地址");
    check(channel_of_frequency(2412) == std::optional<uint32_t>(1), "2412 -> 信道 1");
    check(frequency_of_channel(149) == std::optional<uint32_t>(5745), "信道 149 -> 5745");
  }

  // 蓝牙控制通道：握手 + 探活 + RFCOMM 子通道 + 数据通道 + WiFi 组网
  {
    NearbySession session(HostIdentity{}, test_keys(), std::optional<std::array<uint8_t, 6>>{}, NearbyLink::kBluetooth,
                          0x99);
    const NearbyFrameCipher phone_cipher(test_keys());
    session.start(0);

    // 握手（不带 tag7）
    session.feed(phone_frame(phone_cipher, 0, encode_tlv(1, bytes_of({5, 0})), false));
    session.feed(phone_frame(phone_cipher, 0, encode_tlv(3, bytes_of({'A', 'B', 'C', 0})), false));
    const auto last = session.feed(phone_frame(phone_cipher, 0, encode_tlv(5, bytes_of({1})), false));
    const auto frames = frames_of(last);
    check(frames.size() == 1, "蓝牙通道开加密后只回一帧（不发 tag7）");
    check(session.handshake_complete(), "蓝牙握手完成");

    // 消息层探活
    const auto probe = session.feed(phone_frame(phone_cipher, 2, encode_tlv(1), true));
    check(frames_of(probe).size() == 1, "探活应有应答");
    const auto probe_frame = decode_first(frames_of(probe)[0]);
    check(probe_frame.has_value(), "探活帧可解");
    const auto probe_tlvs = parse_tlvs(phone_cipher.open(*probe_frame));
    check(probe_tlvs.size() == 1 && probe_tlvs[0].tag == 2 && probe_tlvs[0].value.empty(), "探活应答 tag 2 空值");

    // RFCOMM 子通道请求（业务 19，协议 0）
    socket_messages::Request rfcomm;
    rfcomm.channel = 0;
    rfcomm.business_id = NearbySession::kBusinessAuth;
    rfcomm.tag = {'h', 'i', 'c', 'a', 'r', 'A', 'u', 't', 'h'};
    rfcomm.protocol = 0;
    const auto rfcomm_actions = session.feed(phone_frame(
        phone_cipher, socket_messages::kOuterMessage,
        encode_tlv(socket_messages::kCmdCreateRequest, socket_messages::encode_request(rfcomm)), true));
    std::optional<SocketRequested> requested;
    for (const auto& a : rfcomm_actions) {
      if (const auto* r = std::get_if<SocketRequested>(&a)) requested = *r;
    }
    check(requested.has_value() && requested->channel == NearbySession::kChannelBluetooth, "RFCOMM 请求通道归一为 2");
    const auto accepted = session.accept_rfcomm_socket(*requested, 9);
    const auto accepted_frame = decode_first(frames_of(accepted)[0]);
    check(accepted_frame.has_value(), "RFCOMM 应答可解");
    const auto response_tlvs = parse_tlvs(phone_cipher.open(*accepted_frame));
    const auto response = socket_messages::parse_response(response_tlvs[0].value);
    check(response.status == 0 && response.port == 9 && response.protocol == 0, "RFCOMM 应答字段");
    check(response.uuid.has_value() && response.uuid->size() == 16 && (*response.uuid)[2] == 0xFE &&
              (*response.uuid)[3] == 0x36,
          "RFCOMM 应答带默认 FE36 UUID");

    // 数据通道协商
    const std::vector<uint8_t> request_value =
        ByteWriter().ea(3).raw(encode_tlv(3, ByteWriter().ea(1).ea(1).ea(4).ea(1).ea(7).ea(2412).take())).take();
    const auto data_actions = session.feed(phone_frame(
        phone_cipher, socket_messages::kOuterResource, encode_tlv(data_channel::kCommandRequest, request_value), true));
    std::optional<DataChannelRequested> channel_request;
    for (const auto& a : data_actions) {
      if (const auto* r = std::get_if<DataChannelRequested>(&a)) channel_request = *r;
    }
    check(channel_request.has_value() && channel_request->data_channel == 3, "数据通道请求");

    const auto data_reply = session.accept_data_channel(*channel_request, 2412);
    const auto data_frame = decode_first(frames_of(data_reply)[0]);
    const auto data_tlvs = parse_tlvs(phone_cipher.open(*data_frame));
    check(data_tlvs.size() == 1 && data_tlvs[0].tag == data_channel::kCommandResponse, "数据通道应答 tag 2");
    ByteReader value_reader(data_tlvs[0].value);
    check(value_reader.ea() == 3 && value_reader.ea() == data_channel::kResultOk, "数据通道应答通道号与结果");
    const auto detail_tlvs = parse_tlvs(value_reader.rest());
    ByteReader detail(detail_tlvs[0].value);
    check(detail.u8() == data_channel::kRoleGroupOwner && detail.ea() == 2412, "角色与频率");

    // WiFi 组网层：要 MAC
    const auto mac_request = session.request_wifi_peer_address();
    const auto mac_frame = decode_first(frames_of(mac_request)[0]);
    check(mac_frame.has_value() && mac_frame->outer_type() == 33, "组网层外层类型 33");
    const auto mac_tlvs = parse_tlvs(phone_cipher.open(*mac_frame));
    check(mac_tlvs.size() == 1 && mac_tlvs[0].tag == 1, "要 MAC 用 tag 1");

    const auto mac_reply = session.feed(phone_frame(
        phone_cipher, 33, encode_tlv(2, std::vector<uint8_t>{'A', 'A', ':', 'B', 'B', ':', 'C', 'C', ':', 'D', 'D', ':',
                                                              'E', 'E', ':', 'F', 'F'}),
        true));
    bool got_mac = false;
    for (const auto& a : mac_reply) {
      if (const auto* m = std::get_if<WifiPeerAddress>(&a)) {
        got_mac = m->mac == "aa:bb:cc:dd:ee:ff";
      }
    }
    check(got_mac, "手机 MAC 解析");

    // 下发连接串
    WifiConnectionInfo info;
    info.phone_ip = "192.168.66.151";
    info.ssid = "MyWiFi";
    info.bssid = "aa:bb:cc:dd:ee:ff";
    info.passphrase = "12345678";
    info.frequency_mhz = 2412;
    info.port = 32400;
    info.car_ip = "192.168.66.150";
    const auto info_actions = session.send_wifi_connection_info(info);
    const auto info_frame = decode_first(frames_of(info_actions)[0]);
    const auto info_tlvs = parse_tlvs(phone_cipher.open(*info_frame));
    check(info_tlvs.size() == 1 && info_tlvs[0].tag == 3, "连接串用 tag 3");
    std::string text(info_tlvs[0].value.begin(), info_tlvs[0].value.end());
    check(WifiConnectionInfo::parse(text).port == 32400, "连接串内容可解析");
    check(!session.next_tick_at().has_value(), "握手完成后无定时");
  }

  if (g_failures == 0) {
    std::puts("ALL PASSED");
    return 0;
  }
  std::fprintf(stderr, "%d 项失败\n", g_failures);
  return 1;
}
