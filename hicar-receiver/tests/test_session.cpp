#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "common/error.h"
#include "nearby/cipher.h"
#include "nearby/channel_management.h"
#include "nearby/frame.h"
#include "nearby/session.h"
#include "nearby/socket_messages.h"
#include "nearby/tlv.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<uint8_t> bytes_of(std::initializer_list<uint8_t> list) { return std::vector<uint8_t>(list); }

std::vector<std::vector<uint8_t>> frames_of(const std::vector<hicar::NearbyAction>& actions) {
  std::vector<std::vector<uint8_t>> out;
  for (const auto& action : actions) {
    if (const auto* send = std::get_if<hicar::SendFrame>(&action)) out.push_back(send->bytes);
  }
  return out;
}

std::optional<hicar::NearbyFrame> only_frame(const std::vector<hicar::NearbyAction>& actions) {
  const auto frames = frames_of(actions);
  if (frames.size() != 1) return std::nullopt;
  hicar::NearbyFrameDecoder decoder;
  decoder.feed(frames[0]);
  return decoder.next();
}

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

// 手机侧：把载荷封装成明文或加密帧。
std::vector<uint8_t> phone_frame(const hicar::NearbyFrameCipher& cipher, uint32_t outer_type,
                                 const std::vector<uint8_t>& payload, bool encrypted) {
  if (!encrypted) return hicar::NearbyFrame::plain(outer_type, payload).encode();
  return cipher.seal(outer_type, payload, bytes_of({1, 2, 3, 4, 5, 6, 7, 8})).encode();
}

}  // namespace

int main() {
  using namespace hicar;

  const NearbyKeyMaterial keys = test_keys();
  const NearbyFrameCipher phone_cipher(keys);
  const std::array<uint8_t, 6> bt = {0x02, 0x12, 0x34, 0x56, 0x78, 0x9A};

  NearbySession session(HostIdentity{}, keys, bt, NearbyLink::kUsb, 0x1234);

  // 建连：先发 connectId
  {
    const auto actions = session.start(1000);
    check(session.next_tick_at() == std::optional<uint64_t>(6000), "握手超时应为 5000ms 后");
    const auto frame = only_frame(actions);
    check(frame.has_value() && frame->outer_type() == 0 && !frame->is_encrypted(), "connectId 应为明文章节帧");
    const auto tlvs = parse_tlvs(frame->payload());
    check(tlvs.size() == 1 && tlvs[0].tag == channel_management::kTagConnectId, "首帧只带 tag 15");
    check(tlvs[0].value.size() == 6, "connectId 为 6 位十进制");
  }

  // 握手：版本、摘要、加密开关
  {
    const auto v = session.feed(phone_frame(phone_cipher, 0,
                                            encode_tlv(channel_management::kTagVersionRequest,
                                                       bytes_of({0x05, 0x00})),
                                            false));
    const auto frame = only_frame(v);
    check(frame.has_value() && !frame->is_encrypted(), "版本应答应为明文");
    const auto tlvs = parse_tlvs(frame->payload());
    check(tlvs.size() == 1 && tlvs[0].tag == channel_management::kTagVersionResponse &&
              tlvs[0].value == bytes_of({0x02}),
          "车机版本固定回 2");

    std::vector<uint8_t> summary_text = bytes_of({'A', '1', 'B', '2', 'C', '3', 'D', '4', 'E', '5', 'F', '6'});
    summary_text.push_back(0);
    const auto s = session.feed(phone_frame(phone_cipher, 0,
                                            encode_tlv(channel_management::kTagSummaryRequest, summary_text), false));
    const auto sframe = only_frame(s);
    check(sframe.has_value(), "摘要应答应有一帧");
    const auto stlvs = parse_tlvs(sframe->payload());
    check(stlvs.size() == 1 && stlvs[0].tag == channel_management::kTagSummaryResponse, "摘要应答 tag 4");
    check(std::string(stlvs[0].value.begin(), stlvs[0].value.end()) == session.device_id(),
          "摘要应答应回本机 deviceId");

    // 开加密：本帧的应答立即用加密发出，另外先发一帧 tag 7
    const auto e = session.feed(phone_frame(phone_cipher, 0,
                                            encode_tlv(channel_management::kTagEncryptionRequest, bytes_of({1})), false));
    check(session.encrypted(), "加密开关应生效");
    const auto eframes = frames_of(e);
    check(eframes.size() == 2, "加密开关应答应有两帧（tag7 + 应答）");

    NearbyFrameDecoder decoder;
    decoder.feed(eframes[0]);
    const auto bluetooth_frame = decoder.next();
    check(bluetooth_frame.has_value() && bluetooth_frame->is_encrypted(), "tag7 帧应加密");
    const auto btlvs = parse_tlvs(phone_cipher.open(*bluetooth_frame));
    check(btlvs.size() == 1 && btlvs[0].tag == channel_management::kTagBluetoothRequest, "应主动发 tag 7");
    check(std::string(btlvs[0].value.begin(), btlvs[0].value.end()) == session.bluetooth_address_text(),
          "tag 7 应带本机蓝牙地址");

    NearbyFrameDecoder decoder2;
    decoder2.feed(eframes[1]);
    const auto reply = decoder2.next();
    check(reply.has_value() && reply->is_encrypted(), "加密开关的应答应加密");
    const auto etlvs = parse_tlvs(phone_cipher.open(*reply));
    check(etlvs.size() == 1 && etlvs[0].tag == channel_management::kTagEncryptionResponse &&
              etlvs[0].value == bytes_of({0x01}),
          "加密开关应答 tag 6 值 1");

    bool completed = false;
    for (const auto& a : e) {
      if (const auto* c = std::get_if<HandshakeCompleted>(&a)) {
        completed = true;
        check(c->peer_version == 5 && c->encrypted, "握手完成事件内容");
        check(c->peer_summary.has_value() && *c->peer_summary == "A1B2C3D4E5F6", "对端摘要");
      }
    }
    check(completed, "应给出握手完成事件");
    check(!session.next_tick_at().has_value(), "握手完成后不再计时");
    check(session.handshake_complete(), "握手状态");
  }

  // 手机请求认证 socket（业务 19）
  {
    socket_messages::Request req;
    req.channel = NearbySession::kChannelUsb;
    req.business_id = NearbySession::kBusinessAuth;
    req.tag.assign({'h', 'i', 'c', 'a', 'r', 'A', 'u', 't', 'h'});
    req.protocol = socket_messages::kProtocolTcp;
    const auto payload = encode_tlv(socket_messages::kCmdCreateRequest, socket_messages::encode_request(req));
    const auto actions = session.feed(phone_frame(phone_cipher, socket_messages::kOuterResource, payload, true));

    std::optional<SocketRequested> requested;
    for (const auto& a : actions) {
      if (const auto* r = std::get_if<SocketRequested>(&a)) requested = *r;
    }
    check(requested.has_value(), "应给出 SocketRequested");
    check(requested && requested->outer_type == socket_messages::kOuterResource &&
              requested->channel == NearbySession::kChannelUsb &&
              requested->request.business_id == NearbySession::kBusinessAuth &&
              requested->request.protocol == socket_messages::kProtocolTcp,
          "请求字段");

    const auto accepted = session.accept_socket(*requested, 32401);
    const auto frame = only_frame(accepted);
    check(frame.has_value() && frame->is_encrypted(), "应答应加密");
    const auto tlvs = parse_tlvs(phone_cipher.open(*frame));
    check(tlvs.size() == 1 && tlvs[0].tag == socket_messages::kCmdCreateResponse, "应答 tag 4");
    const auto response = socket_messages::parse_response(tlvs[0].value);
    check(response.status == socket_messages::kStatusAccepted && response.port == 32401 &&
              response.channel == NearbySession::kChannelUsb &&
              response.business_id == NearbySession::kBusinessAuth &&
              response.protocol == socket_messages::kProtocolTcp,
          "应答字段");
    check(std::string(response.tag.begin(), response.tag.end()) == "hicarAuth", "应答标签照抄");
  }

  // 拒绝未知业务
  {
    socket_messages::Request req;
    req.channel = NearbySession::kChannelUsb;
    req.business_id = 99;
    req.tag.assign({'x'});
    req.protocol = socket_messages::kProtocolTcp;
    const auto actions = session.feed(phone_frame(
        phone_cipher, socket_messages::kOuterMessage,
        encode_tlv(socket_messages::kCmdCreateRequest, socket_messages::encode_request(req)), true));
    std::optional<SocketRequested> requested;
    for (const auto& a : actions) {
      if (const auto* r = std::get_if<SocketRequested>(&a)) requested = *r;
    }
    check(requested.has_value(), "未知业务也应先交出请求，由上层决定拒绝");
    const auto rejected = session.reject_socket(*requested);
    const auto frame = only_frame(rejected);
    check(frame.has_value(), "拒绝应答应有一帧");
    const auto tlvs = parse_tlvs(phone_cipher.open(*frame));
    const auto response = socket_messages::parse_response(tlvs[0].value);
    check(response.status == socket_messages::kStatusRejected && response.port == 0 && response.protocol == 0,
          "拒绝字段");
  }

  // 握手超时
  {
    NearbySession timeout_session(HostIdentity{}, keys, bt, NearbyLink::kUsb, 7);
    timeout_session.start(0);
    check(timeout_session.on_tick(4999).empty(), "未到点不应超时");
    const auto actions = timeout_session.on_tick(5000);
    check(actions.size() == 1 && std::get_if<HandshakeTimedOut>(&actions[0]) != nullptr, "到点应超时");
    check(timeout_session.closed(), "超时后会话作废");
    check(timeout_session.feed(bytes_of({0x7F})).empty(), "作废后 feed 应无动作");
  }

  if (g_failures == 0) {
    std::puts("ALL PASSED");
    return 0;
  }
  std::fprintf(stderr, "%d 项失败\n", g_failures);
  return 1;
}
