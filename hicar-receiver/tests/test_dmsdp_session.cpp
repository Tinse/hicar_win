#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <variant>
#include <vector>

#include "auth/crypto.h"
#include "common/byte_buffer.h"
#include "common/error.h"
#include "dmsdp/cipher.h"
#include "dmsdp/framing.h"
#include "dmsdp/message.h"
#include "dmsdp/session.h"

namespace {
int g_failures = 0;
void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

const std::array<uint8_t, 16> kKey = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

std::vector<uint8_t> bytes_of(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::vector<uint8_t> ea(uint32_t value) {
  hicar::ByteWriter writer;
  writer.ea(value);
  return writer.take();
}

std::vector<uint8_t> encrypted_record(uint32_t module, int32_t type, const std::vector<uint8_t>& data) {
  const auto record = hicar::dmsdp::encode_device_record(module, type, data);
  const uint8_t iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  return hicar::dmsdp::encode_control_frame(
      hicar::dmsdp::kControlEncrypted,
      hicar::dmsdp::seal_control_payload(kKey.data(), iv, record));
}

std::string first_send(const std::vector<hicar::dmsdp::DmsdpOutput>& outputs, bool* found) {
  *found = false;
  for (const auto& output : outputs) {
    if (const auto* action = std::get_if<hicar::dmsdp::DmsdpAction>(&output)) {
      if (action->kind == hicar::dmsdp::DmsdpAction::Kind::kSend) {
        *found = true;
        return std::string(action->bytes.begin(), action->bytes.end());
      }
    }
  }
  return {};
}

bool has_event(const std::vector<hicar::dmsdp::DmsdpOutput>& outputs,
               hicar::dmsdp::DmsdpEvent::Kind kind) {
  for (const auto& output : outputs) {
    if (const auto* event = std::get_if<hicar::dmsdp::DmsdpEvent>(&output)) {
      if (event->kind == kind) return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  using namespace hicar;
  using namespace hicar::dmsdp;

  // 文本消息
  {
    const auto raw = encode_dmsdp_message("SET_PARAMETER * DMSDP/1.0",
                                          {{"CSeq", "7"}, {"Content-Length", "3"}}, bytes_of("abc"));
    const auto message = parse_dmsdp_message(raw);
    check(message.start_line == "SET_PARAMETER * DMSDP/1.0", "首行");
    check(message.header("cseq") != nullptr && *message.header("cseq") == "7", "头部不区分大小写");
    check(message.body == bytes_of("abc"), "正文");
    check(content_length_matches(message), "Content-Length 匹配");
    check(!message.is_response(), "请求不是响应");
  }
  {
    const auto message = parse_dmsdp_message(bytes_of("DMSDP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"));
    check(message.is_response(), "响应");
    check(message.status_code() == 200, "状态码");
  }

  DmsdpConfig config;
  config.device_id = std::string(64, 'A');
  config.device_name = "HiCar-Windows";
  config.bluetooth_mac = "2C:0D:A7:3C:B1:3E";
  config.local_ip = "192.168.66.150";
  config.phone_ip = "192.168.66.101";
  config.full_model = "00048000";
  DmsdpDisplay display;
  display.width = 1280;
  display.height = 720;
  display.video_width = 1280;
  display.video_height = 720;
  display.dpi = 160;
  display.fps = 30;
  display.density = 1.5;
  config.display = display;

  auth::SequenceRandom random("dmsdp-test");
  DmsdpSession session(config, kKey, &random);
  uint64_t now = 1000;

  // 业务 20 首轮协商
  {
    std::vector<uint8_t> payload(16, 0);
    const auto frame = encode_session_frame(kSessionModule, payload);
    const auto outputs = session.feed(DmsdpChannel::kSession, frame.data(), frame.size(), now);
    bool open = false;
    for (const auto& output : outputs) {
      if (const auto* action = std::get_if<DmsdpAction>(&output)) {
        if (action->kind == DmsdpAction::Kind::kOpenControlListener) open = true;
      }
    }
    check(open, "请求开控制监听");
  }
  {
    const auto outputs = session.control_listener_ready(40000, now);
    bool sent = false;
    const auto text = first_send(outputs, &sent);
    check(sent, "回协商应答");
    SessionFrameDecoder decoder;
    decoder.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    const auto frame = decoder.next();
    check(frame.has_value() && frame->payload.size() == 16, "协商应答帧");
    check(frame->payload[1] == 0x9C && frame->payload[2] == 0x40, "端口 40000");
  }

  // 控制连接建立 → 明文 OPTIONS
  {
    const auto outputs = session.on_connected(DmsdpChannel::kControl, now);
    bool sent = false;
    const auto text = first_send(outputs, &sent);
    check(sent, "控制连接发 OPTIONS");
    ControlFrameDecoder decoder;
    decoder.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    const auto frame = decoder.next();
    check(frame.has_value() && !frame->encrypted, "OPTIONS 明文");
    const auto message = parse_dmsdp_message(frame->payload);
    check(message.method() == std::optional<std::string>("OPTIONS"), "OPTIONS 方法");
    check(message.header("CryptoAbility") != nullptr && *message.header("CryptoAbility") == "222",
          "CryptoAbility");
  }

  // 手机选择加密
  {
    const auto selection = encode_dmsdp_message(
        "SET_PARAMETER * DMSDP/1.0",
        {{"CSeq", "1"}, {"CryptoVer", "1"}, {"CryptoSwitch", "222"}, {"CryptoAlg", "aes128-ctr"},
         {"UdpKA", "0"}});
    const auto frame = encode_control_frame(kControlPlain, selection);
    const auto outputs = session.feed(DmsdpChannel::kControl, frame.data(), frame.size(), now);
    bool sent = false;
    const auto text = first_send(outputs, &sent);
    check(sent && session.encrypted(), "加密应答并切换");
    ControlFrameDecoder decoder;
    decoder.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    const auto reply = decoder.next();
    check(reply.has_value() && !reply->encrypted, "加密应答仍是明文");
    check(has_event(outputs, DmsdpEvent::Kind::kEncryptionEnabled), "EncryptionEnabled 事件");
  }

  // 设备信息 101
  {
    std::vector<uint8_t> data = ea(101);
    const auto json = bytes_of("{\"deviceId\":\"PHONEID\",\"deviceType\":2,\"properties\":{}}");
    data.insert(data.end(), json.begin(), json.end());
    const auto frame = encrypted_record(3, -1, data);
    const auto outputs = session.feed(DmsdpChannel::kControl, frame.data(), frame.size(), now);
    bool sent = false;
    const auto text = first_send(outputs, &sent);
    check(sent, "回本机 101");
    check(has_event(outputs, DmsdpEvent::Kind::kPeerDeviceInfo), "PeerDeviceInfo");

    ControlFrameDecoder decoder;
    decoder.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    const auto reply = decoder.next();
    check(reply.has_value() && reply->encrypted, "本机 101 加密");
    const auto plain = open_control_payload(kKey.data(), reply->payload);
    const auto records = parse_device_records(plain);
    check(records.size() == 1 && records[0].module == 3 && records[0].type == -1, "101 记录");
    check(!records[0].data.empty() && records[0].data[0] == 0xE5, "101 EA");
  }

  // 服务请求 104 → 显示服务 102
  {
    std::vector<uint8_t> data = ea(104);
    ByteWriter writer;
    writer.u32be(8);
    data.insert(data.end(), writer.data().begin(), writer.data().end());
    const auto frame = encrypted_record(3, -1, data);
    const auto outputs = session.feed(DmsdpChannel::kControl, frame.data(), frame.size(), now);
    check(has_event(outputs, DmsdpEvent::Kind::kServicesRequested), "ServicesRequested");

    bool sent = false;
    const auto text = first_send(outputs, &sent);
    ControlFrameDecoder decoder;
    decoder.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    const auto reply = decoder.next();
    check(sent && reply.has_value() && reply->encrypted, "服务 102 加密");
    const auto plain = open_control_payload(kKey.data(), reply->payload);
    const auto records = parse_device_records(plain);
    check(records.size() == 1 && records[0].data[0] == 0xE6, "102 EA");
    const std::string json(records[0].data.begin() + 1, records[0].data.end());
    check(json.find("\"serviceId\":\"display1\"") != std::string::npos, "display1");
    check(json.find("\"4001\":1.5") != std::string::npos, "density");
  }

  // 显示端口
  {
    std::vector<uint8_t> data = ea(101);
    const auto port = ea(40000);
    data.insert(data.end(), port.begin(), port.end());
    const auto frame = encrypted_record(5, -1, data);
    const auto outputs = session.feed(DmsdpChannel::kControl, frame.data(), frame.size(), now);
    bool announced = false;
    for (const auto& output : outputs) {
      if (const auto* event = std::get_if<DmsdpEvent>(&output)) {
        if (event->kind == DmsdpEvent::Kind::kDisplayPortAnnounced && event->number == 40000) {
          announced = true;
        }
      }
    }
    check(announced, "DisplayPortAnnounced 40000");
  }

  // 保活：手机先发一个 GET_PARAMETER，之后本机才主动发
  {
    const auto get = encode_dmsdp_message("GET_PARAMETER * DMSDP/1.0", {{"CSeq", "2"}});
    const uint8_t iv[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    const auto frame = encode_control_frame(
        kControlEncrypted, seal_control_payload(kKey.data(), iv, get));
    (void)session.feed(DmsdpChannel::kControl, frame.data(), frame.size(), now);

    check(session.next_tick_at().has_value(), "有定时任务");
    const auto outputs = session.on_tick(now + 1000);
    bool sent = false;
    const auto text = first_send(outputs, &sent);
    check(sent, "保活 GET_PARAMETER");
    ControlFrameDecoder decoder;
    decoder.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    const auto reply = decoder.next();
    check(reply.has_value() && reply->encrypted, "保活加密");
    if (reply.has_value()) {
      const auto plain = open_control_payload(kKey.data(), reply->payload);
      const auto message = parse_dmsdp_message(plain);
      check(message.start_line == "GET_PARAMETER * DMSDP/1.0", "保活首行");
    }
  }

  // 明文阶段的设备记录必须拒绝
  {
    DmsdpConfig cfg = config;
    auth::SequenceRandom rng2("another");
    DmsdpSession fresh(cfg, kKey, &rng2);
    const auto frame = encrypted_record(3, -1, {0xE5});
    bool threw = false;
    try {
      (void)fresh.feed(DmsdpChannel::kControl, frame.data(), frame.size(), now);
    } catch (const std::logic_error&) {
      threw = true;
    } catch (const MalformedMessage&) {
      threw = true;
    }
    check(threw, "未连接控制通道时拒绝数据");
  }

  if (g_failures == 0) {
    std::puts("dmsdp session: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "dmsdp session: %d failure(s)\n", g_failures);
  return 1;
}
