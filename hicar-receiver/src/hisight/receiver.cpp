#include "hisight/receiver.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <random>
#include <stdexcept>

#include "dmsdp/cipher.h"

namespace hicar {
namespace hisight {
namespace {

void fail(const std::string& message) { throw std::runtime_error(message); }

std::vector<std::string> split(const std::string& text, char delimiter) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (true) {
    const size_t at = text.find(delimiter, start);
    if (at == std::string::npos) {
      parts.push_back(text.substr(start));
      break;
    }
    parts.push_back(text.substr(start, at - start));
    start = at + 1;
  }
  return parts;
}

}  // namespace

HisightReceiver::HisightReceiver(std::array<uint8_t, 16> session_key, HisightConfig config,
                                 AccessUnitSink video_sink)
    : key_(session_key),
      config_(config),
      video_sink_(std::move(video_sink)),
      capabilities_(config),
      video_(session_key, [this](const AccessUnit& unit) {
        if (video_sink_) video_sink_(unit);
      }) {}

HsAction HisightReceiver::make_send(HsChannel channel, std::vector<uint8_t> bytes) const {
  HsAction action;
  action.kind = HsAction::Kind::kSend;
  action.channel = channel;
  action.bytes = std::move(bytes);
  return action;
}

std::vector<uint8_t> HisightReceiver::send_control_bytes(const std::vector<uint8_t>& plain) {
  std::vector<uint8_t> payload = plain;
  if (crypto_ready_) {
    std::array<uint8_t, 16> iv{};
    std::random_device device;
    for (auto& byte : iv) byte = static_cast<uint8_t>(device());
    const auto cipher = dmsdp::aes128_ctr_crypt(key_.data(), iv.data(), plain.data(), plain.size());
    payload.resize(16 + cipher.size());
    std::copy(iv.begin(), iv.end(), payload.begin());
    std::copy(cipher.begin(), cipher.end(), payload.begin() + 16);
  }
  return encode_control_frame(payload);
}

HsAction HisightReceiver::send_control(const std::vector<uint8_t>& plain) const {
  HsAction action;
  action.kind = HsAction::Kind::kSend;
  action.channel = HsChannel::kControl;
  // const 方法里做加密：用 mutable 局部复制密钥。
  std::vector<uint8_t> payload = plain;
  if (crypto_ready_) {
    std::array<uint8_t, 16> iv{};
    std::random_device device;
    for (auto& byte : iv) byte = static_cast<uint8_t>(device());
    const auto cipher = dmsdp::aes128_ctr_crypt(key_.data(), iv.data(), plain.data(), plain.size());
    payload.resize(16 + cipher.size());
    std::copy(iv.begin(), iv.end(), payload.begin());
    std::copy(cipher.begin(), cipher.end(), payload.begin() + 16);
  }
  action.bytes = encode_control_frame(payload);
  return action;
}

std::vector<HsAction> HisightReceiver::start(uint64_t wall_clock_millis) {
  (void)wall_clock_millis;
  if (started_) fail("start() 只能调用一次");
  started_ = true;
  if (ended_) return {};
  last_cseq_ = 1;
  pending_[1] = "ANNOUNCE";
  return {send_control(rtsp_announce())};
}

std::vector<HsAction> HisightReceiver::feed_control(const uint8_t* data, size_t size,
                                                    uint64_t wall_clock_millis) {
  if (!started_) fail("先调用 start()");
  if (ended_ || failed_) return {};
  std::vector<HsAction> out;
  try {
    decoder_.append(data, size);
    while (!ended_) {
      std::vector<uint8_t> payload;
      if (!decoder_.next(&payload)) break;
      std::vector<uint8_t> plain = payload;
      if (crypto_ready_) {
        if (payload.size() < 16) fail("加密单元不足 16 字节，缺少 IV");
        const auto decrypted = dmsdp::aes128_ctr_crypt(key_.data(), payload.data(), payload.data() + 16,
                                                        payload.size() - 16);
        plain.assign(decrypted.begin(), decrypted.end());
      }
      const auto parsed = parse_rtsp(plain);
      std::fprintf(stderr, "[HiSight RX] %s | CSeq=%d | CT=%s | body=%u\n", parsed.first_line.c_str(),
                   parsed.cseq, parsed.header("content-type").value_or("<none>").c_str(),
                   static_cast<unsigned>(parsed.body.size()));
      const auto actions = handle(parsed, wall_clock_millis);
      out.insert(out.end(), actions.begin(), actions.end());
    }
  } catch (...) {
    failed_ = true;
    carry_over_.insert(carry_over_.end(), out.begin(), out.end());
    throw;
  }
  return out;
}

std::vector<HsAction> HisightReceiver::handle(const RtspMessage& message, uint64_t wall_clock_millis) {
  if (message.is_response()) return handle_response(message);
  const std::string method = request_method(message.first_line);
  if (method == "ANNOUNCE") return handle_announce(message, wall_clock_millis);
  if (method == "OPTIONS") return handle_options(message, wall_clock_millis);
  if (method == "GET_PARAMETER") return handle_get_parameter(message);
  if (method == "SET_PARAMETER") return handle_set_parameter(message, wall_clock_millis);
  fail("收到未实现的控制请求");
}

std::vector<HsAction> HisightReceiver::handle_response(const RtspMessage& message) {
  if (message.first_line != "RTSP/1.0 200 OK" || !message.body.empty()) fail("手机应答不是空正文的 200");
  const auto it = pending_.find(message.cseq);
  if (it == pending_.end()) fail("手机应答的 CSeq 对不上待应答请求");
  const std::string pending = it->second;
  pending_.erase(it);
  if (pending == "ANNOUNCE") return {};  // 车机发出的加密协商，手机回 200 OK 即可
  if (pending == "SETUP") return handle_setup_response(message);
  if (pending == "PLAY") {
    HsAction action;
    action.kind = HsAction::Kind::kPlayAccepted;
    return {action};
  }
  if (pending == "OPTIONS") return {};
  fail("手机应答对应的请求未知");
}

std::vector<HsAction> HisightReceiver::handle_announce(const RtspMessage& message,
                                                      uint64_t wall_clock_millis) {
  if (crypto_ready_) fail("ANNOUNCE 重复");
  // HarmonyOS 7 会在车机 ANNOUNCE 的 200 之后，再发一个无正文的空 ANNOUNCE 探针；
  // 这是合法握手的一部分，只回 200，不当作加密选择。
  if (message.body.empty()) {
    std::vector<HsAction> out;
    out.push_back(send_control(rtsp_ok(message.cseq, rtsp_date(wall_clock_millis))));
    // HarmonyOS 7 的空 ANNOUNCE 等价于“接受车机声明的 aes128ctr”，应答后立即切加密。
    crypto_ready_ = true;
    return out;
  }
  if (!message.is_text_parameters()) fail("ANNOUNCE 类型不是 text/parameters");
  const std::string text(message.body.begin(), message.body.end());
  if (text.size() < 2 || text.compare(text.size() - 2, 2, "\r\n") != 0) fail("加密选择必须是单独一行");
  size_t crlf = text.find("\r\n");
  if (crlf + 2 != text.size()) fail("加密选择必须是单独一行");
  const std::string line = text.substr(0, crlf);
  const size_t colon = line.find(':');
  if (colon == std::string::npos || line.substr(0, colon) != "encrypt_description") {
    fail("加密选择缺少 encrypt_description");
  }
  std::map<std::string, std::string> fields;
  for (const auto& item : split(trim_space_tab(line.substr(colon + 1)), ';')) {
    const size_t eq = item.find('=');
    if (eq == std::string::npos) fail("加密选择字段缺失");
    const std::string name = item.substr(0, eq);
    if (fields.count(name) != 0) fail("加密选择字段重复");
    fields[name] = item.substr(eq + 1);
  }
  if (fields.size() != 2 || fields.count("encrypt_list") == 0 || fields.count("version") == 0) {
    fail("加密选择字段不完整");
  }
  std::string list = fields["encrypt_list"];
  for (char& c : list) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (list != "aes128ctr" || fields["version"] != "1") fail("只支持 aes128ctr / version 1");

  std::vector<HsAction> out;
  out.push_back(send_control(rtsp_ok(message.cseq, rtsp_date(wall_clock_millis))));
  crypto_ready_ = true;
  return out;
}

std::vector<HsAction> HisightReceiver::handle_options(const RtspMessage& message,
                                                    uint64_t wall_clock_millis) {
  if (!crypto_ready_ || !message.body.empty() || options_received_) {
    fail("OPTIONS 早于加密协商、带正文或重复");
  }
  const std::string date = rtsp_date(wall_clock_millis);
  std::vector<HsAction> out;
  out.push_back(send_control(rtsp_ok(message.cseq, date, true)));
  const int cseq = next_cseq();
  out.push_back(send_control(rtsp_options(cseq, date)));
  pending_[cseq] = "OPTIONS";
  options_received_ = true;
  return out;
}

void HisightReceiver::require_negotiation_ready(const RtspMessage& message) const {
  if (!crypto_ready_ || !options_received_) fail("能力请求早于加密与 OPTIONS 协商");
  if (!message.body.empty() && !message.is_text_parameters()) fail("能力正文缺少 text/parameters 类型");
}

std::vector<HsAction> HisightReceiver::handle_get_parameter(const RtspMessage& message) {
  require_negotiation_ready(message);
  return {send_control(rtsp_get_parameter_ok(message.cseq, capabilities_.response_body(message.body)))};
}

std::vector<HsAction> HisightReceiver::handle_set_parameter(const RtspMessage& message,
                                                           uint64_t wall_clock_millis) {
  const auto fields = parameter_values(message.body);
  const auto trigger_it = fields.find("his_trigger_method");
  const std::string trigger = trigger_it == fields.end() ? "" : trigger_it->second;
  if (trigger == "TEARDOWN") {
    if (!crypto_ready_) fail("结束触发早于加密协商");
    if (!message.is_text_parameters() || fields.size() != 1) fail("结束触发必须是单独的正文");
    std::vector<HsAction> out;
    out.push_back(send_control(rtsp_ok(message.cseq, rtsp_date(wall_clock_millis))));
    terminate(HsEndReason::kPeerTeardown, &out, true, true);
    return out;
  }
  require_negotiation_ready(message);
  if (trigger.empty()) {
    if (setup_.has_value()) fail("SETUP 之后不支持重新协商能力");
    capabilities_.select(fields);
    return {send_control(rtsp_ok(message.cseq, rtsp_date(wall_clock_millis)))};
  }
  if (trigger != "SETUP" || fields.size() != 1) fail("只支持单独的 SETUP 触发");
  if (setup_.has_value()) fail("重复的 SETUP 触发");
  if (!capabilities_.selection().has_value()) fail("SETUP 前缺少视频参数选择");
  std::vector<HsAction> out;
  out.push_back(send_control(rtsp_ok(message.cseq, rtsp_date(wall_clock_millis))));
  const int cseq = next_cseq();
  out.push_back(send_control(rtsp_setup(cseq)));
  pending_[cseq] = "SETUP";
  return out;
}

std::vector<HsAction> HisightReceiver::handle_setup_response(const RtspMessage& message) {
  const auto transport = message.header("transport");
  if (!transport.has_value()) fail("SETUP 应答缺少 Transport");
  const auto ports = parse_transport(*transport);
  MediaSetup media = capabilities_.media_setup(ports.server_port, ports.remote_control_port);
  setup_ = media;
  if (!media.input_events.empty() || !media.input_vendors.empty()) {
    std::set<std::string> events(media.input_events.begin(), media.input_events.end());
    std::set<std::string> vendors(media.input_vendors.begin(), media.input_vendors.end());
    encoder_ = std::make_unique<UibcEncoder>(key_, std::move(events), std::move(vendors),
                                             media.source_device_type);
  }
  std::vector<HsAction> out;
  HsAction negotiated;
  negotiated.kind = HsAction::Kind::kStreamNegotiated;
  negotiated.width = media.selection.width;
  negotiated.height = media.selection.height;
  negotiated.fps = media.selection.fps;
  negotiated.touch_input = std::includes(media.input_events.begin(), media.input_events.end(),
                                         Capabilities::touch_events().begin(),
                                         Capabilities::touch_events().end());
  negotiated.key_input = std::includes(media.input_events.begin(), media.input_events.end(),
                                       Capabilities::key_events().begin(), Capabilities::key_events().end());
  negotiated.text_input = std::find(media.input_vendors.begin(), media.input_vendors.end(),
                                    Capabilities::text_vendor()) != media.input_vendors.end();
  out.push_back(negotiated);

  HsAction connect_video;
  connect_video.kind = HsAction::Kind::kConnect;
  connect_video.channel = HsChannel::kVideo;
  connect_video.port = media.video_port;
  out.push_back(connect_video);
  if (media.remote_control_port != -1) {
    HsAction connect_remote;
    connect_remote.kind = HsAction::Kind::kConnect;
    connect_remote.channel = HsChannel::kRemoteControl;
    connect_remote.port = media.remote_control_port;
    out.push_back(connect_remote);
  }
  return out;
}

std::vector<HsAction> HisightReceiver::maybe_play() {
  if (!setup_.has_value()) return {};
  const bool remote_ready = setup_->remote_control_port == -1 || remote_connected_;
  if (!video_connected_ || !remote_ready || play_requested_ || control_eof_) return {};
  play_requested_ = true;
  const int cseq = next_cseq();
  pending_[cseq] = "PLAY";
  return {send_control(rtsp_play(cseq))};
}

std::vector<HsAction> HisightReceiver::on_video_connected() {
  if (ended_ || failed_) return {};
  if (!setup_.has_value()) fail("还没有收到 SETUP 应答");
  if (video_connected_) fail("重复通知视频已连接");
  video_connected_ = true;
  return maybe_play();
}

std::vector<HsAction> HisightReceiver::on_remote_control_connected() {
  if (ended_ || failed_) return {};
  if (!setup_.has_value()) fail("还没有收到 SETUP 应答");
  if (setup_->remote_control_port == -1) fail("手机没有给回控端口");
  if (remote_connected_) fail("重复通知回控已连接");
  remote_connected_ = true;
  remote_open_ = true;
  return maybe_play();
}

void HisightReceiver::feed_video(const uint8_t* data, size_t size) {
  if (ended_ || size == 0) return;
  video_.feed(data, size);
}

std::vector<HsAction> HisightReceiver::on_video_closed() {
  if (ended_) return {};
  video_.finish();
  if (ended_) return {};
  std::vector<HsAction> out;
  terminate(HsEndReason::kVideoClosed, &out, true, true);
  return out;
}

std::vector<HsAction> HisightReceiver::on_control_closed() {
  if (ended_) return {};
  if (decoder_.has_partial() && !failed_) fail("控制连接关闭时仍有未收完的帧");
  control_eof_ = true;
  std::vector<HsAction> out;
  terminate(HsEndReason::kControlClosed, &out, false, true);
  return out;
}

std::vector<HsAction> HisightReceiver::on_remote_control_closed() {
  if (ended_) return {};
  if (encoder_) encoder_->clear();
  remote_open_ = false;
  std::vector<HsAction> out;
  terminate(HsEndReason::kRemoteControlClosed, &out, true, false);
  return out;
}

std::vector<HsAction> HisightReceiver::shutdown() {
  std::vector<HsAction> out;
  std::copy(carry_over_.begin(), carry_over_.end(), std::back_inserter(out));
  carry_over_.clear();
  terminate(HsEndReason::kLocalShutdown, &out, true, true);
  return out;
}

void HisightReceiver::terminate(HsEndReason reason, std::vector<HsAction>* out, bool send_teardown,
                                bool release_inputs) {
  if (ended_) return;
  ended_ = true;
  if (encoder_ && release_inputs && remote_open_) {
    try {
      for (auto& packet : encoder_->release()) out->push_back(make_send(HsChannel::kRemoteControl, std::move(packet)));
    } catch (...) {
    }
  }
  if (encoder_) encoder_->clear();
  remote_open_ = false;
  if (send_teardown && crypto_ready_ && !control_eof_) {
    out->push_back(send_control(rtsp_teardown(next_cseq())));
  }
  HsAction close;
  close.kind = HsAction::Kind::kCloseAll;
  out->push_back(close);
  HsAction ended;
  ended.kind = HsAction::Kind::kEnded;
  ended.reason = reason;
  out->push_back(ended);
}

std::vector<HsAction> HisightReceiver::send_touch(TouchAction action, const std::vector<TouchPoint>& points,
                                                int width, int height) {
  if (!encoder_ || !remote_open_ || ended_) return {};
  return {make_send(HsChannel::kRemoteControl, encoder_->encode_touch(action, points, width, height))};
}

std::vector<HsAction> HisightReceiver::send_key(bool down, int key_code, uint32_t meta_state) {
  if (!encoder_ || !remote_open_ || ended_) return {};
  return {make_send(HsChannel::kRemoteControl, encoder_->encode_key(down, key_code, meta_state))};
}

std::vector<HsAction> HisightReceiver::release_inputs() {
  if (!encoder_ || !remote_open_ || ended_) return {};
  std::vector<HsAction> out;
  for (auto& packet : encoder_->release()) out.push_back(make_send(HsChannel::kRemoteControl, std::move(packet)));
  return out;
}

}  // namespace hisight
}  // namespace hicar
