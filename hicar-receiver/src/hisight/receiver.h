#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "hisight/capabilities.h"
#include "hisight/rtsp.h"
#include "hisight/uibc.h"
#include "hisight/video.h"

namespace hicar {
namespace hisight {

enum class HsChannel { kControl, kVideo, kRemoteControl };

enum class HsEndReason {
  kLocalShutdown,
  kPeerTeardown,
  kControlClosed,
  kVideoClosed,
  kRemoteControlClosed,
};

struct HsAction {
  enum class Kind {
    kSend,
    kConnect,
    kCloseAll,
    kStreamNegotiated,
    kPlayAccepted,
    kEnded,
  };
  Kind kind = Kind::kSend;
  HsChannel channel = HsChannel::kControl;
  int port = 0;
  std::vector<uint8_t> bytes;
  int width = 0;
  int height = 0;
  int fps = 0;
  bool touch_input = false;
  bool key_input = false;
  bool text_input = false;
  HsEndReason reason = HsEndReason::kLocalShutdown;
};

// 一次 HiSight 投屏会话的纯协议状态机（不持有连接和线程）。
class HisightReceiver {
 public:
  HisightReceiver(std::array<uint8_t, 16> session_key, HisightConfig config, AccessUnitSink video_sink);

  std::vector<HsAction> start(uint64_t wall_clock_millis);
  std::vector<HsAction> feed_control(const uint8_t* data, size_t size, uint64_t wall_clock_millis);
  std::vector<HsAction> on_control_closed();
  std::vector<HsAction> on_video_connected();
  std::vector<HsAction> on_remote_control_connected();
  void feed_video(const uint8_t* data, size_t size);
  std::vector<HsAction> on_video_closed();
  std::vector<HsAction> on_remote_control_closed();
  std::vector<HsAction> shutdown();

  std::vector<HsAction> send_touch(TouchAction action, const std::vector<TouchPoint>& points, int width,
                                   int height);
  std::vector<HsAction> send_key(bool down, int key_code, uint32_t meta_state);
  std::vector<HsAction> release_inputs();

  bool ended() const { return ended_; }
  bool failed() const { return failed_; }
  const std::optional<MediaSetup>& media() const { return setup_; }

 private:
  std::vector<HsAction> handle(const RtspMessage& message, uint64_t wall_clock_millis);
  std::vector<HsAction> handle_response(const RtspMessage& message);
  std::vector<HsAction> handle_announce(const RtspMessage& message, uint64_t wall_clock_millis);
  std::vector<HsAction> handle_options(const RtspMessage& message, uint64_t wall_clock_millis);
  std::vector<HsAction> handle_get_parameter(const RtspMessage& message);
  std::vector<HsAction> handle_set_parameter(const RtspMessage& message, uint64_t wall_clock_millis);
  std::vector<HsAction> handle_setup_response(const RtspMessage& message);
  std::vector<HsAction> maybe_play();

  std::vector<uint8_t> send_control_bytes(const std::vector<uint8_t>& plain);
  HsAction make_send(HsChannel channel, std::vector<uint8_t> bytes) const;
  HsAction send_control(const std::vector<uint8_t>& plain) const;
  void terminate(HsEndReason reason, std::vector<HsAction>* out, bool send_teardown, bool release_inputs);
  int next_cseq() { return ++last_cseq_; }
  void require_negotiation_ready(const RtspMessage& message) const;

  std::array<uint8_t, 16> key_;
  HisightConfig config_;
  AccessUnitSink video_sink_;
  Capabilities capabilities_;
  VideoDepacketizer video_;

  ControlFrameDecoder decoder_;
  std::map<int, std::string> pending_;
  std::vector<HsAction> carry_over_;

  bool started_ = false;
  bool crypto_ready_ = false;
  bool options_received_ = false;
  int last_cseq_ = 0;
  std::optional<MediaSetup> setup_;
  bool video_connected_ = false;
  bool remote_connected_ = false;
  bool play_requested_ = false;
  bool control_eof_ = false;
  bool failed_ = false;
  bool ended_ = false;

  std::unique_ptr<UibcEncoder> encoder_;
  bool remote_open_ = false;
};

}  // namespace hisight
}  // namespace hicar
