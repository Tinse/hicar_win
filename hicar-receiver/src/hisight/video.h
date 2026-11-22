#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace hicar {
namespace hisight {

struct AccessUnit {
  const uint8_t* data = nullptr;
  size_t size = 0;
  uint32_t rtp_timestamp = 0;
  uint64_t pts_90k = 0;
  uint16_t first_sequence = 0;
  uint16_t last_sequence = 0;
};

using AccessUnitSink = std::function<void(const AccessUnit&)>;

// 视频连接：BE32 RTP 包长 ‖ RTP 包；载荷按 marker 拼成 PES，PES 头明文，ES 为 IV16‖AES-CTR。
class VideoDepacketizer {
 public:
  VideoDepacketizer(std::array<uint8_t, 16> session_key, AccessUnitSink sink);

  void feed(const uint8_t* data, size_t size);
  void finish();

  bool failed() const { return failed_; }
  uint64_t frames_delivered() const { return frames_delivered_; }
  uint64_t packets_received() const { return packets_received_; }

 private:
  void consume();
  void process_packet(const uint8_t* packet, size_t size);
  void deliver();
  void fail(const std::string& message);

  std::array<uint8_t, 16> key_;
  AccessUnitSink sink_;
  std::vector<uint8_t> pending_;
  size_t pending_offset_ = 0;

  bool failed_ = false;
  int64_t last_sequence_ = -1;
  int64_t stream_ssrc_ = -1;
  uint32_t pes_timestamp_ = 0;
  uint16_t pes_first_sequence_ = 0;
  std::vector<uint8_t> pes_;
  std::vector<uint8_t> es_;
  uint64_t frames_delivered_ = 0;
  uint64_t packets_received_ = 0;
};

}  // namespace hisight
}  // namespace hicar
