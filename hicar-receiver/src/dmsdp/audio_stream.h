#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace hicar {
namespace dmsdp {

struct AudioChunk {
  uint32_t ssrc = 0;
  uint32_t timestamp = 0;
  uint16_t sequence = 0;
  uint8_t payload_type = 0;
  bool aac = false;
  std::vector<uint8_t> data;  // PCM：16 位小端交错；AAC：带 ADTS 头的一帧
};

// 扬声器数据通道解包：识别 TCP 分帧、解 AES-128-CTR、拆 RTP、去掉 PCM 内层 12 字节头。
class AudioStreamDecoder {
 public:
  explicit AudioStreamDecoder(std::array<uint8_t, 16> key);

  void feed(const uint8_t* data, size_t size, std::vector<AudioChunk>* out);
  void reset();

  const char* framing_name() const;

 private:
  enum class Header { kNone, kLen4, kLen2, kFlag, kRecord };
  struct Frame {
    size_t payload_offset = 0;
    size_t payload_size = 0;
    bool sealed = false;
    bool ok = false;        // 帧头合法
    bool complete = false;  // 帧体已到齐
  };

  Frame parse_frame(Header header, bool sealed, size_t offset, bool allow_partial) const;
  bool parse_rtp(const std::vector<uint8_t>& rtp, AudioChunk* chunk) const;
  bool try_detect();
  void consume(std::vector<AudioChunk>* out);

  std::array<uint8_t, 16> key_{};
  std::vector<uint8_t> buffer_;
  Header header_ = Header::kNone;
  bool sealed_ = false;
  int invalid_frames_ = 0;
};

}  // namespace dmsdp
}  // namespace hicar
