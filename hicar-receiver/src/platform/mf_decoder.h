#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct IMFTransform;

namespace hicar {
namespace platform {

// Media Foundation H.264 解码器，输出 NV12/YV12 后转 BGRA（top-down）。
class MfH264Decoder {
 public:
  using FrameSink = std::function<void(const uint8_t* bgra, int width, int height)>;

  explicit MfH264Decoder(FrameSink sink);
  ~MfH264Decoder();

  bool open(int width, int height, int fps, std::string* error);
  bool decode(const uint8_t* data, size_t size, uint64_t pts_90k);
  void close();

  bool opened() const { return transform_ != nullptr; }
  int width() const { return width_; }
  int height() const { return height_; }
  uint64_t last_decode_micros() const { return last_decode_micros_; }

 private:
  bool configure_output();
  bool convert_to_bgra(uint8_t* data, uint32_t length);

  FrameSink sink_;
  IMFTransform* transform_ = nullptr;
  int width_ = 0;
  int height_ = 0;
  int fps_ = 30;
  int out_width_ = 0;
  int out_height_ = 0;
  int out_stride_ = 0;
  uint64_t last_decode_micros_ = 0;
  bool nv12_ = true;
  std::vector<uint8_t> bgra_;
};

}  // namespace platform
}  // namespace hicar
