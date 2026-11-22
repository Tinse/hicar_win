#pragma once

#include <windows.h>
#include <mmsystem.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

#include <cstdint>
#include <mutex>
#include <vector>

namespace hicar {
namespace platform {

// 音频输出：优先 WASAPI 共享模式（48kHz 立体声 16 位，自动转换）；失败回退 waveOut。
class AudioPlayer {
 public:
  AudioPlayer();
  ~AudioPlayer();

  bool open(std::string* error);
  void close();
  bool write(const uint8_t* pcm, size_t size);
  void pump();

 private:
  struct Pending {
    WAVEHDR header{};
    std::vector<uint8_t> bytes;
  };

  bool open_wasapi();
  bool pump_wasapi();
  void close_wasapi();
  bool open_waveout(std::string* error);

  bool wasapi_ = false;
  bool com_initialized_ = false;
  IAudioClient* client_ = nullptr;
  IAudioRenderClient* render_ = nullptr;
  WAVEFORMATEX* mix_ = nullptr;
  UINT32 buffer_frames_ = 0;
  uint16_t mix_channels_ = 0;
  uint16_t mix_bits_ = 0;
  bool mix_float_ = false;
  std::vector<uint8_t> queue_;

  HWAVEOUT handle_ = nullptr;
  std::vector<Pending*> pending_;
  std::mutex mutex_;
};

}  // namespace platform
}  // namespace hicar
