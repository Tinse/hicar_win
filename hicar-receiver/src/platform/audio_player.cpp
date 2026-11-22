#include "platform/audio_player.h"

#include <combaseapi.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>

namespace hicar {
namespace platform {
namespace {

constexpr uint32_t kSampleRate = 48000;
constexpr uint16_t kChannels = 2;

}  // namespace

AudioPlayer::AudioPlayer() = default;

AudioPlayer::~AudioPlayer() { close(); }

bool AudioPlayer::open_wasapi() {
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (hr == S_OK || hr == S_FALSE) {
    com_initialized_ = true;
  } else if (hr == RPC_E_CHANGED_MODE) {
    com_initialized_ = false;
  } else {
    return false;
  }

  IMMDeviceEnumerator* enumerator = nullptr;
  hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                        __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(&enumerator));
  if (FAILED(hr) || enumerator == nullptr) return false;
  IMMDevice* device = nullptr;
  hr = enumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device);
  enumerator->Release();
  if (FAILED(hr) || device == nullptr) return false;

  hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                        reinterpret_cast<void**>(&client_));
  device->Release();
  if (FAILED(hr) || client_ == nullptr) return false;

  WAVEFORMATEX requested{};
  requested.wFormatTag = WAVE_FORMAT_PCM;
  requested.nChannels = kChannels;
  requested.nSamplesPerSec = kSampleRate;
  requested.wBitsPerSample = 16;
  requested.nBlockAlign = static_cast<WORD>(requested.nChannels * requested.wBitsPerSample / 8);
  requested.nAvgBytesPerSec = requested.nSamplesPerSec * requested.nBlockAlign;
  hr = client_->Initialize(AUDCLNT_SHAREMODE_SHARED,
                           AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                           0, 0, &requested, nullptr);
  if (FAILED(hr)) {
    // 某些驱动不接受自动转换：退回设备混音格式，只处理 48k 双声道（16 位或 float32）。
    if (mix_ == nullptr) client_->GetMixFormat(&mix_);
    if (mix_ == nullptr || mix_->nSamplesPerSec != kSampleRate) {
      close_wasapi();
      return false;
    }
    mix_channels_ = static_cast<uint16_t>(mix_->nChannels);
    mix_bits_ = mix_->wBitsPerSample;
    if (mix_channels_ != 2 || (mix_bits_ != 16 && mix_bits_ != 32)) {
      close_wasapi();
      return false;
    }
    if (mix_->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
      mix_float_ = true;
    } else if (mix_->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
      const auto* extensible = reinterpret_cast<const WAVEFORMATEXTENSIBLE*>(mix_);
      mix_float_ = extensible->SubFormat.Data1 == 3;  // KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
    }
    hr = client_->Initialize(AUDCLNT_SHAREMODE_SHARED, 0, 0, 0, mix_, nullptr);
    if (FAILED(hr)) {
      close_wasapi();
      return false;
    }
  } else {
    mix_channels_ = kChannels;
    mix_bits_ = 16;
    mix_float_ = false;
  }

  if (FAILED(client_->GetBufferSize(&buffer_frames_)) || buffer_frames_ == 0) {
    close_wasapi();
    return false;
  }
  hr = client_->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void**>(&render_));
  if (FAILED(hr) || render_ == nullptr) {
    close_wasapi();
    return false;
  }
  hr = client_->Start();
  if (FAILED(hr)) {
    close_wasapi();
    return false;
  }
  wasapi_ = true;
  return true;
}

void AudioPlayer::close_wasapi() {
  wasapi_ = false;
  queue_.clear();
  if (client_ != nullptr) {
    client_->Stop();
    client_->Release();
    client_ = nullptr;
  }
  if (render_ != nullptr) {
    render_->Release();
    render_ = nullptr;
  }
  if (mix_ != nullptr) {
    CoTaskMemFree(mix_);
    mix_ = nullptr;
  }
  if (com_initialized_) {
    CoUninitialize();
    com_initialized_ = false;
  }
}

bool AudioPlayer::open_waveout(std::string* error) {
  WAVEFORMATEX format{};
  format.wFormatTag = WAVE_FORMAT_PCM;
  format.nChannels = kChannels;
  format.nSamplesPerSec = kSampleRate;
  format.wBitsPerSample = 16;
  format.nBlockAlign = static_cast<WORD>(format.nChannels * format.wBitsPerSample / 8);
  format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
  const MMRESULT result = waveOutOpen(&handle_, WAVE_MAPPER, &format, 0, 0, CALLBACK_NULL);
  if (result != MMSYSERR_NOERROR) {
    if (error != nullptr) *error = "waveOutOpen 失败（错误 " + std::to_string(result) + "）";
    handle_ = nullptr;
    return false;
  }
  return true;
}

bool AudioPlayer::open(std::string* error) {
  close();
  if (open_wasapi()) return true;
  wasapi_ = false;
  return open_waveout(error);
}

void AudioPlayer::close() {
  close_wasapi();
  std::lock_guard<std::mutex> lock(mutex_);
  if (handle_ != nullptr) {
    waveOutReset(handle_);
    for (auto* pending : pending_) {
      waveOutUnprepareHeader(handle_, &pending->header, sizeof(WAVEHDR));
      delete pending;
    }
    pending_.clear();
    waveOutClose(handle_);
    handle_ = nullptr;
  }
}

bool AudioPlayer::pump_wasapi() {
  if (render_ == nullptr) return false;
  UINT32 padding = 0;
  if (FAILED(client_->GetCurrentPadding(&padding))) return false;
  const UINT32 available = buffer_frames_ - padding;
  const size_t frames_in_queue = queue_.size() / (kChannels * 2);
  if (available == 0 || frames_in_queue == 0) return true;
  const UINT32 frames = static_cast<UINT32>(std::min<size_t>(available, frames_in_queue));
  BYTE* buffer = nullptr;
  if (FAILED(render_->GetBuffer(frames, &buffer)) || buffer == nullptr) return false;

  if (mix_float_) {
    const int16_t* source = reinterpret_cast<const int16_t*>(queue_.data());
    float* target = reinterpret_cast<float*>(buffer);
    const size_t samples = static_cast<size_t>(frames) * kChannels;
    for (size_t i = 0; i < samples; ++i) target[i] = static_cast<float>(source[i]) / 32768.0f;
  } else {
    std::memcpy(buffer, queue_.data(), static_cast<size_t>(frames) * kChannels * 2);
  }
  render_->ReleaseBuffer(frames, 0);
  queue_.erase(queue_.begin(), queue_.begin() + static_cast<std::ptrdiff_t>(frames) * kChannels * 2);
  return true;
}

bool AudioPlayer::write(const uint8_t* pcm, size_t size) {
  if (pcm == nullptr || size < kChannels * 2) return false;
  if (wasapi_) {
    queue_.insert(queue_.end(), pcm, pcm + size);
    const size_t max_bytes = static_cast<size_t>(kSampleRate) * kChannels * 2 * 2;  // 2 秒
    if (queue_.size() > max_bytes) {
      queue_.erase(queue_.begin(), queue_.begin() + static_cast<std::ptrdiff_t>(queue_.size() - max_bytes));
    }
    pump_wasapi();
    return true;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (handle_ == nullptr) return false;
  if (pending_.size() >= 12) return false;

  auto* pending = new Pending();
  pending->bytes.assign(pcm, pcm + size);
  pending->header.lpData = reinterpret_cast<LPSTR>(pending->bytes.data());
  pending->header.dwBufferLength = static_cast<DWORD>(pending->bytes.size());
  if (waveOutPrepareHeader(handle_, &pending->header, sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
    delete pending;
    return false;
  }
  if (waveOutWrite(handle_, &pending->header, sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
    waveOutUnprepareHeader(handle_, &pending->header, sizeof(WAVEHDR));
    delete pending;
    return false;
  }
  pending_.push_back(pending);
  return true;
}

void AudioPlayer::pump() {
  if (wasapi_) {
    pump_wasapi();
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (handle_ == nullptr) return;
  for (auto it = pending_.begin(); it != pending_.end();) {
    Pending* pending = *it;
    if ((pending->header.dwFlags & WHDR_DONE) != 0) {
      waveOutUnprepareHeader(handle_, &pending->header, sizeof(WAVEHDR));
      delete pending;
      it = pending_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace platform
}  // namespace hicar
