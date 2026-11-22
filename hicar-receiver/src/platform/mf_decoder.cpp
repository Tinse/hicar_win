#include "platform/mf_decoder.h"

#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <wmcodecdsp.h>
#include <codecapi.h>
#include <wrl/client.h>

#include <algorithm>
#include <cstring>

using Microsoft::WRL::ComPtr;

namespace hicar {
namespace platform {
namespace {

bool g_mf_started = false;
bool g_com_init = false;

bool ensure_media_foundation(std::string* error) {
  if (!g_com_init) {
    const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
      if (error != nullptr) *error = "CoInitializeEx 失败";
      return false;
    }
    g_com_init = true;
  }
  if (!g_mf_started) {
    const HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (FAILED(hr)) {
      if (error != nullptr) *error = "MFStartup 失败";
      return false;
    }
    g_mf_started = true;
  }
  return true;
}

uint32_t attribute_u32(IMFMediaType* type, const GUID& key, uint32_t fallback) {
  uint32_t value = fallback;
  if (FAILED(type->GetUINT32(key, &value))) return fallback;
  return value;
}

}  // namespace

MfH264Decoder::MfH264Decoder(FrameSink sink) : sink_(std::move(sink)) {}

MfH264Decoder::~MfH264Decoder() { close(); }

bool MfH264Decoder::open(int width, int height, int fps, std::string* error) {
  close();
  if (!ensure_media_foundation(error)) return false;
  width_ = width;
  height_ = height;
  fps_ = fps > 0 ? fps : 30;

  ComPtr<IMFTransform> transform;
  HRESULT hr = CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&transform));
  if (FAILED(hr)) {
    if (error != nullptr) *error = "创建 H.264 解码器失败";
    return false;
  }

  ComPtr<IMFMediaType> input;
  if (FAILED(MFCreateMediaType(&input))) {
    if (error != nullptr) *error = "创建输入类型失败";
    return false;
  }
  input->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
  input->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
  MFSetAttributeSize(input.Get(), MF_MT_FRAME_SIZE, static_cast<UINT32>(width),
                     static_cast<UINT32>(height));
  input->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
  hr = transform->SetInputType(0, input.Get(), 0);
  if (FAILED(hr)) {
    if (error != nullptr) *error = "设置 H.264 输入类型失败（尺寸可能不受支持）";
    return false;
  }

  VARIANT low_latency;
  VariantInit(&low_latency);
  low_latency.vt = VT_BOOL;
  low_latency.boolVal = VARIANT_TRUE;
  ComPtr<ICodecAPI> codec;
  if (SUCCEEDED(transform.As(&codec))) {
    codec->SetValue(&CODECAPI_AVLowLatencyMode, &low_latency);
  }
  VariantClear(&low_latency);

  transform_ = transform.Detach();
  // 尽量在首帧前把输出类型定成 NV12/YV12；部分驱动要等 SPS 后才会给类型，
  // 这里失败也没关系，ProcessOutput 返回 STREAM_CHANGE 时会再配置一次。
  configure_output();

  transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
  transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
  return true;
}

bool MfH264Decoder::configure_output() {
  if (transform_ == nullptr) return false;
  for (uint32_t index = 0; index < 32; ++index) {
    IMFMediaType* type = nullptr;
    if (FAILED(transform_->GetOutputAvailableType(0, index, &type)) || type == nullptr) break;
    GUID subtype{};
    type->GetGUID(MF_MT_SUBTYPE, &subtype);
    if (subtype == MFVideoFormat_NV12 || subtype == MFVideoFormat_YV12) {
      const HRESULT hr = transform_->SetOutputType(0, type, 0);
      if (SUCCEEDED(hr)) {
        UINT32 width = 0;
        UINT32 height = 0;
        MFGetAttributeSize(type, MF_MT_FRAME_SIZE, &width, &height);
        out_width_ = static_cast<int>(width);
        out_height_ = static_cast<int>(height);
        out_stride_ = static_cast<int>(attribute_u32(type, MF_MT_DEFAULT_STRIDE, width));
        nv12_ = subtype == MFVideoFormat_NV12;
        type->Release();
        return out_width_ > 0 && out_height_ > 0;
      }
    }
    type->Release();
  }
  return false;
}

bool MfH264Decoder::decode(const uint8_t* data, size_t size, uint64_t pts_90k) {
  if (transform_ == nullptr || data == nullptr || size == 0) return false;

  ComPtr<IMFSample> sample;
  ComPtr<IMFMediaBuffer> buffer;
  if (FAILED(MFCreateSample(&sample)) || FAILED(MFCreateMemoryBuffer(static_cast<DWORD>(size), &buffer))) {
    return false;
  }
  BYTE* target = nullptr;
  if (FAILED(buffer->Lock(&target, nullptr, nullptr))) return false;
  std::memcpy(target, data, size);
  buffer->Unlock();
  buffer->SetCurrentLength(static_cast<DWORD>(size));
  sample->AddBuffer(buffer.Get());
  const LONGLONG duration = 10000000LL / fps_;
  sample->SetSampleTime(static_cast<LONGLONG>(pts_90k * 10000ULL / 9ULL));
  sample->SetSampleDuration(duration);

  HRESULT hr = transform_->ProcessInput(0, sample.Get(), 0);
  if (FAILED(hr)) return false;

  for (int attempt = 0; attempt < 8; ++attempt) {
    MFT_OUTPUT_STREAM_INFO info{};
    if (FAILED(transform_->GetOutputStreamInfo(0, &info))) break;
    const bool provides_samples = (info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0;
    ComPtr<IMFSample> output;
    MFT_OUTPUT_DATA_BUFFER output_data{};
    output_data.dwStreamID = 0;
    if (!provides_samples) {
      ComPtr<IMFMediaBuffer> output_buffer;
      if (FAILED(MFCreateSample(&output))) return false;
      const DWORD buffer_size = info.cbSize > 0
                                    ? info.cbSize
                                    : static_cast<DWORD>(std::max(1, width_ * height_) * 3 / 2);
      if (FAILED(MFCreateMemoryBuffer(buffer_size, &output_buffer))) return false;
      output->AddBuffer(output_buffer.Get());
      output_data.pSample = output.Get();
    }
    DWORD status = 0;
    hr = transform_->ProcessOutput(0, 1, &output_data, &status);
    if (output_data.pEvents != nullptr) output_data.pEvents->Release();
    if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
      if (output_data.pSample != nullptr && provides_samples) output_data.pSample->Release();
      if (!configure_output()) return false;
      continue;
    }
    if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) {
      if (output_data.pSample != nullptr && provides_samples) output_data.pSample->Release();
      break;
    }
    if (FAILED(hr)) {
      if (output_data.pSample != nullptr && provides_samples) output_data.pSample->Release();
      break;
    }

    IMFSample* sample = provides_samples ? output_data.pSample : output.Get();
    if (sample == nullptr) continue;
    IMFMediaBuffer* decoded = nullptr;
    if (FAILED(sample->GetBufferByIndex(0, &decoded)) || decoded == nullptr) {
      if (provides_samples) sample->Release();
      continue;
    }
    BYTE* raw = nullptr;
    DWORD length = 0;
    if (SUCCEEDED(decoded->Lock(&raw, nullptr, &length))) {
      convert_to_bgra(raw, length);
      decoded->Unlock();
    }
    decoded->Release();
    if (provides_samples) sample->Release();
    break;
  }
  return true;
}

bool MfH264Decoder::convert_to_bgra(uint8_t* data, uint32_t length) {
  if (out_width_ <= 0 || out_height_ <= 0) return false;
  const int stride = std::abs(out_stride_) > 0 ? std::abs(out_stride_) : out_width_;
  const size_t y_size = static_cast<size_t>(stride) * out_height_;
  const size_t chroma_size = static_cast<size_t>(stride) * ((out_height_ + 1) / 2);
  if (length < y_size + chroma_size) return false;
  bgra_.resize(static_cast<size_t>(out_width_) * out_height_ * 4);
  const uint8_t* y_plane = data;
  const uint8_t* uv_plane = data + y_size;
  const bool bottom_up = out_stride_ < 0;

  for (int y = 0; y < out_height_; ++y) {
    const int src_y = bottom_up ? out_height_ - 1 - y : y;
    const uint8_t* y_row = y_plane + static_cast<size_t>(src_y) * stride;
    const uint8_t* uv_row = uv_plane + static_cast<size_t>(src_y / 2) * stride;
    uint8_t* out = bgra_.data() + static_cast<size_t>(y) * out_width_ * 4;
    for (int x = 0; x < out_width_; ++x) {
      const int yy = y_row[x];
      int u = 128;
      int v = 128;
      if (nv12_) {
        u = uv_row[(x / 2) * 2];
        v = uv_row[(x / 2) * 2 + 1];
      } else {
        // YV12：V 平面在前，U 平面在后，每行宽度为 stride/2。
        const uint8_t* v_plane = uv_plane;
        const uint8_t* u_plane = uv_plane + static_cast<size_t>(stride / 2) * ((out_height_ + 1) / 2);
        v = v_plane[static_cast<size_t>(src_y / 2) * (stride / 2) + x / 2];
        u = u_plane[static_cast<size_t>(src_y / 2) * (stride / 2) + x / 2];
      }
      const int r = yy + static_cast<int>(1.402 * (v - 128));
      const int g = yy - static_cast<int>(0.344136 * (u - 128) + 0.714136 * (v - 128));
      const int b = yy + static_cast<int>(1.772 * (u - 128));
      out[x * 4 + 0] = static_cast<uint8_t>(std::clamp(b, 0, 255));
      out[x * 4 + 1] = static_cast<uint8_t>(std::clamp(g, 0, 255));
      out[x * 4 + 2] = static_cast<uint8_t>(std::clamp(r, 0, 255));
      out[x * 4 + 3] = 255;
    }
  }
  if (sink_) sink_(bgra_.data(), out_width_, out_height_);
  width_ = out_width_;
  height_ = out_height_;
  return true;
}

void MfH264Decoder::close() {
  if (transform_ != nullptr) {
    transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
    transform_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
    transform_->Release();
    transform_ = nullptr;
  }
  out_width_ = 0;
  out_height_ = 0;
  bgra_.clear();
}

}  // namespace platform
}  // namespace hicar
