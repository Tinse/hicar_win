#include "dmsdp/audio_stream.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "dmsdp/cipher.h"

namespace hicar {
namespace dmsdp {
namespace {

uint16_t read_be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

uint32_t read_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

bool rtp_payload_offset(const std::vector<uint8_t>& rtp, size_t* offset) {
  if (rtp.size() < 12) return false;
  if ((rtp[0] >> 6) != 2) return false;
  size_t pos = 12 + static_cast<size_t>(rtp[0] & 0x0F) * 4;
  if ((rtp[0] & 0x10) != 0) {
    if (pos + 4 > rtp.size()) return false;
    const uint16_t words = read_be16(rtp.data() + pos + 2);
    pos += 4 + static_cast<size_t>(words) * 4;
  }
  if (pos > rtp.size()) return false;
  size_t end = rtp.size();
  if ((rtp[0] & 0x20) != 0) {  // RTP 头的 P 位在第一个字节
    if (end == 0) return false;
    const uint8_t padding = rtp[end - 1];
    if (padding == 0 || padding > end - pos) return false;
    end -= padding;
  }
  if (end < pos) return false;
  *offset = pos;
  return true;
}

bool looks_aac(const uint8_t* data, size_t size) {
  return size >= 2 && data[0] == 0xFF && (data[1] & 0xF0) == 0xF0;
}

}  // namespace

AudioStreamDecoder::AudioStreamDecoder(std::array<uint8_t, 16> key) : key_(key) {}

void AudioStreamDecoder::reset() {
  buffer_.clear();
  header_ = Header::kNone;
  sealed_ = false;
  invalid_frames_ = 0;
}

const char* AudioStreamDecoder::framing_name() const {
  switch (header_) {
    case Header::kLen4: return sealed_ ? "4字节长度+加密" : "4字节长度";
    case Header::kLen2: return sealed_ ? "2字节长度+加密" : "2字节长度";
    case Header::kFlag: return sealed_ ? "AB标志+加密" : "00标志";
    case Header::kRecord: return sealed_ ? "$记录+加密" : "$记录";
    default: return "未识别";
  }
}

AudioStreamDecoder::Frame AudioStreamDecoder::parse_frame(Header header, bool sealed, size_t offset,
                                                          bool /*allow_partial*/) const {
  Frame frame;
  frame.sealed = sealed;
  const size_t available = buffer_.size();
  if (header == Header::kNone || offset >= available) return frame;

  size_t length = 0;
  size_t payload = 0;
  if (header == Header::kLen4) {
    if (offset + 4 > available) return frame;
    length = read_be32(buffer_.data() + offset);
    payload = offset + 4;
  } else if (header == Header::kLen2) {
    if (offset + 2 > available) return frame;
    length = read_be16(buffer_.data() + offset);
    payload = offset + 2;
  } else if (header == Header::kFlag) {
    if (offset + 3 > available) return frame;
    if (buffer_[offset] != 0x00 && buffer_[offset] != 0xAB) return frame;
    length = read_be16(buffer_.data() + offset + 1);
    payload = offset + 3;
  } else {
    if (offset + 4 > available) return frame;
    if (buffer_[offset] != '$') return frame;
    length = read_be16(buffer_.data() + offset + 2);
    payload = offset + 4;
  }
  if (length == 0 || length > 65535) return frame;
  if (sealed && length < 16 + 12) return frame;
  if (!sealed && length < 12) return frame;
  frame.ok = true;
  frame.payload_offset = payload;
  frame.payload_size = length;
  frame.complete = payload + length <= available;
  return frame;
}

bool AudioStreamDecoder::parse_rtp(const std::vector<uint8_t>& rtp, AudioChunk* chunk) const {
  if (rtp.size() < 12 || (rtp[0] >> 6) != 2) return false;
  size_t offset = 0;
  if (!rtp_payload_offset(rtp, &offset)) return false;
  if (offset >= rtp.size()) return false;

  chunk->ssrc = read_be32(rtp.data() + 8);
  chunk->timestamp = read_be32(rtp.data() + 4);
  chunk->sequence = read_be16(rtp.data() + 2);
  chunk->payload_type = rtp[1] & 0x7F;
  chunk->data.assign(rtp.begin() + static_cast<std::ptrdiff_t>(offset), rtp.end());
  chunk->aac = looks_aac(chunk->data.data(), chunk->data.size());

  // PCM 内层头：00 01 ‖ 8 字节 ‖ 数据长度 BE16；长度对得上才去掉。
  if (!chunk->aac && chunk->data.size() >= 12 && chunk->data[0] == 0x00 && chunk->data[1] == 0x01) {
    const uint16_t inner = read_be16(chunk->data.data() + 10);
    if (inner == chunk->data.size() - 12) {
      chunk->data.erase(chunk->data.begin(), chunk->data.begin() + 12);
    }
  }
  return !chunk->data.empty();
}

bool AudioStreamDecoder::try_detect() {
  static const Header kHeaders[] = {Header::kLen4, Header::kLen2, Header::kFlag, Header::kRecord};
  for (const Header header : kHeaders) {
    for (int sealed_index = 0; sealed_index < 2; ++sealed_index) {
      const bool sealed = sealed_index == 1;
      size_t offset = 0;
      int frames = 0;
      uint32_t ssrc = 0;
      uint16_t sequence = 0;
      uint8_t payload_type = 0;
      bool incomplete = false;
      for (; frames < 3; ++frames) {
        const Frame frame = parse_frame(header, sealed, offset, true);
        if (!frame.ok) break;
        if (!frame.complete) {
          incomplete = true;
          break;
        }
        std::vector<uint8_t> body(buffer_.begin() + static_cast<std::ptrdiff_t>(frame.payload_offset),
                                  buffer_.begin() + static_cast<std::ptrdiff_t>(frame.payload_offset + frame.payload_size));
        if (frame.sealed) {
          try {
            body = open_control_payload(key_.data(), body);
          } catch (...) {
            break;
          }
        }
        AudioChunk chunk;
        if (!parse_rtp(body, &chunk)) break;
        if (frames == 0) {
          ssrc = chunk.ssrc;
          sequence = chunk.sequence;
          payload_type = chunk.payload_type;
        } else if (chunk.ssrc != ssrc || chunk.sequence != static_cast<uint16_t>(sequence + 1) ||
                   chunk.payload_type != payload_type) {
          break;
        }
        sequence = chunk.sequence;
        offset = frame.payload_offset + frame.payload_size;
      }
      if (frames == 3) {
        header_ = header;
        sealed_ = sealed;
        invalid_frames_ = 0;
        return true;
      }
      (void)incomplete;
    }
  }
  return false;
}

void AudioStreamDecoder::consume(std::vector<AudioChunk>* out) {
  size_t consumed = 0;
  while (!buffer_.empty()) {
    const Frame frame = parse_frame(header_, sealed_, consumed, true);
    if (!frame.ok || !frame.complete) break;
    std::vector<uint8_t> body(buffer_.begin() + static_cast<std::ptrdiff_t>(frame.payload_offset),
                              buffer_.begin() + static_cast<std::ptrdiff_t>(frame.payload_offset + frame.payload_size));
    if (frame.sealed) {
      try {
        body = open_control_payload(key_.data(), body);
      } catch (...) {
        ++invalid_frames_;
        ++consumed;
        continue;
      }
    }
    AudioChunk chunk;
    if (!parse_rtp(body, &chunk)) {
      ++invalid_frames_;
      ++consumed;
      continue;
    }
    invalid_frames_ = 0;
    if (out != nullptr) out->push_back(std::move(chunk));
    consumed = frame.payload_offset + frame.payload_size;
  }
  if (consumed > 0) buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(consumed));
  if (invalid_frames_ > 8) {
    header_ = Header::kNone;
    sealed_ = false;
    invalid_frames_ = 0;
    if (buffer_.size() > 4) buffer_.erase(buffer_.begin(), buffer_.begin() + 4);
  }
}

void AudioStreamDecoder::feed(const uint8_t* data, size_t size, std::vector<AudioChunk>* out) {
  if (data != nullptr && size > 0) buffer_.insert(buffer_.end(), data, data + size);
  if (header_ == Header::kNone) {
    if (!try_detect()) {
      if (buffer_.size() > 65536) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_.size() - 8192));
      }
      return;
    }
  }
  consume(out);
}

}  // namespace dmsdp
}  // namespace hicar
