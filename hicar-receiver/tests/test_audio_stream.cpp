#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "dmsdp/audio_stream.h"
#include "dmsdp/cipher.h"

namespace {

int failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

std::vector<uint8_t> rtp_packet(uint16_t sequence, const std::array<uint8_t, 16>& key,
                                bool inner_header) {
  std::vector<uint8_t> rtp(12, 0);
  rtp[0] = 0x80;
  rtp[1] = 96;
  rtp[2] = static_cast<uint8_t>(sequence >> 8);
  rtp[3] = static_cast<uint8_t>(sequence & 0xFF);
  rtp[6] = 0x00;
  rtp[7] = 0x01;
  rtp[8] = 0x00;
  rtp[9] = 0x00;
  rtp[10] = 0x03;
  rtp[11] = 0xE8;  // SSRC 1000
  if (inner_header) {
    rtp.insert(rtp.end(), {0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4});
  }
  rtp.insert(rtp.end(), {0x11, 0x22, 0x33, 0x44});
  (void)key;
  return rtp;
}

std::vector<uint8_t> seal_ab(const std::array<uint8_t, 16>& key, uint16_t index,
                             const std::vector<uint8_t>& rtp) {
  std::array<uint8_t, 16> iv{};
  iv[15] = static_cast<uint8_t>(index);
  const auto sealed = hicar::dmsdp::seal_control_payload(key.data(), iv.data(), rtp);
  std::vector<uint8_t> frame;
  frame.push_back(0xAB);
  const uint16_t length = static_cast<uint16_t>(sealed.size());
  frame.push_back(static_cast<uint8_t>(length >> 8));
  frame.push_back(static_cast<uint8_t>(length & 0xFF));
  frame.insert(frame.end(), sealed.begin(), sealed.end());
  return frame;
}

std::vector<uint8_t> plain_len4(const std::vector<uint8_t>& rtp) {
  std::vector<uint8_t> frame;
  const uint32_t length = static_cast<uint32_t>(rtp.size());
  frame.push_back(static_cast<uint8_t>(length >> 24));
  frame.push_back(static_cast<uint8_t>(length >> 16));
  frame.push_back(static_cast<uint8_t>(length >> 8));
  frame.push_back(static_cast<uint8_t>(length));
  frame.insert(frame.end(), rtp.begin(), rtp.end());
  return frame;
}

}  // namespace

int main() {
  const std::array<uint8_t, 16> key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  // AB 标志 + 加密 + 三包连续 RTP 才识别
  {
    std::vector<uint8_t> stream;
    for (uint16_t i = 0; i < 3; ++i) {
      const auto frame = seal_ab(key, i, rtp_packet(static_cast<uint16_t>(7 + i), key, false));
      stream.insert(stream.end(), frame.begin(), frame.end());
    }
    hicar::dmsdp::AudioStreamDecoder decoder(key);
    std::vector<hicar::dmsdp::AudioChunk> chunks;
    decoder.feed(stream.data(), stream.size(), &chunks);
    check(chunks.size() == 3, "加密 AB 分帧解出 3 包");    if (!chunks.empty()) {
      check(chunks[0].ssrc == 1000 && chunks[0].payload_type == 96, "RTP 字段正确");
      check(chunks[0].data.size() == 4 && chunks[0].data[0] == 0x11, "PCM 数据正确");
    }
    check(std::string(decoder.framing_name()).find("AB") != std::string::npos, "识别为 AB 分帧");
  }

  // 4 字节大端长度 + 明文 RTP
  {
    std::vector<uint8_t> stream;
    for (uint16_t i = 0; i < 3; ++i) {
      const auto frame = plain_len4(rtp_packet(static_cast<uint16_t>(100 + i), key, false));
      stream.insert(stream.end(), frame.begin(), frame.end());
    }
    hicar::dmsdp::AudioStreamDecoder decoder(key);
    std::vector<hicar::dmsdp::AudioChunk> chunks;
    decoder.feed(stream.data(), stream.size(), &chunks);
    check(chunks.size() == 3, "4 字节长度分帧解出 3 包");
    check(std::string(decoder.framing_name()).find("4") != std::string::npos, "识别为 4 字节长度");
  }

  // PCM 内层 12 字节头在长度吻合时去掉
  {
    std::vector<uint8_t> stream;
    for (uint16_t i = 0; i < 3; ++i) {
      const auto frame = plain_len4(rtp_packet(static_cast<uint16_t>(200 + i), key, true));
      stream.insert(stream.end(), frame.begin(), frame.end());
    }
    hicar::dmsdp::AudioStreamDecoder decoder(key);
    std::vector<hicar::dmsdp::AudioChunk> chunks;
    decoder.feed(stream.data(), stream.size(), &chunks);
    check(chunks.size() == 3, "带内层头的 3 包");
    if (!chunks.empty()) check(chunks[0].data.size() == 4 && chunks[0].data[3] == 0x44, "内层头已去掉");
  }

  // 半包不丢数据
  {
    const auto frame = plain_len4(rtp_packet(300, key, false));
    hicar::dmsdp::AudioStreamDecoder decoder(key);
    std::vector<hicar::dmsdp::AudioChunk> chunks;
    decoder.feed(frame.data(), frame.size() - 1, &chunks);
    check(chunks.empty(), "半包不出包");
    const auto frame2 = plain_len4(rtp_packet(301, key, false));
    const auto frame3 = plain_len4(rtp_packet(302, key, false));
    std::vector<uint8_t> rest(frame.end() - 1, frame.end());
    rest.insert(rest.end(), frame2.begin(), frame2.end());
    rest.insert(rest.end(), frame3.begin(), frame3.end());
    decoder.feed(rest.data(), rest.size(), &chunks);
    check(chunks.size() == 3, "补半包后出 3 包");
  }

  if (failures == 0) std::puts("audio stream: all checks passed");
  return failures == 0 ? 0 : 1;
}
