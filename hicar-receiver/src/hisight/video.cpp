#include "hisight/video.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "dmsdp/cipher.h"

namespace hicar {
namespace hisight {
namespace {

constexpr uint32_t kMaxPacket = 10u * 1024u * 1024u;
constexpr uint16_t kLastSequence = 64999;

uint16_t be16(const uint8_t* data) {
  return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t be32(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | data[3];
}

}  // namespace

VideoDepacketizer::VideoDepacketizer(std::array<uint8_t, 16> session_key, AccessUnitSink sink)
    : key_(session_key), sink_(std::move(sink)) {}

void VideoDepacketizer::fail(const std::string& message) {
  failed_ = true;
  throw std::runtime_error(message);
}

void VideoDepacketizer::feed(const uint8_t* data, size_t size) {
  if (failed_) throw std::runtime_error("视频流已经失败");
  if (data == nullptr || size == 0) return;
  pending_.insert(pending_.end(), data, data + size);
  consume();
}

void VideoDepacketizer::consume() {
  while (!failed_) {
    const size_t available = pending_.size() - pending_offset_;
    if (available < 4) break;
    const uint32_t length = be32(pending_.data() + pending_offset_);
    if (length < 12 || length > kMaxPacket) fail("视频 RTP 包长不在 12..10MiB");
    if (available < 4 + length) break;
    process_packet(pending_.data() + pending_offset_ + 4, length);
    pending_offset_ += 4 + length;
  }
  if (pending_offset_ > 0) {
    pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(pending_offset_));
    pending_offset_ = 0;
  }
}

void VideoDepacketizer::process_packet(const uint8_t* packet, size_t size) {
  const uint8_t b0 = packet[0];
  const uint8_t b1 = packet[1];
  if ((b0 >> 6) != 2) fail("视频 RTP 版本不是 2");
  if ((b0 & 0x20) != 0) fail("视频 RTP 带 padding，未实现");
  if ((b1 & 0x7F) != 96) fail("视频 RTP 载荷类型不是 96");
  const bool has_extension = (b0 & 0x10) != 0;
  const uint8_t csrc_count = b0 & 0x0F;
  const bool marker = (b1 & 0x80) != 0;
  const uint16_t sequence = be16(packet + 2);
  const uint32_t timestamp = be32(packet + 4);
  const uint32_t ssrc = be32(packet + 8);

  size_t header = 12 + 4 * csrc_count;
  if (header >= size) fail("视频 RTP 的 CSRC 截断或缺少载荷");
  if (has_extension) {
    if (header + 4 >= size) fail("视频 RTP 扩展头截断");
    const uint16_t profile = be16(packet + header);
    const uint16_t extension_length = be16(packet + header + 2);
    if ((profile & 1) != 1) fail("视频 RTP 扩展 profile 最低位不是 1");
    // RTP 扩展头的 length 单位是 32-bit word，不是字节；少乘 4 会把扩展内容
    // 当成 H.264 载荷，PES 随即损坏，表现就是一直黑屏。
    const size_t extension_bytes = static_cast<size_t>(extension_length) * 4;
    if (extension_bytes > size - header - 4) fail("视频 RTP 扩展长度越界");
    header += 4 + extension_bytes;
    if (header >= size) fail("视频 RTP 扩展截断或缺少载荷");
  }

  if (last_sequence_ >= 0) {
    const uint16_t expected = last_sequence_ == kLastSequence ? 0 : static_cast<uint16_t>(last_sequence_ + 1);
    if (sequence != expected) fail("视频 RTP 序号不连续（丢包或重复）");
  }
  if (stream_ssrc_ >= 0 && ssrc != static_cast<uint32_t>(stream_ssrc_)) fail("视频 RTP 的 SSRC 在连接中改变");
  if (!pes_.empty() && timestamp != pes_timestamp_) fail("同一 PES 内 RTP 时间戳改变");

  const size_t payload_length = size - header;
  static int rtp_diag = 0;
  if (rtp_diag < 3) {
    std::fprintf(stderr, "[HiSight] RTP b0=%02x b1=%02x csrc=%u ext=%d header=%zu size=%zu payload=%zu first=",
                 b0, b1, csrc_count, has_extension ? 1 : 0, header, size, payload_length);
    for (size_t i = 0; i < payload_length && i < 16; ++i) std::fprintf(stderr, "%02x", packet[header + i]);
    std::fprintf(stderr, "\n");
    ++rtp_diag;
  }
  if (pes_.size() + payload_length > kMaxPacket) fail("未完成的 PES 超过 10MiB");
  if (pes_.empty()) {
    pes_first_sequence_ = sequence;
    pes_timestamp_ = timestamp;
  }
  last_sequence_ = sequence;
  stream_ssrc_ = ssrc;
  pes_.insert(pes_.end(), packet + header, packet + size);
  ++packets_received_;
  if (marker) deliver();
}

void VideoDepacketizer::deliver() {
  const size_t n = pes_.size();
  // 部分 HarmonyOS 手机在 PES 前多带 1 个（或几个）填充字节，直接按 0 偏移
  // 校验会把正常流判成“起始码错误”。在头部有限范围内找到第一个 00 00 01。
  size_t base = 0;
  while (base + 3 < n && !(pes_[base] == 0 && pes_[base + 1] == 0 && pes_[base + 2] == 1)) ++base;
  if (base + 3 >= n) {
    std::fprintf(stderr, "[HiSight] PES 起始码缺失，前 32 字节：");
    for (size_t i = 0; i < n && i < 32; ++i) std::fprintf(stderr, "%02x", pes_[i]);
    std::fprintf(stderr, "\n");
    fail("视频 PES 头截断或起始码错误");
  }
  if (base != 0) std::fprintf(stderr, "[HiSight] PES 起始偏移 %zu\n", base);
  const uint8_t* p = pes_.data() + base;
  const size_t m = n - base;
  if (m < 14) fail("视频 PES 头截断或起始码错误");
  const uint16_t declared = be16(p + 4);
  if (declared != 0 && static_cast<size_t>(declared) + 6 != m) fail("视频 PES 声明长度与实际不符");
  const uint8_t flags = p[7];
  // PES 第 6 字节只要求最高两位是 '10'；0x80/0x84 都合法（0x84 只是置了
  // data_alignment_indicator）。写死 0x84 会把部分手机的正常流直接判失败。
  if ((p[6] & 0xC0) != 0x80 || (flags & 0x80) == 0) fail("视频 PES 标志不是 '10' 或缺少 PTS");
  const uint64_t pts = ((static_cast<uint64_t>(p[9]) & 0x06) << 29) |
                       ((static_cast<uint64_t>(p[10]) & 0xFF) << 22) |
                       ((static_cast<uint64_t>(p[11]) & 0xFE) << 14) |
                       ((static_cast<uint64_t>(p[12]) & 0xFF) << 7) |
                       ((static_cast<uint64_t>(p[13]) & 0xFE) >> 1);
  const uint8_t header_data = p[8];
  // PES_header_data_length 从第 8 字节之后开始计数：PTS 5 字节 + 可选扩展。
  // 所以 ES 起点始终是 9 + header_data；原来扩展分支写成 15 + header_data，
  // 会多跳过 6 字节，把 H.264 起始码/密文开头一起丢掉，表现就是黑屏。
  if ((flags & 0x80) != 0 && header_data < 5) fail("视频 PES 声明带 PTS 但头长度不足");
  const size_t es_offset = 9 + static_cast<size_t>(header_data);
  if (es_offset + 16 >= m) fail("视频 PES 缺少完整 IV 或 ES 为空");
  const size_t cipher_start = es_offset + 16;
  const size_t es_length = m - cipher_start;
  es_.resize(es_length);
  const auto decrypted = dmsdp::aes128_ctr_crypt(key_.data(), p + es_offset,
                                                 p + cipher_start, es_length);
  std::copy(decrypted.begin(), decrypted.end(), es_.begin());

  AccessUnit unit;
  unit.data = es_.data();
  unit.size = es_length;
  unit.rtp_timestamp = pes_timestamp_;
  unit.pts_90k = pts;
  unit.first_sequence = pes_first_sequence_;
  unit.last_sequence = last_sequence_ >= 0 ? static_cast<uint16_t>(last_sequence_) : 0;
  if (sink_) sink_(unit);
  ++frames_delivered_;
  pes_.clear();
}

void VideoDepacketizer::finish() {
  if (failed_) throw std::runtime_error("视频流已经失败");
  if (pending_offset_ != 0 || !pending_.empty()) fail("视频连接结束时仍有未收完的 RTP 包");
  if (!pes_.empty()) fail("视频连接结束时 PES 缺少结尾 marker");
}

}  // namespace hisight
}  // namespace hicar
