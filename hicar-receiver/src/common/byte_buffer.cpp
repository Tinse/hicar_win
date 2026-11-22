#include "common/byte_buffer.h"

#include <string>

namespace hicar {

namespace {
void check_range(uint32_t value, uint32_t max, const char* name) {
  if (value > max) throw std::invalid_argument(std::string(name) + " 越界");
}
}  // namespace

ByteWriter& ByteWriter::u8(uint32_t v) {
  check_range(v, 0xFF, "u8");
  buf_.push_back(static_cast<uint8_t>(v));
  return *this;
}

ByteWriter& ByteWriter::u16be(uint32_t v) {
  check_range(v, 0xFFFF, "u16");
  buf_.push_back(static_cast<uint8_t>(v >> 8));
  buf_.push_back(static_cast<uint8_t>(v));
  return *this;
}

ByteWriter& ByteWriter::u16le(uint32_t v) {
  check_range(v, 0xFFFF, "u16");
  buf_.push_back(static_cast<uint8_t>(v));
  buf_.push_back(static_cast<uint8_t>(v >> 8));
  return *this;
}

ByteWriter& ByteWriter::u32be(uint32_t v) {
  buf_.push_back(static_cast<uint8_t>(v >> 24));
  buf_.push_back(static_cast<uint8_t>(v >> 16));
  buf_.push_back(static_cast<uint8_t>(v >> 8));
  buf_.push_back(static_cast<uint8_t>(v));
  return *this;
}

ByteWriter& ByteWriter::u32le(uint32_t v) {
  buf_.push_back(static_cast<uint8_t>(v));
  buf_.push_back(static_cast<uint8_t>(v >> 8));
  buf_.push_back(static_cast<uint8_t>(v >> 16));
  buf_.push_back(static_cast<uint8_t>(v >> 24));
  return *this;
}

ByteWriter& ByteWriter::ea(uint32_t v) {
  const size_t n = ea_encoded_size(v);
  const size_t old = buf_.size();
  buf_.resize(old + n);
  ea_encode(v, buf_.data() + old);
  return *this;
}

ByteWriter& ByteWriter::raw(const uint8_t* data, size_t len) {
  buf_.insert(buf_.end(), data, data + len);
  return *this;
}

ByteWriter& ByteWriter::raw(const std::vector<uint8_t>& data) {
  buf_.insert(buf_.end(), data.begin(), data.end());
  return *this;
}

ByteWriter& ByteWriter::ascii(std::string_view text) {
  buf_.insert(buf_.end(), text.begin(), text.end());
  return *this;
}

void ByteReader::need(size_t count) const {
  if (count > remaining()) {
    throw MalformedMessage("数据不够: 需要 " + std::to_string(count) + " 字节，只剩 " +
                           std::to_string(remaining()) + " 字节");
  }
}

uint8_t ByteReader::u8() {
  need(1);
  return data_[pos_++];
}

uint16_t ByteReader::u16be() {
  need(2);
  const uint16_t v = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
  pos_ += 2;
  return v;
}

uint16_t ByteReader::u16le() {
  need(2);
  const uint16_t v = static_cast<uint16_t>(data_[pos_] | (data_[pos_ + 1] << 8));
  pos_ += 2;
  return v;
}

uint32_t ByteReader::u32be() {
  need(4);
  const uint32_t v = (static_cast<uint32_t>(data_[pos_]) << 24) |
                     (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                     static_cast<uint32_t>(data_[pos_ + 3]);
  pos_ += 4;
  return v;
}

uint32_t ByteReader::u32le() {
  need(4);
  const uint32_t v = static_cast<uint32_t>(data_[pos_]) |
                     (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                     (static_cast<uint32_t>(data_[pos_ + 2]) << 16) |
                     (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
  pos_ += 4;
  return v;
}

uint32_t ByteReader::ea() {
  const EaDecoded r = ea_decode(data_, size_, pos_, size_);
  if (r.status == EaStatus::kNeedMore) throw MalformedMessage("EA 变长整数被截断");
  if (r.status == EaStatus::kUnterminated) throw MalformedMessage("EA 变长整数没有终止位");
  pos_ += r.size;
  return r.value;
}

std::vector<uint8_t> ByteReader::bytes(size_t count) {
  need(count);
  std::vector<uint8_t> out(data_ + pos_, data_ + pos_ + count);
  pos_ += count;
  return out;
}

void ByteReader::skip(size_t count) {
  need(count);
  pos_ += count;
}

std::vector<uint8_t> ByteReader::rest() { return bytes(remaining()); }

}  // namespace hicar
