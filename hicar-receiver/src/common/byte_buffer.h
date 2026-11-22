#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "common/error.h"
#include "common/ea.h"

namespace hicar {

// 按顺序拼字节，自动扩容。多字节整数分大端（be）和小端（le）。
class ByteWriter {
 public:
  ByteWriter() = default;
  explicit ByteWriter(size_t capacity) { buf_.reserve(capacity); }

  ByteWriter& u8(uint32_t v);
  ByteWriter& u16be(uint32_t v);
  ByteWriter& u16le(uint32_t v);
  ByteWriter& u32be(uint32_t v);
  ByteWriter& u32le(uint32_t v);
  ByteWriter& ea(uint32_t v);
  ByteWriter& raw(const uint8_t* data, size_t len);
  ByteWriter& raw(const std::vector<uint8_t>& data);
  ByteWriter& ascii(std::string_view text);

  size_t size() const { return buf_.size(); }
  const std::vector<uint8_t>& data() const { return buf_; }
  std::vector<uint8_t> take() { std::vector<uint8_t> out = std::move(buf_); buf_.clear(); return out; }

 private:
  std::vector<uint8_t> buf_;
};

// 按顺序从字节数组里读字段，带越界检查；越界抛 MalformedMessage。
class ByteReader {
 public:
  ByteReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}
  explicit ByteReader(const std::vector<uint8_t>& data) : data_(data.data()), size_(data.size()) {}

  uint8_t u8();
  uint16_t u16be();
  uint16_t u16le();
  uint32_t u32be();
  uint32_t u32le();
  uint32_t ea();

  std::vector<uint8_t> bytes(size_t count);
  void skip(size_t count);
  std::vector<uint8_t> rest();

  size_t position() const { return pos_; }
  size_t remaining() const { return size_ - pos_; }

 private:
  void need(size_t count) const;

  const uint8_t* data_;
  size_t size_;
  size_t pos_ = 0;
};

}  // namespace hicar
