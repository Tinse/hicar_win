#pragma once

#include <stdexcept>
#include <string>

namespace hicar {

// 收到对端数据不合协议时抛这个，收包处统一当作「对端数据不合法」处理。
class MalformedMessage : public std::runtime_error {
 public:
  explicit MalformedMessage(const std::string& what) : std::runtime_error(what) {}
};

}  // namespace hicar
