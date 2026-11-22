#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace hicar {

// 车机身份（身份资产里 host 的三项，deviceName/brand 只用于日志与展示）。
struct HostIdentity {
  std::array<uint8_t, 3> model_id = {0x00, 0x04, 0x80};
  uint8_t sub_model_id = 0x00;
  std::string brand = "car";
  std::string device_name = "HiCar-Windows";
};

}  // namespace hicar
