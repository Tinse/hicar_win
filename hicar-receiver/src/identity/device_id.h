#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace hicar {

// 车机设备 ID：SHA-256(UTF-8(大写十六进制(车型编号 3 字节 ‖ 子编号 1 字节 ‖ 蓝牙地址 6 字节)))
// 蓝牙地址为 02:00:00:00:00:00 时，哈希输入改用 6 个 0 字节。
std::array<uint8_t, 32> derive_device_id(const std::array<uint8_t, 3>& model_id, uint8_t sub_model_id,
                                         const std::array<uint8_t, 6>& bluetooth_address);

// 64 位大写十六进制文本。
std::string device_id_hex(const std::array<uint8_t, 32>& device_id);

}  // namespace hicar
