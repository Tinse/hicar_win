#pragma once

#include <cstddef>
#include <cstdint>

namespace hicar {

// CRC-16/ARC：多项式 0x8005（反射形式 0xA001），初值 0，输入输出反射，无最终异或。
// "123456789" 的校验值为 0xBB3D。帧尾按小端写。
uint16_t crc16_arc(const uint8_t* data, size_t size);

}  // namespace hicar
