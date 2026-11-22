#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hicar {
namespace dmsdp {

// AES-128-CTR：计数器初值为 IV，按大端递增；加解密是同一运算。
// 用于 DMSDP 控制连接：载荷 = IV(16) ‖ aes128_ctr(key, IV, 明文)。
std::vector<uint8_t> aes128_ctr_crypt(const uint8_t key[16], const uint8_t iv[16],
                                      const uint8_t* data, size_t size);

// 生成一帧加密控制载荷（IV 由调用方给出），返回 IV‖密文。
std::vector<uint8_t> seal_control_payload(const uint8_t key[16], const uint8_t iv[16],
                                          const std::vector<uint8_t>& plain);

// 解开一帧加密控制载荷（IV 取自前 16 字节）；不足 16 字节抛 MalformedMessage。
std::vector<uint8_t> open_control_payload(const uint8_t key[16], const std::vector<uint8_t>& sealed);

}  // namespace dmsdp
}  // namespace hicar
