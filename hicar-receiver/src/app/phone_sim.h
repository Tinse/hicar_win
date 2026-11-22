#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "nearby/cipher.h"

namespace hicar {

// 模拟手机端跑一遍控制通道：握手 → 开加密 → 请求业务 19 的 socket → 连上子端口发一段字节。
// 用来在没有真机时验证接收端的 TCP 通道与 nearby 状态机。
int run_phone_sim(const std::string& host, uint16_t port, const std::array<uint8_t, 6>& bluetooth,
                  const NearbyKeyMaterial& keys);

}  // namespace hicar
