#pragma once

#include "identity/host_identity.h"
#include "nearby/cipher.h"

namespace hicar {

// 默认身份资产：与 OpenHC 的 openhc-identity.json 相同（车型 000480、子编号 00、三段 16 字节密钥）。
// 想换身份时直接用 NearbyKeyMaterial 覆盖即可。
NearbyKeyMaterial default_nearby_keys();
HostIdentity default_host_identity();

}  // namespace hicar
