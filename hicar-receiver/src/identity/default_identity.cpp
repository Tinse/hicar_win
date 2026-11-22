#include "identity/default_identity.h"

#include "common/hex.h"

namespace hicar {

NearbyKeyMaterial default_nearby_keys() {
  NearbyKeyMaterial keys;
  keys.root_key = from_hex("34C7D0D1AF0823106903A6DAB1C3039D");
  keys.const_a = from_hex("02722AA7E390FB1E68995638F41D5AD7");
  keys.const_b = from_hex("57F6B9D905EF238BA31438BEAD22A248");
  return keys;
}

HostIdentity default_host_identity() {
  HostIdentity host;
  host.model_id = {0x00, 0x04, 0x80};
  host.sub_model_id = 0x00;
  host.brand = "car";
  host.device_name = "HiCar-Windows";
  return host;
}

}  // namespace hicar
