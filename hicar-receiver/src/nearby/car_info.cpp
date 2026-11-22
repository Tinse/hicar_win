#include "nearby/car_info.h"

#include <cstdio>
#include <cstring>
#include <map>

#include "common/byte_buffer.h"
#include "common/error.h"

namespace hicar {

namespace {

constexpr uint8_t kMagic[8] = {'h', 'w', 'n', 'e', 'a', 'r', 'b', 'y'};
constexpr uint8_t kFixedHeader[9] = {0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01};

constexpr uint8_t kTagModelId = 1;
constexpr uint8_t kTagSubModelId = 2;
constexpr uint8_t kTagDeviceId = 3;
constexpr uint8_t kTagBluetooth = 4;
constexpr uint8_t kTagHostIp = 6;
constexpr uint8_t kTagPort = 7;

constexpr size_t field_size(uint8_t tag) {
  switch (tag) {
    case kTagModelId: return CarInfo::kModelIdSize;
    case kTagSubModelId: return 1;
    case kTagDeviceId: return CarInfo::kDeviceIdSize;
    case kTagBluetooth: return CarInfo::kBluetoothSize;
    case kTagHostIp: return CarInfo::kHostIpLength;
    case kTagPort: return 4;
    default: return 0;
  }
}

void put_field(ByteWriter& w, uint8_t tag, const uint8_t* data, size_t size) {
  w.u8(tag).u8(static_cast<uint32_t>(size)).raw(data, size);
}

}  // namespace

bool CarInfo::is_valid_host_ip(const std::string& ip) {
  if (ip.size() != kHostIpLength) return false;
  size_t index = 0;
  for (int part = 0; part < 4; ++part) {
    const size_t start = index;
    int value = 0;
    while (index < ip.size() && ip[index] != '.') {
      if (ip[index] < '0' || ip[index] > '9') return false;
      value = value * 10 + (ip[index] - '0');
      if (value > 255) return false;
      ++index;
    }
    const size_t digits = index - start;
    if (digits == 0 || digits > 3) return false;
    if (digits > 1 && ip[start] == '0') return false;  // 不允许前导 0
    if (part < 3) {
      if (index >= ip.size() || ip[index] != '.') return false;
      ++index;
    }
  }
  return index == ip.size();
}

bool CarInfo::is_valid_port(uint32_t port) { return port >= 1 && port <= 65535; }

std::vector<uint8_t> CarInfo::encode() const {
  if (!is_valid_host_ip(host_ip)) throw std::invalid_argument("车机 IP 必须是 14 字符的规范 IPv4 文本");
  if (!is_valid_port(port)) throw std::invalid_argument("端口必须在 1..65535");

  ByteWriter w(kLength);
  w.raw(kMagic, sizeof(kMagic));
  w.u16le(static_cast<uint32_t>(kLength));
  w.raw(kFixedHeader, sizeof(kFixedHeader));
  put_field(w, kTagModelId, model_id.data(), model_id.size());
  put_field(w, kTagSubModelId, &sub_model_id, 1);
  put_field(w, kTagDeviceId, device_id.data(), device_id.size());
  put_field(w, kTagBluetooth, bluetooth_address.data(), bluetooth_address.size());
  put_field(w, kTagHostIp, reinterpret_cast<const uint8_t*>(host_ip.data()), host_ip.size());
  ByteWriter port_writer(4);
  port_writer.u32le(port);
  put_field(w, kTagPort, port_writer.data().data(), 4);

  if (w.size() != kLength) throw std::invalid_argument("carInfo 长度不等于 91");
  return w.take();
}

CarInfo CarInfo::parse(const std::vector<uint8_t>& data) {
  if (data.size() != kLength) throw MalformedMessage("carInfo 应为 91 字节");
  ByteReader r(data);
  const std::vector<uint8_t> magic = r.bytes(sizeof(kMagic));
  if (std::memcmp(magic.data(), kMagic, sizeof(kMagic)) != 0) throw MalformedMessage("carInfo 魔数不对");
  if (r.u16le() != kLength) throw MalformedMessage("carInfo 总长字段不对");
  const std::vector<uint8_t> header = r.bytes(sizeof(kFixedHeader));
  if (std::memcmp(header.data(), kFixedHeader, sizeof(kFixedHeader)) != 0) {
    throw MalformedMessage("carInfo 固定头与已知布局不符");
  }

  CarInfo out;
  std::map<uint8_t, std::vector<uint8_t>> fields;
  while (r.remaining() > 0) {
    const uint8_t tag = r.u8();
    const uint8_t len = r.u8();
    const size_t expected = field_size(tag);
    if (expected == 0) throw MalformedMessage("carInfo 出现未知 tag");
    if (len != expected) throw MalformedMessage("carInfo tag 长度不对");
    if (!fields.emplace(tag, r.bytes(len)).second) throw MalformedMessage("carInfo tag 重复");
  }

  for (uint8_t tag : {kTagModelId, kTagSubModelId, kTagDeviceId, kTagBluetooth, kTagHostIp, kTagPort}) {
    if (fields.find(tag) == fields.end()) throw MalformedMessage("carInfo 缺少 tag");
  }

  const std::vector<uint8_t>& ip_bytes = fields[kTagHostIp];
  for (uint8_t b : ip_bytes) {
    if (b < 0x20 || b > 0x7E) throw MalformedMessage("carInfo 的 IP 文本不是 ASCII");
  }
  out.host_ip.assign(reinterpret_cast<const char*>(ip_bytes.data()), ip_bytes.size());
  if (!is_valid_host_ip(out.host_ip)) throw MalformedMessage("carInfo 的 IP 文本不是规范 IPv4");

  out.port = ByteReader(fields[kTagPort]).u32le();
  if (!is_valid_port(out.port)) throw MalformedMessage("carInfo 端口越界");

  std::memcpy(out.model_id.data(), fields[kTagModelId].data(), kModelIdSize);
  out.sub_model_id = fields[kTagSubModelId][0];
  std::memcpy(out.device_id.data(), fields[kTagDeviceId].data(), kDeviceIdSize);
  std::memcpy(out.bluetooth_address.data(), fields[kTagBluetooth].data(), kBluetoothSize);
  return out;
}

}  // namespace hicar
