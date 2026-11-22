#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "common/byte_buffer.h"
#include "common/crc16_arc.h"
#include "common/ea.h"
#include "common/hex.h"
#include "nearby/car_info.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<uint8_t> bytes_of(std::initializer_list<uint8_t> list) { return std::vector<uint8_t>(list); }

}  // namespace

int main() {
  using namespace hicar;

  // EA 编码：最短形式
  {
    struct Case {
      uint32_t value;
      std::vector<uint8_t> encoded;
    } cases[] = {
        {0, bytes_of({0x80})},
        {1, bytes_of({0x81})},
        {127, bytes_of({0xFF})},
        {128, bytes_of({0x00, 0x81})},
        {155, bytes_of({0x1B, 0x81})},
        {0x0FFFFFFF, bytes_of({0x7F, 0x7F, 0x7F, 0xFF})},
    };
    for (const auto& c : cases) {
      std::vector<uint8_t> out(ea_encoded_size(c.value));
      ea_encode(c.value, out.data());
      check(out == c.encoded, "EA 编码");
      const EaDecoded d = ea_decode(out.data(), out.size(), 0, out.size());
      check(d.status == EaStatus::kOk && d.value == c.value && d.size == out.size(), "EA 解码");
    }
    // 非最短形式 00 80 = 0，占 2 字节
    const std::vector<uint8_t> non_minimal = bytes_of({0x00, 0x80});
    const EaDecoded d = ea_decode(non_minimal.data(), non_minimal.size(), 0, non_minimal.size());
    check(d.status == EaStatus::kOk && d.value == 0 && d.size == 2, "EA 接受非最短形式");
    // 截断 / 无终止位
    const std::vector<uint8_t> truncated = bytes_of({0x00});
    check(ea_decode(truncated.data(), truncated.size(), 0, truncated.size()).status == EaStatus::kNeedMore,
          "EA 需更多数据");
    const std::vector<uint8_t> unterminated = bytes_of({0x01, 0x02, 0x03, 0x04});
    check(ea_decode(unterminated.data(), unterminated.size(), 0, unterminated.size()).status ==
              EaStatus::kUnterminated,
          "EA 无终止位");
  }

  // CRC-16/ARC 标准校验值
  {
    const std::string text = "123456789";
    const uint16_t crc = crc16_arc(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    check(crc == 0xBB3D, "CRC-16/ARC 校验值应为 0xBB3D");
  }

  // 十六进制往返
  {
    const std::vector<uint8_t> v = bytes_of({0x00, 0x7F, 0x80, 0xFF});
    check(from_hex(to_hex(v)) == v, "hex 往返");
    check(from_hex("00:7f-80_ff") == v, "hex 分隔符");
  }

  // carInfo 编码与解析
  {
    CarInfo info;
    info.model_id = {0x00, 0x04, 0x80};
    info.sub_model_id = 0x00;
    for (size_t i = 0; i < info.device_id.size(); ++i) info.device_id[i] = static_cast<uint8_t>(i);
    info.bluetooth_address = {0x02, 0x12, 0x34, 0x56, 0x78, 0x9A};
    info.host_ip = "192.168.66.150";
    info.port = 32400;

    const std::vector<uint8_t> out = info.encode();
    check(out.size() == CarInfo::kLength, "carInfo 长度应为 91");
    check(std::memcmp(out.data(), "hwnearby", 8) == 0, "carInfo 魔数");
    check(out[8] == 0x5B && out[9] == 0x00, "carInfo 总长字段应是小端 91");
    check(out[19] == 0x01 && out[20] == 0x03 && out[21] == 0x00, "carInfo 首个 TLV 应为 01 03 00");
    check(out[22] == 0x04 && out[23] == 0x80, "carInfo 车型编号应为 00 04 80");

    const CarInfo parsed = CarInfo::parse(out);
    check(parsed.host_ip == info.host_ip, "carInfo IP 往返");
    check(parsed.port == info.port, "carInfo 端口往返");
    check(parsed.model_id == info.model_id, "carInfo 车型编号往返");
    check(parsed.device_id == info.device_id, "carInfo deviceId 往返");
    check(parsed.bluetooth_address == info.bluetooth_address, "carInfo 蓝牙地址往返");

    bool rejected = false;
    try {
      CarInfo bad = info;
      bad.host_ip = "192.168.66.1";  // 13 字符
      bad.encode();
    } catch (const std::exception&) {
      rejected = true;
    }
    check(rejected, "carInfo 拒绝非 14 字符 IP");

    check(CarInfo::is_valid_host_ip("192.168.66.100") && CarInfo::is_valid_host_ip("192.168.66.253"),
          "合法 IP 判定");
    check(!CarInfo::is_valid_host_ip("192.168.066.1") && !CarInfo::is_valid_host_ip("256.1.1.1"),
          "非法 IP 判定");
  }

  // ByteReader 越界
  {
    const std::vector<uint8_t> small = bytes_of({0x01, 0x02});
    bool thrown = false;
    try {
      ByteReader r(small);
      r.bytes(3);
    } catch (const MalformedMessage&) {
      thrown = true;
    }
    check(thrown, "ByteReader 越界抛 MalformedMessage");
  }

  if (g_failures == 0) {
    std::puts("ALL PASSED");
    return 0;
  }
  std::fprintf(stderr, "%d 项失败\n", g_failures);
  return 1;
}
