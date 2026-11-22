#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "common/error.h"
#include "common/hex.h"
#include "nearby/cipher.h"
#include "nearby/frame.h"
#include "nearby/tlv.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<uint8_t> bytes_of(std::initializer_list<uint8_t> list) { return std::vector<uint8_t>(list); }

bool throws_malformed(const std::vector<uint8_t>& data, size_t max_payload = 64 * 1024) {
  hicar::NearbyFrameDecoder decoder(max_payload);
  try {
    decoder.feed(data);
    while (decoder.next()) {
    }
  } catch (const hicar::MalformedMessage&) {
    return true;
  }
  return false;
}

}  // namespace

int main() {
  using namespace hicar;

  // TLV 编码 / 解析
  {
    const std::vector<uint8_t> seed = bytes_of({1, 2, 3, 4, 5, 6, 7, 8});
    const std::vector<uint8_t> encoded = encode_tlv(NearbyFrame::kSeedTag, seed);
    check(encoded.size() == 10, "种子 TLV 应为 10 字节");
    check(encoded[0] == 0x81 && encoded[1] == 0x88, "TLV 头应为 81 88");
    const std::vector<Tlv> parsed = parse_tlvs(encoded);
    check(parsed.size() == 1 && parsed[0].tag == 1 && parsed[0].value == seed, "TLV 往返");
    check(parse_tlvs(encode_tlv(15)).size() == 1, "空值 TLV");

    // 不完整 TLV 必须被拒绝
    const std::vector<uint8_t> truncated = bytes_of({0x81, 0x88, 0x01, 0x02});
    bool thrown = false;
    try {
      parse_tlvs(truncated);
    } catch (const MalformedMessage&) {
      thrown = true;
    }
    check(thrown, "不完整 TLV 抛异常");
  }

  // 明文帧字节布局
  {
    const NearbyFrame frame = NearbyFrame::plain(20, bytes_of({0xDE, 0xAD}));
    const std::vector<uint8_t> wire = frame.encode();
    check(wire.size() == 1 + 1 + 2 + 1 + 2 + 2, "明文帧长度");
    check(wire[0] == 0x7F, "帧头应为 7F");
    check(wire[1] == 0x94, "外层类型 20 应编码为 94");
    check(wire[2] == 0x80 && wire[3] == 0x80, "明文标志段应为 80 80");

    std::string hex = to_hex(wire);
    check(hex.rfind("7f94808082dead", 0) == 0, "帧前缀应为 7f948080 82 dead");

    NearbyFrameDecoder decoder;
    decoder.feed(wire);
    const auto got = decoder.next();
    check(got.has_value(), "单帧应能拆出");
    check(got->outer_type() == 20 && got->payload() == bytes_of({0xDE, 0xAD}), "明文帧往返");
    check(!got->is_encrypted(), "明文帧标志");
    check(!decoder.next().has_value(), "不应有第二帧");
  }

  // 加密帧：标志段 = 81 88 + 种子
  {
    const std::vector<uint8_t> seed = bytes_of({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
    const NearbyFrame frame = NearbyFrame::encrypted(19, bytes_of({0xAA, 0xBB}), seed);
    const std::vector<uint8_t> wire = frame.encode();
    check(wire[1] == 0x93, "外层类型 19 应编码为 93");
    check(wire[2] == 0x81 && wire[3] == 0x8A, "加密标志段头应为 81 8A");
    check(frame.is_encrypted() && frame.seed() == seed, "种子往返");

    NearbyFrameDecoder decoder;
    decoder.feed(wire);
    const auto got = decoder.next();
    check(got.has_value() && got->is_encrypted() && got->seed() == seed, "加密帧拆解");
    check(got && got->payload() == bytes_of({0xAA, 0xBB}), "密文载荷原样保留");
  }

  // 半帧、粘包、CRC 损坏
  {
    const std::vector<uint8_t> a = NearbyFrame::plain(1, bytes_of({0x01, 0x02, 0x03})).encode();
    const std::vector<uint8_t> b = NearbyFrame::plain(2, bytes_of({0x04, 0x05})).encode();

    NearbyFrameDecoder decoder;
    decoder.feed(a.data(), 3);
    check(!decoder.next().has_value(), "半帧应返回空");
    check(decoder.buffered() == 3, "半帧应留在缓冲");
    std::vector<uint8_t> rest(a.begin() + 3, a.end());
    rest.insert(rest.end(), b.begin(), b.end());
    decoder.feed(rest);
    std::vector<uint32_t> types;
    while (const auto f = decoder.next()) types.push_back(f->outer_type());
    check(types.size() == 2 && types[0] == 1 && types[1] == 2, "粘包应按顺序拆出");

    const std::vector<uint8_t> corrupted = a;
    std::vector<uint8_t> bad = corrupted;
    bad[bad.size() - 1] ^= 0xFF;
    check(throws_malformed(bad), "CRC 损坏应被拒绝");

    const std::vector<uint8_t> bad_head = bytes_of({0x7E, 0x80, 0x80, 0x80, 0x00, 0x00});
    check(throws_malformed(bad_head), "错误帧头应被拒绝");

    // 载荷长度超过上限
    const NearbyFrame huge = NearbyFrame::plain(3, std::vector<uint8_t>(70000, 0x00));
    check(throws_malformed(huge.encode(), 65536), "超长载荷应被拒绝");
  }

  // 帧密钥派生 + 载荷加解密
  {
    NearbyKeyMaterial keys;
    keys.const_a = bytes_of({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F});
    keys.const_b = bytes_of({0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                             0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF});
    keys.root_key = bytes_of({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F});
    const NearbyFrameCipher cipher(keys);

    // 手算校验派生根首字节：h1[11] = a[14] ^ b[11] = 0x0E ^ 0xFB = 0xF5；H[0] = 0xF5 ^ 0x10 = 0xE5
    const std::vector<uint8_t>& root = cipher.derived_root_for_test();
    check(root.size() == 16, "派生根长度");
    check(root[0] == 0xE5, "派生根首字节");

    const std::vector<uint8_t> seed = bytes_of({0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04});
    const std::vector<uint8_t> plain = bytes_of({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
    const std::vector<uint8_t> ct = cipher.encrypt(plain, seed);
    check(ct.size() == plain.size(), "密文长度应与明文相同");
    check(ct != plain, "密文应与明文不同");
    check(cipher.decrypt(ct, seed) == plain, "载荷加解密往返");

    const NearbyFrame sealed = cipher.seal(19, plain, seed);
    const std::vector<uint8_t> wire = sealed.encode();
    NearbyFrameDecoder decoder;
    decoder.feed(wire);
    const auto got = decoder.next();
    check(got.has_value() && cipher.open(*got) == plain, "加密帧 seal/open 往返");

    // 错误种子长度、错误密钥长度
    bool thrown = false;
    try {
      cipher.encrypt(plain, bytes_of({0x01}));
    } catch (const std::exception&) {
      thrown = true;
    }
    check(thrown, "错误种子长度应被拒绝");

    NearbyKeyMaterial short_keys = keys;
    short_keys.root_key.resize(4);
    short_keys.const_a.resize(4);
    short_keys.const_b.resize(4);
    thrown = false;
    try {
      NearbyFrameCipher bad(short_keys);
    } catch (const std::exception&) {
      thrown = true;
    }
    check(thrown, "过短密钥材料应被拒绝");
  }

  if (g_failures == 0) {
    std::puts("ALL PASSED");
    return 0;
  }
  std::fprintf(stderr, "%d 项失败\n", g_failures);
  return 1;
}
