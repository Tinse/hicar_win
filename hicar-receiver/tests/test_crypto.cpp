#include <cstdio>
#include <string>
#include <vector>

#include "common/hex.h"
#include "crypto/aes128.h"
#include "crypto/sha256.h"
#include "identity/device_id.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<uint8_t> bytes_of(const std::string& hex) {
  std::vector<uint8_t> out;
  int hi = -1;
  for (char c : hex) {
    if (c == ' ' || c == '\n') continue;
    int v = 0;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else { ++g_failures; return {}; }
    if (hi < 0) hi = v;
    else { out.push_back(static_cast<uint8_t>((hi << 4) | v)); hi = -1; }
  }
  return out;
}

std::string hex_of(const uint8_t* data, size_t size) { return hicar::to_hex(data, size); }

}  // namespace

int main() {
  using namespace hicar;

  // SHA-256 标准向量（FIPS 180-4）
  {
    check(hex_of(sha256(nullptr, 0).data(), 32) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "SHA-256 空串");
    const std::string abc = "abc";
    check(hex_of(sha256(reinterpret_cast<const uint8_t*>(abc.data()), abc.size()).data(), 32) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256 abc");
    // 跨块边界（56 字节触发两个分组）
    const std::string abcd = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check(hex_of(sha256(reinterpret_cast<const uint8_t*>(abcd.data()), abcd.size()).data(), 32) ==
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "SHA-256 448 位消息");
  }

  // HMAC-SHA256（RFC 4231 用例 2）
  {
    const std::vector<uint8_t> key = bytes_of("4a656665");  // "Jefe"
    const std::vector<uint8_t> data = bytes_of("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
    check(hex_of(hmac_sha256(key, data).data(), 32) ==
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "HMAC-SHA256 RFC4231 case2");
  }

  // AES-128 单块（FIPS-197 附录 C.1）
  {
    const std::vector<uint8_t> key = bytes_of("000102030405060708090a0b0c0d0e0f");
    const std::vector<uint8_t> in = bytes_of("00112233445566778899aabbccddeeff");
    uint8_t out[16];
    aes128_encrypt_block(key.data(), in.data(), out);
    check(to_hex(out, 16) == "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 单块向量");
  }

  // AES-128-CFB128（NIST SP 800-38A F.3.13 / CFB128.AES）
  {
    const std::vector<uint8_t> key = bytes_of("2b7e151628aed2a6abf7158809cf4f3c");
    const std::vector<uint8_t> iv = bytes_of("000102030405060708090a0b0c0d0e0f");
    const std::vector<uint8_t> plain = bytes_of(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710");
    const std::vector<uint8_t> want = bytes_of(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6");
    const std::vector<uint8_t> got = aes128_cfb_encrypt(key.data(), iv.data(), plain.data(), plain.size());
    check(got == want, "AES-128-CFB128 加密向量");
    const std::vector<uint8_t> back = aes128_cfb_decrypt(key.data(), iv.data(), got.data(), got.size());
    check(back == plain, "AES-128-CFB128 解密还原");

    // 截断到 20 字节仍应是完整密文的前缀（流式语义）
    const std::vector<uint8_t> short_ct = aes128_cfb_encrypt(key.data(), iv.data(), plain.data(), 20);
    std::vector<uint8_t> prefix(want.begin(), want.begin() + 20);
    check(short_ct == prefix, "AES-CFB 前缀性质");
  }

  // 设备 ID 结构与派生稳定性
  {
    const std::array<uint8_t, 3> model = {0x00, 0x04, 0x80};
    const std::array<uint8_t, 6> bt = {0x02, 0x12, 0x34, 0x56, 0x78, 0x9A};
    const std::array<uint8_t, 32> a = derive_device_id(model, 0x00, bt);
    const std::array<uint8_t, 32> b = derive_device_id(model, 0x00, bt);
    const std::string text = device_id_hex(a);
    check(text.size() == 64, "deviceId 文本应为 64 字符");
    check(text == device_id_hex(b), "deviceId 派生稳定");
    bool upper_only = true;
    for (char c : text) {
      if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) upper_only = false;
    }
    check(upper_only, "deviceId 应全大写十六进制");

    // 蓝牙地址不可用时改用 6 个 0 字节，等价于 02:00:00:00:00:00
    const std::array<uint8_t, 6> unavailable = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
    const std::array<uint8_t, 6> zeros{};
    check(derive_device_id(model, 0x00, unavailable) == derive_device_id(model, 0x00, zeros),
          "deviceId 蓝牙不可用分支");
  }

  if (g_failures == 0) {
    std::puts("ALL PASSED");
    return 0;
  }
  std::fprintf(stderr, "%d 项失败\n", g_failures);
  return 1;
}
