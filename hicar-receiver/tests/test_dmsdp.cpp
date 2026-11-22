#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "common/crc16_arc.h"
#include "common/error.h"
#include "dmsdp/cipher.h"
#include "dmsdp/framing.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::vector<uint8_t> bytes_of(std::initializer_list<uint8_t> list) {
  return std::vector<uint8_t>(list);
}

}  // namespace

int main() {
  using namespace hicar;
  using namespace hicar::dmsdp;

  // 会话帧布局
  {
    const auto frame = encode_session_frame(1, bytes_of({0x11, 0x22, 0x33}));
    check(frame.size() == 6 + 2, "会话帧总长 = 头+2 个 EA+载荷+CRC");
    check(frame[0] == 0x7F, "会话帧首字节 0x7F");
    check(frame[1] == 0x81, "module 1 的 EA");
    check(frame[2] == 0x83, "长度 3 的 EA");
    check(frame[3] == 0x11 && frame[4] == 0x22 && frame[5] == 0x33, "载荷原样");
    const uint16_t crc = crc16_arc(frame.data(), 6);
    check(frame[6] == static_cast<uint8_t>(crc & 0xFF), "CRC 低字节在前");
    check(frame[7] == static_cast<uint8_t>(crc >> 8), "CRC 高字节在后");
  }

  // 首轮协商应答
  {
    const auto raw = negotiation_reply(40000);
    SessionFrameDecoder decoder;
    decoder.append(raw.data(), raw.size());
    const auto frame = decoder.next();
    check(frame.has_value(), "协商应答可解");
    check(frame->module == 1, "协商应答 module 1");
    check(frame->payload.size() == kNegotiationBytes, "协商应答 16 字节");
    check(frame->payload[0] == 0, "结果 0");
    check(frame->payload[1] == 0x9C && frame->payload[2] == 0x40, "控制端口 BE16");
    bool tail_zero = true;
    for (size_t i = 3; i < frame->payload.size(); ++i) {
      if (frame->payload[i] != 0) tail_zero = false;
    }
    check(tail_zero, "端口后 13 个 0");
  }

  // 半包与粘包
  {
    const auto first = encode_session_frame(1, bytes_of({0x01, 0x02}));
    const auto second = encode_session_frame(1, bytes_of({0x03}));
    SessionFrameDecoder decoder;
    decoder.append(first.data(), 2);
    check(!decoder.next().has_value(), "不足一帧返回空");
    check(decoder.has_partial(), "保留半包");

    std::vector<uint8_t> rest;
    rest.insert(rest.end(), first.begin() + 2, first.end());
    rest.insert(rest.end(), second.begin(), second.end());
    decoder.append(rest.data(), rest.size());

    const auto a = decoder.next();
    check(a.has_value() && a->payload == bytes_of({0x01, 0x02}), "第一帧");
    const auto b = decoder.next();
    check(b.has_value() && b->payload == bytes_of({0x03}), "粘包第二帧");
    check(!decoder.next().has_value(), "取完为空");
    check(!decoder.has_partial(), "无残留");
  }

  // 校验与首字节错误
  {
    auto bad = encode_session_frame(1, bytes_of({0x01}));
    bad[bad.size() - 1] ^= 0xFF;
    SessionFrameDecoder decoder;
    decoder.append(bad.data(), bad.size());
    bool threw = false;
    try {
      (void)decoder.next();
    } catch (const MalformedMessage&) {
      threw = true;
    }
    check(threw, "CRC 错误抛异常");
  }
  {
    auto bad = encode_session_frame(1, bytes_of({0x01}));
    bad[0] = 0x7E;
    SessionFrameDecoder decoder;
    decoder.append(bad.data(), bad.size());
    bool threw = false;
    try {
      (void)decoder.next();
    } catch (const MalformedMessage&) {
      threw = true;
    }
    check(threw, "首字节不是 0x7F 抛异常");
  }

  // 控制帧
  {
    const auto plain = encode_control_frame(kControlPlain, bytes_of({0x24, 0x00}));
    check(plain.size() == 5, "控制帧 3 字节头 + 2 字节载荷");
    check(plain[0] == 0x00 && plain[1] == 0x00 && plain[2] == 0x02, "明文标志与 BE16 长度");
    ControlFrameDecoder decoder;
    decoder.append(plain.data(), 1);
    check(!decoder.next().has_value(), "控制帧半包");
    decoder.append(plain.data() + 1, plain.size() - 1);
    const auto frame = decoder.next();
    check(frame.has_value() && !frame->encrypted && frame->payload == bytes_of({0x24, 0x00}),
          "明文控制帧");
  }
  {
    const auto enc = encode_control_frame(kControlEncrypted, bytes_of({0xAB, 0xCD}));
    ControlFrameDecoder decoder;
    decoder.append(enc.data(), enc.size());
    const auto frame = decoder.next();
    check(frame.has_value() && frame->encrypted, "加密控制帧");
  }
  {
    bool threw = false;
    try {
      (void)encode_control_frame(kControlPlain, {});
    } catch (const std::invalid_argument&) {
      threw = true;
    }
    check(threw, "空控制载荷拒绝编码");
  }
  {
    ControlFrameDecoder decoder;
    const uint8_t bad[] = {0x12, 0x00, 0x01, 0x00};
    decoder.append(bad, sizeof(bad));
    bool threw = false;
    try {
      (void)decoder.next();
    } catch (const MalformedMessage&) {
      threw = true;
    }
    check(threw, "未知控制标志抛异常");
  }

  // 设备记录
  {
    std::vector<uint8_t> payload;
    const auto a = encode_device_record(1, -1, bytes_of({0x61, 0x62, 0x63}));
    const auto b = encode_device_record(4, 504, bytes_of({0x7B, 0x7D}));
    payload.insert(payload.end(), a.begin(), a.end());
    payload.insert(payload.end(), b.begin(), b.end());

    check(is_device_record(payload), "记录标记");
    check(!is_device_record(bytes_of({0x00})), "非记录");
    const auto records = parse_device_records(payload);
    check(records.size() == 2, "两条记录");
    check(records[0].module == 1 && records[0].type == -1, "module 1 type -1");
    check(records[0].data == bytes_of({0x61, 0x62, 0x63}), "第一条数据");
    check(records[1].module == 4 && records[1].type == 504, "module 4 type 504");
    check(records[1].data == bytes_of({0x7B, 0x7D}), "第二条数据");

    const auto encoded = encode_device_record(1, -1, bytes_of({0x61}));
    check(encoded.size() == kDeviceRecordHeaderBytes + 1, "记录头 11 字节");
    check(encoded[0] == 0x24, "标记 '$'");
    check(encoded[5] == 0xFF && encoded[6] == 0xFF && encoded[7] == 0xFF && encoded[8] == 0xFF,
          "type -1 线上全 FF");
  }
  {
    std::vector<uint8_t> truncated;
    const auto a = encode_device_record(1, 1, bytes_of({0x01, 0x02}));
    truncated.insert(truncated.end(), a.begin(), a.end() - 1);
    bool threw = false;
    try {
      (void)parse_device_records(truncated);
    } catch (const MalformedMessage&) {
      threw = true;
    }
    check(threw, "截断的设备记录抛异常");
  }
  {
    bool threw = false;
    try {
      (void)encode_device_record(1, 1, {});
    } catch (const std::invalid_argument&) {
      threw = true;
    }
    check(threw, "空设备数据拒绝编码");
  }

  // AES-128-CTR：NIST SP 800-38A F.5.1 向量（前两块）
  {
    const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    const std::vector<uint8_t> plain = bytes_of({
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
        0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51});
    const std::vector<uint8_t> expected = bytes_of({
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
        0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b,
        0xb9, 0xff, 0xfd, 0xff});
    const auto cipher = aes128_ctr_crypt(key, iv, plain.data(), plain.size());
    check(cipher == expected, "AES-128-CTR NIST 向量");
    const auto back = aes128_ctr_crypt(key, iv, cipher.data(), cipher.size());
    check(back == plain, "CTR 解密还原");

    const std::vector<uint8_t> iv_vec(iv, iv + 16);
    const auto sealed = seal_control_payload(key, iv, plain);
    check(sealed.size() == 16 + plain.size(), "加密载荷 = IV + 密文");
    check(open_control_payload(key, sealed) == plain, "控制载荷封装/解开");

    bool threw = false;
    try {
      (void)open_control_payload(key, bytes_of({0x00}));
    } catch (const MalformedMessage&) {
      threw = true;
    }
    check(threw, "加密载荷不足 IV 抛异常");
  }

  if (g_failures == 0) {
    std::puts("dmsdp framing: all checks passed");
    return 0;
  }
  std::fprintf(stderr, "dmsdp framing: %d failure(s)\n", g_failures);
  return 1;
}
