#include <winsock2.h>

#include <cstdio>

#include "app/phone_sim.h"

#include "common/byte_buffer.h"
#include "common/hex.h"
#include "nearby/channel_management.h"
#include "nearby/frame.h"
#include "nearby/session.h"
#include "nearby/socket_messages.h"
#include "nearby/tlv.h"
#include "platform/tcp.h"

namespace hicar {

namespace {

std::optional<NearbyFrame> read_frame(platform::TcpSocket& socket, NearbyFrameDecoder& decoder) {
  uint8_t buffer[4096];
  for (int attempt = 0; attempt < 200; ++attempt) {
    if (const auto frame = decoder.next()) return frame;
    std::string error;
    const auto got = socket.recv_some(buffer, sizeof(buffer), &error);
    if (!got.has_value()) {
      if (!error.empty()) {
        std::fprintf(stderr, "读失败：%s\n", error.c_str());
        return std::nullopt;
      }
      Sleep(10);
      continue;
    }
    if (*got == 0) return std::nullopt;
    decoder.feed(std::vector<uint8_t>(buffer, buffer + *got));
  }
  return std::nullopt;
}

void print_payload(const std::vector<uint8_t>& payload) {
  for (const Tlv& tlv : parse_tlvs(payload)) {
    std::printf("    tag %u，%zu 字节，值 %s\n", tlv.tag, tlv.value.size(),
                to_hex(tlv.value).c_str());
  }
}

}  // namespace

int run_phone_sim(const std::string& host, uint16_t port, const std::array<uint8_t, 6>& bluetooth,
                  const NearbyKeyMaterial& keys) {
  (void)bluetooth;
  platform::WinsockInit winsock;
  if (!winsock.ok()) {
    std::fputs("WSAStartup 失败\n", stderr);
    return 1;
  }
  std::string error;
  auto socket = platform::TcpSocket::connect_to(host, port, &error);
  if (!socket.has_value()) {
    std::fprintf(stderr, "连接 %s:%u 失败：%s\n", host.c_str(), port, error.c_str());
    return 1;
  }
  const int timeout = 3000;
  setsockopt(static_cast<SOCKET>(socket->native()), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
             sizeof(timeout));
  std::printf("已连接接收端 %s:%u\n", host.c_str(), port);

  NearbyFrameCipher cipher(keys);
  NearbyFrameDecoder decoder;

  // 1. 连接后第一条是明文 connectId
  const auto connect_frame = read_frame(*socket, decoder);
  if (!connect_frame.has_value()) {
    std::fputs("没有收到 connectId 帧\n", stderr);
    return 1;
  }
  std::printf("收到首帧：外层 %u，加密 %s\n", connect_frame->outer_type(),
              connect_frame->is_encrypted() ? "是" : "否");
  print_payload(connect_frame->payload());

  // 2. 版本 + 摘要 + 开加密
  std::vector<uint8_t> summary{'A', '1', 'B', '2', 'C', '3', 'D', '4', 'E', '5', 'F', '6', 0};
  const std::vector<uint8_t> hello =
      ByteWriter()
          .raw(encode_tlv(channel_management::kTagVersionRequest, std::vector<uint8_t>{5, 0}))
          .raw(encode_tlv(channel_management::kTagSummaryRequest, summary))
          .raw(encode_tlv(channel_management::kTagEncryptionRequest, std::vector<uint8_t>{1}))
          .take();
  std::vector<uint8_t> hello_frame = NearbyFrame::plain(0, hello).encode();
  socket->send_all(hello_frame.data(), hello_frame.size(), nullptr);

  // 3. 接收两帧：tag7（加密）和握手应答（加密）
  for (int i = 0; i < 2; ++i) {
    const auto frame = read_frame(*socket, decoder);
    if (!frame.has_value()) {
      std::fputs("没有收到握手应答\n", stderr);
      return 1;
    }
    std::printf("收到应答帧：外层 %u，加密 %s\n", frame->outer_type(), frame->is_encrypted() ? "是" : "否");
    print_payload(cipher.open(*frame));
  }

  // 4. 请求业务 19 的 socket
  socket_messages::Request request;
  request.channel = NearbySession::kChannelUsb;
  request.business_id = NearbySession::kBusinessAuth;
  request.tag = {'h', 'i', 'c', 'a', 'r', 'A', 'u', 't', 'h'};
  request.protocol = socket_messages::kProtocolTcp;
  const std::vector<uint8_t> request_payload =
      encode_tlv(socket_messages::kCmdCreateRequest, socket_messages::encode_request(request));
  const std::vector<uint8_t> request_frame =
      cipher.seal(socket_messages::kOuterResource, request_payload, std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 8})
          .encode();
  socket->send_all(request_frame.data(), request_frame.size(), nullptr);

  // 5. 读回端口并连上去
  const auto response_frame = read_frame(*socket, decoder);
  if (!response_frame.has_value()) {
    std::fputs("没有收到建 socket 应答\n", stderr);
    return 1;
  }
  const auto payload = cipher.open(*response_frame);
  const auto tlvs = parse_tlvs(payload);
  if (tlvs.size() != 1 || tlvs[0].tag != socket_messages::kCmdCreateResponse) {
    std::fputs("应答格式不对\n", stderr);
    return 1;
  }
  const auto response = socket_messages::parse_response(tlvs[0].value);
  std::printf("建 socket 应答：状态 %u，端口 %u，通道 %u，业务 %u，协议 %u\n", response.status, response.port,
              response.channel, response.business_id, response.protocol);
  if (response.status != socket_messages::kStatusAccepted) return 1;

  auto auth = platform::TcpSocket::connect_to(host, static_cast<uint16_t>(response.port), &error);
  if (!auth.has_value()) {
    std::fprintf(stderr, "连接业务端口失败：%s\n", error.c_str());
    return 1;
  }
  const std::vector<uint8_t> probe = {'{', '"', 't', 'e', 's', 't', '"', ':', '"', 'a', 'u', 't', 'h', '"', '}'};
  auth->send_all(probe.data(), probe.size(), nullptr);
  std::puts("已向业务 19 端口发送测试 JSON，完成");
  return 0;
}

}  // namespace hicar
