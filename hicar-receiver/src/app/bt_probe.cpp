#include <winsock2.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "app/bt_probe.h"
#include "common/hex.h"
#include "platform/bluetooth.h"
#include "platform/tcp.h"

namespace hicar {

namespace {

uint64_t now_millis() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
}

}  // namespace

int run_bluetooth_probe(int seconds) {
  platform::WinsockInit winsock;
  if (!winsock.ok()) {
    std::fputs("WSAStartup 失败\n", stderr);
    return 1;
  }

  std::string error;
  const auto radio = platform::find_first_radio(&error);
  if (!radio.has_value()) {
    std::fprintf(stderr, "%s\n", error.c_str());
    return 1;
  }
  wprintf(L"蓝牙无线电：%s\n", radio->name.c_str());
  std::printf("地址：%s\n", platform::format_bluetooth_address(radio->bytes).c_str());

  platform::RfcommListener listener;
  if (!listener.listen(radio->address, 0, &error)) {
    std::fprintf(stderr, "%s\n", error.c_str());
    return 1;
  }
  std::printf("RFCOMM 监听通道：%u\n", listener.channel());

  if (!listener.publish_sdp(&error)) {
    std::fprintf(stderr, "SDP 发布失败：%s\n", error.c_str());
    return 1;
  }
  std::puts("SDP 已发布：UUID 0000FE35，服务名 HiCar Receiver");

  const uint64_t deadline = now_millis() + static_cast<uint64_t>(seconds) * 1000;
  std::puts("等待连接（Ctrl+C 结束）…");
  std::fflush(stdout);

  std::vector<platform::TcpSocket> connections;
  while (now_millis() < deadline) {
    fd_set read_set;
    FD_ZERO(&read_set);
    SOCKET max_socket = static_cast<SOCKET>(listener.native());
    FD_SET(max_socket, &read_set);
    for (const auto& connection : connections) {
      const SOCKET handle = static_cast<SOCKET>(connection.native());
      FD_SET(handle, &read_set);
      if (handle > max_socket) max_socket = handle;
    }
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 100 * 1000;
    const int ready = select(0, &read_set, nullptr, nullptr, &timeout);
    if (ready <= 0) continue;

    if (FD_ISSET(static_cast<SOCKET>(listener.native()), &read_set)) {
      std::string accept_error;
      auto accepted = listener.accept(&accept_error);
      if (accepted.has_value()) {
        std::puts("有蓝牙连接进来了");
        connections.push_back(std::move(*accepted));
      } else {
        std::fprintf(stderr, "%s\n", accept_error.c_str());
      }
    }

    for (auto& connection : connections) {
      if (!connection.valid()) continue;
      const SOCKET handle = static_cast<SOCKET>(connection.native());
      if (!FD_ISSET(handle, &read_set)) continue;
      uint8_t buffer[1024];
      std::string read_error;
      connection.set_nonblocking(true, nullptr);
      const auto got = connection.recv_some(buffer, sizeof(buffer), &read_error);
      if (!got.has_value()) {
        if (read_error.empty()) continue;  // 只是 would-block
        std::fprintf(stderr, "读失败：%s\n", read_error.c_str());
        connection.close();
        continue;
      }
      if (*got == 0) {
        std::puts("连接关闭");
        connection.close();
        continue;
      }
      std::printf("收到 %zu 字节：%s\n", *got, to_hex(buffer, *got).c_str());
    }
  }
  std::puts("诊断结束");
  return 0;
}

}  // namespace hicar
