#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace hicar {
namespace platform {

// Winsock 初始化 / 清理（进程内只做一次）。
class WinsockInit {
 public:
  WinsockInit();
  ~WinsockInit();
  WinsockInit(const WinsockInit&) = delete;
  WinsockInit& operator=(const WinsockInit&) = delete;
  bool ok() const { return ok_; }

 private:
  bool ok_ = false;
};

// 阻塞式 TCP 套接字，移动语义，析构自动关闭。
class TcpSocket {
 public:
  TcpSocket() = default;
  explicit TcpSocket(uintptr_t handle);
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;
  ~TcpSocket();
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;

  bool valid() const { return handle_ != kInvalid; }
  uintptr_t native() const { return handle_; }
  void close();

  bool set_nonblocking(bool enabled, std::string* error);
  std::optional<TcpSocket> accept(std::string* error);
  // 返回读到的字节数；0 表示对端关闭；std::nullopt 表示错误（非阻塞下 would-block 也返回 nullopt 并置 error 为空）。
  std::optional<size_t> recv_some(void* buffer, size_t size, std::string* error);
  bool send_all(const void* data, size_t size, std::string* error);
  uint16_t local_port() const;
  std::string peer_ip() const;

  static std::optional<TcpSocket> listen_on(const std::string& ip, uint16_t port, std::string* error);
  static std::optional<TcpSocket> connect_to(const std::string& ip, uint16_t port, std::string* error);

  static constexpr uintptr_t kInvalid = static_cast<uintptr_t>(~0ull);

 private:
  uintptr_t handle_ = kInvalid;
};

}  // namespace platform
}  // namespace hicar
