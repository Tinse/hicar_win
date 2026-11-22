#include <winsock2.h>
#include <ws2tcpip.h>

#include "platform/tcp.h"

#include <algorithm>

namespace hicar {
namespace platform {

namespace {

constexpr SOCKET kInvalidSocket = INVALID_SOCKET;

SOCKET to_socket(uintptr_t handle) { return static_cast<SOCKET>(handle); }

std::string last_error_text() {
  const int code = WSAGetLastError();
  char* text = nullptr;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, static_cast<DWORD>(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 reinterpret_cast<char*>(&text), 0, nullptr);
  std::string out = "WSA " + std::to_string(code);
  if (text != nullptr) {
    out += ": ";
    out += text;
    LocalFree(text);
  }
  return out;
}

}  // namespace

WinsockInit::WinsockInit() {
  WSADATA data{};
  ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

WinsockInit::~WinsockInit() {
  if (ok_) WSACleanup();
}

TcpSocket::TcpSocket(uintptr_t handle) : handle_(handle) {}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : handle_(other.handle_) { other.handle_ = kInvalid; }

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalid;
  }
  return *this;
}

TcpSocket::~TcpSocket() { close(); }

void TcpSocket::close() {
  if (handle_ != kInvalid) {
    closesocket(to_socket(handle_));
    handle_ = kInvalid;
  }
}

bool TcpSocket::set_nonblocking(bool enabled, std::string* error) {
  u_long mode = enabled ? 1 : 0;
  if (ioctlsocket(to_socket(handle_), FIONBIO, &mode) != 0) {
    if (error != nullptr) *error = last_error_text();
    return false;
  }
  return true;
}

std::optional<TcpSocket> TcpSocket::accept(std::string* error) {
  SOCKADDR_STORAGE address{};
  int length = sizeof(address);
  const SOCKET accepted = ::accept(to_socket(handle_), reinterpret_cast<sockaddr*>(&address), &length);
  if (accepted == kInvalidSocket) {
    if (error != nullptr) *error = last_error_text();
    return std::nullopt;
  }
  return TcpSocket(static_cast<uintptr_t>(accepted));
}

std::optional<size_t> TcpSocket::recv_some(void* buffer, size_t size, std::string* error) {
  const int got = ::recv(to_socket(handle_), static_cast<char*>(buffer), static_cast<int>(size), 0);
  if (got < 0) {
    const int code = WSAGetLastError();
    if (code == WSAEWOULDBLOCK || code == WSAEINTR) {
      if (error != nullptr) error->clear();
      return std::nullopt;
    }
    if (error != nullptr) *error = last_error_text();
    return std::nullopt;
  }
  return static_cast<size_t>(got);
}

bool TcpSocket::send_all(const void* data, size_t size, std::string* error) {
  const char* cursor = static_cast<const char*>(data);
  size_t left = size;
  while (left > 0) {
    const int sent = ::send(to_socket(handle_), cursor, static_cast<int>(left), 0);
    if (sent <= 0) {
      const int code = WSAGetLastError();
      if (code == WSAEWOULDBLOCK) {
        Sleep(1);
        continue;
      }
      if (error != nullptr) *error = last_error_text();
      return false;
    }
    cursor += sent;
    left -= static_cast<size_t>(sent);
  }
  return true;
}

uint16_t TcpSocket::local_port() const {
  SOCKADDR_IN address{};
  int length = sizeof(address);
  if (getsockname(to_socket(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) return 0;
  return ntohs(address.sin_port);
}

std::string TcpSocket::peer_ip() const {
  SOCKADDR_IN address{};
  int length = sizeof(address);
  if (getpeername(to_socket(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) return {};
  char text[INET_ADDRSTRLEN] = {};
  if (InetNtopA(AF_INET, &address.sin_addr, text, sizeof(text)) == nullptr) return {};
  return text;
}

std::optional<TcpSocket> TcpSocket::listen_on(const std::string& ip, uint16_t port, std::string* error) {
  const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kInvalidSocket) {
    if (error != nullptr) *error = last_error_text();
    return std::nullopt;
  }
  TcpSocket out(static_cast<uintptr_t>(socket));

  const BOOL exclusive = FALSE;
  setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

  SOCKADDR_IN address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (ip.empty()) {
    address.sin_addr.S_un.S_addr = INADDR_ANY;
  } else if (InetPtonA(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
    if (error != nullptr) *error = "无效的 IPv4 地址: " + ip;
    return std::nullopt;
  }
  if (::bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
    if (error != nullptr) *error = "绑定 " + ip + ":" + std::to_string(port) + " 失败：" + last_error_text();
    return std::nullopt;
  }
  if (::listen(socket, SOMAXCONN) != 0) {
    if (error != nullptr) *error = "监听失败：" + last_error_text();
    return std::nullopt;
  }
  return out;
}

std::optional<TcpSocket> TcpSocket::connect_to(const std::string& ip, uint16_t port, std::string* error) {
  const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kInvalidSocket) {
    if (error != nullptr) *error = last_error_text();
    return std::nullopt;
  }
  TcpSocket out(static_cast<uintptr_t>(socket));

  SOCKADDR_IN address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (InetPtonA(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
    if (error != nullptr) *error = "无效的 IPv4 地址: " + ip;
    return std::nullopt;
  }
  if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
    if (error != nullptr) *error = last_error_text();
    return std::nullopt;
  }
  return out;
}

}  // namespace platform
}  // namespace hicar
