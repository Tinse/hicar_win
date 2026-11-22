#include <winsock2.h>
#include <ws2bth.h>

#include <bluetoothapis.h>
#include <windows.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "platform/bluetooth.h"

namespace hicar {
namespace platform {

namespace {

constexpr SOCKET kInvalidSocket = INVALID_SOCKET;

std::string last_wsa_error(const char* what) {
  const int code = WSAGetLastError();
  char* text = nullptr;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                 static_cast<DWORD>(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 reinterpret_cast<char*>(&text), 0, nullptr);
  std::string out = std::string(what) + "：WSA " + std::to_string(code);
  if (text != nullptr) {
    out += " ";
    out += text;
    LocalFree(text);
  }
  return out;
}

// ---- SDP 记录构造 ----
struct SdpBuilder {
  std::vector<uint8_t> bytes;

  void raw(std::initializer_list<uint8_t> data) { bytes.insert(bytes.end(), data.begin(), data.end()); }

  void uint8(uint16_t attribute, uint8_t value) {
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(attribute >> 8));
    bytes.push_back(static_cast<uint8_t>(attribute & 0xFF));
    bytes.push_back(0x08);
    bytes.push_back(value);
  }

  void uint16(uint16_t attribute, uint16_t value) {
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(attribute >> 8));
    bytes.push_back(static_cast<uint8_t>(attribute & 0xFF));
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
  }

  void uint32(uint16_t attribute, uint32_t value) {
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(attribute >> 8));
    bytes.push_back(static_cast<uint8_t>(attribute & 0xFF));
    bytes.push_back(0x0A);
    for (int shift = 24; shift >= 0; shift -= 8) bytes.push_back(static_cast<uint8_t>(value >> shift));
  }

  void uuid16(uint16_t attribute, uint16_t uuid) {
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(attribute >> 8));
    bytes.push_back(static_cast<uint8_t>(attribute & 0xFF));
    bytes.push_back(0x19);
    bytes.push_back(static_cast<uint8_t>(uuid >> 8));
    bytes.push_back(static_cast<uint8_t>(uuid & 0xFF));
  }

  void text(uint16_t attribute, const std::string& value) {
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(attribute >> 8));
    bytes.push_back(static_cast<uint8_t>(attribute & 0xFF));
    if (value.size() > 0xFF) throw std::invalid_argument("SDP 文本太长");
    bytes.push_back(0x25);
    bytes.push_back(static_cast<uint8_t>(value.size()));
    bytes.insert(bytes.end(), value.begin(), value.end());
  }

  // 把一段已经构造好的值放进属性（调用方负责值本身的数据元素头）。
  void value(uint16_t attribute, const std::vector<uint8_t>& element) {
    bytes.push_back(0x09);
    bytes.push_back(static_cast<uint8_t>(attribute >> 8));
    bytes.push_back(static_cast<uint8_t>(attribute & 0xFF));
    bytes.insert(bytes.end(), element.begin(), element.end());
  }
};

std::vector<uint8_t> sequence(const std::vector<uint8_t>& body) {
  if (body.size() > 0xFF) throw std::invalid_argument("SDP 序列太长");
  std::vector<uint8_t> out;
  out.push_back(0x35);
  out.push_back(static_cast<uint8_t>(body.size()));
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<uint8_t> element_uuid16(uint16_t uuid) {
  return {0x19, static_cast<uint8_t>(uuid >> 8), static_cast<uint8_t>(uuid & 0xFF)};
}

std::vector<uint8_t> element_uint8(uint8_t value) { return {0x08, value}; }

std::vector<uint8_t> element_uint16(uint16_t value) {
  return {0x09, static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value & 0xFF)};
}

std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
  std::vector<uint8_t> out;
  for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
  return out;
}

// HiCar 控制服务：UUID FE35，RFCOMM 通道 channel。
std::vector<uint8_t> build_hbr_record(uint8_t channel) {
  SdpBuilder record;
  record.uint32(0x0000, 0x00010001);
  record.value(0x0001, sequence(element_uuid16(0xFE35)));
  const auto l2cap = sequence(element_uuid16(0x0100));
  const auto rfcomm = sequence(concat({element_uuid16(0x0003), element_uint8(channel)}));
  record.value(0x0004, sequence(concat({l2cap, rfcomm})));
  record.value(0x0005, sequence(element_uuid16(0x1002)));
  record.text(0x0100, "HiCar Receiver");
  record.value(0x0009, sequence(concat({element_uuid16(0xFE35), element_uint16(0x0100)})));
  return record.bytes;
}

}  // namespace

std::string format_bluetooth_address(const std::array<uint8_t, 6>& address) {
  char text[18];
  std::snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1], address[2], address[3],
                address[4], address[5]);
  return std::string(text);
}

std::optional<BluetoothRadioInfo> find_first_radio(std::string* error) {
  BLUETOOTH_FIND_RADIO_PARAMS params{};
  params.dwSize = sizeof(params);
  HANDLE radio = nullptr;
  HBLUETOOTH_RADIO_FIND find = BluetoothFindFirstRadio(&params, &radio);
  if (find == nullptr) {
    if (error != nullptr) *error = "没有可用的蓝牙无线电（错误码 " + std::to_string(GetLastError()) + "）";
    return std::nullopt;
  }
  BLUETOOTH_RADIO_INFO info{};
  info.dwSize = sizeof(info);
  const DWORD got = BluetoothGetRadioInfo(radio, &info);
  BluetoothFindRadioClose(find);
  if (got != ERROR_SUCCESS) {
    CloseHandle(radio);
    if (error != nullptr) *error = "读取蓝牙无线电信息失败（错误码 " + std::to_string(got) + "）";
    return std::nullopt;
  }
  CloseHandle(radio);

  BluetoothRadioInfo out;
  out.address = info.address.ullLong;
  for (size_t i = 0; i < 6; ++i) {
    out.bytes[5 - i] = static_cast<uint8_t>((out.address >> (8 * i)) & 0xFF);
  }
  out.name = info.szName;
  return out;
}

RfcommListener::RfcommListener(RfcommListener&& other) noexcept
    : handle_(other.handle_), local_address_(other.local_address_), channel_(other.channel_) {
  other.handle_ = TcpSocket::kInvalid;
  other.channel_ = 0;
  other.local_address_ = 0;
}

RfcommListener& RfcommListener::operator=(RfcommListener&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    local_address_ = other.local_address_;
    channel_ = other.channel_;
    other.handle_ = TcpSocket::kInvalid;
    other.channel_ = 0;
    other.local_address_ = 0;
  }
  return *this;
}

RfcommListener::~RfcommListener() { close(); }

void RfcommListener::close() {
  if (handle_ != TcpSocket::kInvalid) {
    closesocket(static_cast<SOCKET>(handle_));
    handle_ = TcpSocket::kInvalid;
  }
}

bool RfcommListener::listen(uint64_t local_address, uint8_t channel, std::string* error) {
  close();
  const SOCKET socket = ::socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
  if (socket == kInvalidSocket) {
    if (error != nullptr) *error = last_wsa_error("创建 RFCOMM 套接字失败");
    return false;
  }
  const BOOL authenticate = FALSE;
  setsockopt(socket, SOL_RFCOMM, SO_BTH_AUTHENTICATE, reinterpret_cast<const char*>(&authenticate),
             sizeof(authenticate));

  SOCKADDR_BTH address{};
  address.addressFamily = AF_BTH;
  address.btAddr = local_address;
  address.serviceClassId = GUID{};

  const uint8_t first = channel == 0 ? 1 : channel;
  const uint8_t last = channel == 0 ? 30 : channel;
  for (uint32_t candidate = first; candidate <= last; ++candidate) {
    address.port = candidate;
    if (::bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
      if (::listen(socket, SOMAXCONN) == 0) {
        handle_ = static_cast<uintptr_t>(socket);
        local_address_ = local_address;
        channel_ = static_cast<uint8_t>(candidate);
        return true;
      }
    }
  }
  closesocket(socket);
  if (error != nullptr) *error = last_wsa_error("RFCOMM 绑定/监听失败");
  return false;
}

std::optional<TcpSocket> RfcommListener::accept(std::string* error) {
  SOCKADDR_BTH address{};
  int length = sizeof(address);
  const SOCKET accepted = ::accept(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&address), &length);
  if (accepted == kInvalidSocket) {
    if (error != nullptr) *error = last_wsa_error("RFCOMM accept 失败");
    return std::nullopt;
  }
  return TcpSocket(static_cast<uintptr_t>(accepted));
}

bool RfcommListener::publish_sdp(std::string* error) {
  if (handle_ == TcpSocket::kInvalid) {
    if (error != nullptr) *error = "RFCOMM 还没有监听";
    return false;
  }

  // 用 WSAQUERYSET 的标准成员让系统自己组 SDP 记录：服务类 UUID + RFCOMM 通道来自本地地址。
  SOCKADDR_BTH local{};
  local.addressFamily = AF_BTH;
  local.btAddr = local_address_;
  local.port = channel_;
  local.serviceClassId = GUID{};

  CSADDR_INFO address{};
  address.LocalAddr.lpSockaddr = reinterpret_cast<SOCKADDR*>(&local);
  address.LocalAddr.iSockaddrLength = sizeof(local);
  address.iSocketType = SOCK_STREAM;
  address.iProtocol = BTHPROTO_RFCOMM;

  GUID service_class = {0x0000FE35, 0x0000, 0x1000, {0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB}};
  WCHAR name[] = L"HiCar Receiver";

  WSAQUERYSETW query{};
  query.dwSize = sizeof(query);
  query.lpServiceClassId = &service_class;
  query.lpszServiceInstanceName = name;
  query.dwNameSpace = NS_BTH;
  query.dwNumberOfCsAddrs = 1;
  query.lpcsaBuffer = &address;

  const int result = WSASetServiceW(&query, RNRSERVICE_REGISTER, 0);
  if (result != 0) {
    if (error != nullptr) *error = last_wsa_error("发布 SDP 记录失败");
    return false;
  }
  return true;
}

}  // namespace platform
}  // namespace hicar
