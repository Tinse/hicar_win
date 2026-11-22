#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace hicar {

// 通道管理（外层类型 0）载荷：tag 成对，奇数请求、偶数应答。
namespace channel_management {

constexpr uint32_t kOuterType = 0;

constexpr uint32_t kTagVersionRequest = 1;
constexpr uint32_t kTagVersionResponse = 2;
constexpr uint32_t kTagSummaryRequest = 3;
constexpr uint32_t kTagSummaryResponse = 4;
constexpr uint32_t kTagEncryptionRequest = 5;
constexpr uint32_t kTagEncryptionResponse = 6;
constexpr uint32_t kTagBluetoothRequest = 7;
constexpr uint32_t kTagBluetoothResponse = 8;
constexpr uint32_t kTagConnectId = 15;

// 车机自报的版本固定为 2，不回显对端版本。
constexpr uint32_t kLocalVersion = 2;

constexpr uint32_t kConnectIdMin = 100000;
constexpr uint32_t kConnectIdMax = 999999;

struct Version {
  bool request = false;
  uint32_t version = 0;
};

struct Summary {
  bool request = false;
  std::vector<uint8_t> raw;
  std::string text;
};

struct Encryption {
  bool request = false;
  bool enabled = false;
};

struct BluetoothAddress {
  bool request = false;
  std::vector<uint8_t> raw;
  std::string text;
};

struct ConnectId {
  std::vector<uint8_t> raw;
};

struct Unknown {
  uint32_t tag = 0;
  std::vector<uint8_t> value;
};

using Item = std::variant<Version, Summary, Encryption, BluetoothAddress, ConnectId, Unknown>;

std::vector<Item> decode(const std::vector<uint8_t>& payload);
std::vector<uint8_t> connect_id_value(uint32_t connect_id);

// 文本字段按 UTF-8 解，去掉结尾 NUL。十六进制/地址文本原样返回。
std::string text_of(const std::vector<uint8_t>& raw);

}  // namespace channel_management

}  // namespace hicar
