#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace hicar {

// 手机在数据通道协商里报的 WiFi 能力（资源层命令 1 的 TLV 3）。
struct WifiCapability {
  std::optional<bool> can_be_group_owner;
  std::optional<bool> can_be_group_client;
  std::optional<bool> supports_2g;
  std::optional<bool> supports_5g;
  std::optional<uint64_t> channel_bitmap;
  std::optional<bool> dual_band;
  std::optional<uint32_t> connected_frequency_mhz;
  std::map<uint32_t, uint32_t> other_fields;

  // 按能力判断能否使用某个频率（2.4G / 5G 规则）。
  bool can_use(uint32_t frequency_mhz) const;
};

enum class DataChannelRefusal : uint32_t { kBusy = 2, kNoChannel = 255 };

namespace data_channel {

constexpr uint32_t kCommandRequest = 1;
constexpr uint32_t kCommandResponse = 2;
constexpr uint32_t kCommandResult = 7;
constexpr uint32_t kTagDetail = 3;
constexpr uint32_t kResultOk = 1;

constexpr uint32_t kRoleGroupOwner = 1;
constexpr uint32_t kRoleGroupClient = 2;

struct Request {
  uint32_t data_channel = 0;
  WifiCapability capability;
};

struct Result {
  uint32_t data_channel = 0;
  uint32_t result = 0;
  std::optional<uint32_t> role;
  std::optional<uint32_t> frequency_mhz;
};

WifiCapability parse_capability(const std::vector<uint8_t>& value);
Request parse_request(const std::vector<uint8_t>& value);
Result parse_result(const std::vector<uint8_t>& value);

// 命令 2 接受 / 拒绝的完整载荷（含外层 TLV）。
std::vector<uint8_t> accept_payload(uint32_t data_channel, uint32_t role, uint32_t frequency_mhz);
std::vector<uint8_t> refuse_payload(uint32_t data_channel, DataChannelRefusal refusal);

}  // namespace data_channel
}  // namespace hicar
