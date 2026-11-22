#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "auth/crypto.h"
#include "auth/json.h"

namespace hicar::auth {

namespace code {
constexpr int kPakeRequest = 0x0001;
constexpr int kPakeClientConfirm = 0x0002;
constexpr int kExchangeRequest = 0x0003;
constexpr int kAuthStartRequest = 0x0011;
constexpr int kAuthAckRequest = 0x0012;
constexpr int kAddAuthInfoRequest = 0x0023;
constexpr int kRemoveAuthInfoRequest = 0x0033;
constexpr int kSecCloneStartRequest = 0x0041;
constexpr int kSecCloneAckRequest = 0x0042;
constexpr int kPakeResponse = 0x8001;
constexpr int kPakeServerConfirmResponse = 0x8002;
constexpr int kExchangeResponse = 0x8003;
constexpr int kAuthStartResponse = 0x8011;
constexpr int kAuthAckResponse = 0x8012;
constexpr int kAddAuthInfoResponse = 0x8023;
constexpr int kRemoveAuthInfoResponse = 0x8033;
constexpr int kSecCloneStartResponse = 0x8041;
constexpr int kSecCloneAckResponse = 0x8042;
constexpr int kInformMessage = 0x8080;
}  // namespace code

namespace op {
constexpr int kNoOperation = 0;
constexpr int kBind = 1;
constexpr int kAuthenticate = 2;
constexpr int kAddAuthInfo = 3;
constexpr int kRemoveAuthInfo = 4;
constexpr int kUnbind = 5;
constexpr int kAuthKeyAgreement = 6;
constexpr int kSecClone = 8;
}  // namespace op

namespace hcerr {
constexpr int kOk = 0;
constexpr int kInputError = 1;
constexpr int kInnerError = 2;
constexpr int kStateError = 3;
constexpr int kServiceConfirmError = 4;
constexpr int kUnknownMessage = 5;
constexpr int kNoMessageToSend = 6;
constexpr int kRepeatedReference = 7;
constexpr int kNeedDepend = 8;
constexpr int kBuildObjectFailed = 9;
constexpr int kBuildSendDataFailed = 10;
constexpr int kVersionUnsupported = 12;
constexpr int kVerifyProofFailed = 17;
constexpr int kGenerateSessionKeyFailed = 19;
constexpr int kComputeStsSharedSecretFailed = 21;
constexpr int kPaKeObjectError = 24;
constexpr int kStsObjectError = 25;
constexpr int kDecryptFailed = 26;
constexpr int kSignTooShort = 28;
constexpr int kVerifyExchangeFailed = 29;
constexpr int kSaveLtpkFailed = 31;
constexpr int kMessageInconsistency = 38;
constexpr int kOperationCodeError = 39;
constexpr int kMemcpyError = 40;
constexpr int kProtocolStateError = 41;
}  // namespace hcerr

struct Version {
  uint32_t first = 0;
  uint32_t second = 0;
  uint32_t third = 0;

  static Version parse(std::string_view text);
  bool operator>=(const Version& other) const;
  bool operator<=(const Version& other) const;
  bool operator==(const Version& other) const;
};

struct PakeStartRequest {
  Version current;
  Version minimum;
  int operation_code = 0;
};

struct PakeEndRequest {
  Bytes challenge;
  Bytes epk;
  Bytes kcf;
};

struct ExchangeRequest {
  Bytes cipher;
};

struct StsStartRequest {
  Version current;
  Version minimum;
  int operation_code = 0;
  Bytes challenge;
  Bytes epk;
};

struct StsEndRequest {
  Bytes auth_data;
};

// 解析失败返回 nullopt（对应认证库的 BUILD_OBJECT_FAILED）。
std::optional<PakeStartRequest> parse_pake_start(const JsonValue& payload);
std::optional<PakeEndRequest> parse_pake_end(const JsonValue& payload);
std::optional<ExchangeRequest> parse_exchange(const JsonValue& payload);
std::optional<StsStartRequest> parse_sts_start(const JsonValue& payload);
std::optional<StsEndRequest> parse_sts_end(const JsonValue& payload);
bool validate_response(int message_code, const JsonValue& payload);

std::string build_pake_response(const Bytes& challenge, const Bytes& salt, const Bytes& epk);
std::string build_pake_server_confirm(const Bytes& kcf);
std::string build_exchange_response(const Bytes& cipher);
std::string build_auth_start_response(const Bytes& auth_data, const Bytes& challenge,
                                      const Bytes& epk, const Bytes& salt, const Bytes& self_id,
                                      int peer_user_type);
std::string build_auth_ack_response(const Bytes& auth_return);
std::string build_exchange_auth_info(const Bytes& auth_id, const Bytes& public_key);
std::string build_inform(int error_code);

std::string hex_upper(const Bytes& value);

}  // namespace hicar::auth
