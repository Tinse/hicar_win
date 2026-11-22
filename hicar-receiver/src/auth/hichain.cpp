#include "auth/hichain.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>

#include "common/hex.h"

namespace hicar::auth {

namespace {

constexpr size_t kMaxChallenge = 16;
constexpr size_t kMaxSalt = 16;
constexpr size_t kMaxHmac = 32;
constexpr size_t kMaxPakeEpk = 384;
constexpr size_t kMaxStsEpk = 32;
constexpr size_t kMaxAuthData = 256;
constexpr size_t kMaxAuthId = 64;
constexpr size_t kMaxExchangeCipher = 350;
constexpr size_t kMaxExchangePublicKey = 64;

constexpr const char* kVersionFields =
    "\"version\":{\"currentVersion\":\"1.0.0\",\"minVersion\":\"1.0.0\"}";

std::optional<Bytes> hex_value(const JsonValue& object, std::string_view name, size_t max_length) {
  const JsonValue* field = object.find_ci(name);
  if (field == nullptr) return std::nullopt;
  const auto text = field->as_string();
  if (!text.has_value()) return std::nullopt;
  try {
    Bytes bytes = from_hex(*text);
    if (bytes.empty() || bytes.size() > max_length) return std::nullopt;
    return bytes;
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

std::optional<int> int_field(const JsonValue& object, std::string_view name) {
  const JsonValue* field = object.find_ci(name);
  if (field == nullptr) return std::nullopt;
  return field->as_int();
}

std::optional<std::string> string_field(const JsonValue& object, std::string_view name) {
  const JsonValue* field = object.find_ci(name);
  if (field == nullptr) return std::nullopt;
  return field->as_string();
}

std::optional<std::pair<Version, Version>> version_field(const JsonValue& object) {
  const JsonValue* version = object.find_ci("version");
  if (version == nullptr || !version->is_object()) return std::nullopt;
  const auto current = string_field(*version, "currentVersion");
  const auto minimum = string_field(*version, "minVersion");
  if (!current.has_value() || !minimum.has_value()) return std::nullopt;
  return std::make_pair(Version::parse(*current), Version::parse(*minimum));
}

bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

}  // namespace

Version Version::parse(std::string_view text) {
  std::vector<std::string> tokens;
  std::string current;
  for (char c : text) {
    if (c == '.') {
      if (!current.empty()) tokens.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty()) tokens.push_back(current);

  auto part = [&](size_t index) -> uint32_t {
    if (index >= tokens.size()) return 0;
    const std::string& token = tokens[index];
    size_t i = 0;
    while (i < token.size() && (token[i] == ' ' || token[i] == '\t' || token[i] == '\n' ||
                                token[i] == '\v' || token[i] == '\f' || token[i] == '\r')) {
      ++i;
    }
    bool negative = false;
    if (i < token.size() && (token[i] == '+' || token[i] == '-')) {
      negative = token[i] == '-';
      ++i;
    }
    uint64_t value = 0;
    size_t digits = 0;
    while (i < token.size() && token[i] >= '0' && token[i] <= '9') {
      const uint64_t digit = static_cast<uint64_t>(token[i] - '0');
      if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
        value = std::numeric_limits<uint64_t>::max();
      } else {
        value = value * 10 + digit;
      }
      ++i;
      ++digits;
    }
    if (digits == 0) return 0;
    if (negative) value = static_cast<uint64_t>(0) - value;
    return static_cast<uint32_t>(value & 0xFFFFFFFFull);
  };

  return Version{part(0), part(1), part(2)};
}

bool Version::operator>=(const Version& other) const {
  if (first != other.first) return first > other.first;
  if (second != other.second) return second > other.second;
  return third >= other.third;
}

bool Version::operator<=(const Version& other) const {
  if (first != other.first) return first < other.first;
  if (second != other.second) return second < other.second;
  return third <= other.third;
}

bool Version::operator==(const Version& other) const {
  return first == other.first && second == other.second && third == other.third;
}

std::optional<PakeStartRequest> parse_pake_start(const JsonValue& payload) {
  const auto operation = int_field(payload, "operationCode");
  if (!operation.has_value() || *operation == -1) return std::nullopt;
  const auto version = version_field(payload);
  if (!version.has_value()) return std::nullopt;
  return PakeStartRequest{version->first, version->second, *operation};
}

std::optional<PakeEndRequest> parse_pake_end(const JsonValue& payload) {
  const auto challenge = hex_value(payload, "challenge", kMaxChallenge);
  const auto kcf = hex_value(payload, "kcfData", kMaxHmac);
  const auto epk = hex_value(payload, "epk", kMaxPakeEpk);
  if (!challenge.has_value() || !kcf.has_value() || !epk.has_value()) return std::nullopt;
  return PakeEndRequest{*challenge, *epk, *kcf};
}

std::optional<ExchangeRequest> parse_exchange(const JsonValue& payload) {
  const auto cipher = hex_value(payload, "exAuthInfo", kMaxExchangeCipher);
  if (!cipher.has_value()) return std::nullopt;
  return ExchangeRequest{*cipher};
}

std::optional<StsStartRequest> parse_sts_start(const JsonValue& payload) {
  const auto operation = int_field(payload, "operationCode");
  if (!operation.has_value() || *operation == -1) return std::nullopt;
  const auto challenge = hex_value(payload, "challenge", kMaxChallenge);
  const auto epk = hex_value(payload, "epk", kMaxStsEpk);
  const auto version = version_field(payload);
  if (!challenge.has_value() || !epk.has_value() || !version.has_value()) return std::nullopt;
  return StsStartRequest{version->first, version->second, *operation, *challenge, *epk};
}

std::optional<StsEndRequest> parse_sts_end(const JsonValue& payload) {
  const auto auth_data = hex_value(payload, "authData", kMaxAuthData);
  if (!auth_data.has_value()) return std::nullopt;
  return StsEndRequest{*auth_data};
}

bool validate_response(int message_code, const JsonValue& payload) {
  switch (message_code) {
    case code::kPakeResponse:
      return hex_value(payload, "challenge", kMaxChallenge).has_value() &&
             hex_value(payload, "salt", kMaxSalt).has_value() &&
             hex_value(payload, "epk", kMaxPakeEpk).has_value() &&
             version_field(payload).has_value();
    case code::kPakeServerConfirmResponse:
      return hex_value(payload, "kcfData", kMaxHmac).has_value();
    case code::kAuthStartResponse:
      return hex_value(payload, "authData", kMaxAuthData).has_value() &&
             hex_value(payload, "challenge", kMaxChallenge).has_value() &&
             hex_value(payload, "salt", kMaxSalt).has_value() &&
             hex_value(payload, "epk", kMaxStsEpk).has_value() &&
             version_field(payload).has_value();
    case code::kAuthAckResponse:
      return hex_value(payload, "authReturn", kMaxAuthData).has_value();
    case code::kExchangeResponse:
      return hex_value(payload, "exAuthInfo", kMaxExchangeCipher).has_value();
    default:
      return false;
  }
}

std::string hex_upper(const Bytes& value) { return to_hex_upper(value); }

std::string build_pake_response(const Bytes& challenge, const Bytes& salt, const Bytes& epk) {
  return "{\"message\":32769,\"payload\":{" + std::string(kVersionFields) +
         ",\"challenge\":\"" + hex_upper(challenge) + "\",\"salt\":\"" + hex_upper(salt) +
         "\",\"epk\":\"" + hex_upper(epk) + "\"}}";
}

std::string build_pake_server_confirm(const Bytes& kcf) {
  return "{\"message\":32770,\"payload\":{\"kcfData\":\"" + hex_upper(kcf) + "\"}}";
}

std::string build_exchange_response(const Bytes& cipher) {
  return "{\"message\":32771,\"payload\":{\"exAuthInfo\":\"" + hex_upper(cipher) + "\"}}";
}

std::string build_auth_start_response(const Bytes& auth_data, const Bytes& challenge,
                                      const Bytes& epk, const Bytes& salt, const Bytes& self_id,
                                      int peer_user_type) {
  return "{\"authForm\":0,\"message\":32785,\"payload\":{\"authData\":\"" + hex_upper(auth_data) +
         "\",\"challenge\":\"" + hex_upper(challenge) + "\",\"epk\":\"" + hex_upper(epk) +
         "\",\"salt\":\"" + hex_upper(salt) + "\"," + std::string(kVersionFields) +
         ",\"peerAuthId\":\"" + hex_upper(self_id) + "\",\"peerUserType\":\"" +
         std::to_string(peer_user_type) + "\"}}";
}

std::string build_auth_ack_response(const Bytes& auth_return) {
  return "{\"authForm\":0,\"message\":32786,\"payload\":{\"authReturn\":\"" + hex_upper(auth_return) +
         "\"}}";
}

std::string build_exchange_auth_info(const Bytes& auth_id, const Bytes& public_key) {
  return "{\"authId\":\"" + hex_upper(auth_id) + "\", \"authPk\":\"" + hex_upper(public_key) + "\"}";
}

std::string build_inform(int error_code) {
  return "{\"message\":32896, \"payload\":{\"errorCode\":" +
         std::to_string(static_cast<unsigned>(error_code) & 0xFFFF) + "}}";
}

}  // namespace hicar::auth
