#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "auth/authenticator.h"
#include "auth/crypto.h"
#include "auth/json.h"

namespace hicar::auth {

struct AuthSessionConfig {
  std::string envelope_version;
  bool usb_connection = true;
  std::optional<Bytes> pin;  // 无线时必须给出（二维码/屏幕上的连接码）
  std::vector<std::pair<std::string, std::string>> device_info;
};

struct AuthOutput {
  enum class Kind { Send, Note, Succeeded, Failed };

  Kind kind = Kind::Note;
  Bytes bytes;       // Send：要写回认证连接的字节
  std::string note;  // Note
  Bytes session_key;
  int error = 0;     // Failed：认证库错误码；-1 表示未信任；-2 表示连接方式不一致
};

class AuthSession {
 public:
  AuthSession(AuthSessionConfig config, AccessoryAuthConfig auth_config, TrustStore& store,
              RandomSource& random);

  std::vector<AuthOutput> feed(std::string_view bytes);
  std::vector<AuthOutput> on_connection_closed();

  bool finished() const { return finished_; }

 private:
  std::vector<AuthOutput> on_json_message(const std::string& message);
  std::vector<AuthOutput> on_handshake(const JsonValue& root, const std::string& data);
  std::vector<AuthOutput> on_hichain(const std::string& data);

  AuthSessionConfig config_;
  AccessoryAuthConfig auth_config_;
  TrustStore& store_;
  RandomSource& random_;

  bool finished_ = false;
  bool handshake_seen_ = false;
  std::optional<Bytes> active_pin_;
  int mode_ = 0;  // 1 PIN 配对，2 免码回连
  std::string peer_device_id_;
  std::unique_ptr<AccessoryAuthenticator> authenticator_;

  // 分帧状态
  std::string pending_;
  int depth_ = 0;
  bool in_string_ = false;
  bool escaped_ = false;
  bool started_ = false;
};

}  // namespace hicar::auth
