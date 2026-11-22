#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "auth/crypto.h"
#include "auth/trust_store.h"

namespace hicar::auth {

struct AccessoryAuthConfig {
  std::string service_package;
  std::string service_type;
  Bytes self_auth_id;
  Bytes peer_auth_id;
  std::optional<Bytes> pin;  // ASCII；无表示只接受免码回连
};

struct AuthAction {
  enum class Kind { Send, Progress, Succeeded, Failed };

  Kind kind = Kind::Progress;
  std::string message;  // Send
  int result = 0;       // Progress
  Bytes session_key;    // Succeeded
  int error = 0;        // Failed（认证库错误码，或对端 0x8080 的错误码）
  bool malformed = false;  // 消息本身不合法（调用方应断开连接）
};

class AccessoryAuthenticator {
 public:
  AccessoryAuthenticator(AccessoryAuthConfig config, TrustStore& store, RandomSource& random);
  ~AccessoryAuthenticator();

  AccessoryAuthenticator(const AccessoryAuthenticator&) = delete;
  AccessoryAuthenticator& operator=(const AccessoryAuthenticator&) = delete;

  bool peer_trusted() const;
  bool finished() const;
  std::vector<AuthAction> on_message(std::string_view message);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace hicar::auth
