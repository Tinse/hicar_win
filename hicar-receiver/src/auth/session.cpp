#include "auth/session.h"

#include <cstdio>

#include "auth/hichain.h"
#include "auth/json.h"
#include "common/hex.h"

namespace hicar::auth {

namespace {

constexpr size_t kMaxMessageBytes = 10240;

std::string string_map_json(const std::vector<std::pair<std::string, std::string>>& values) {
  std::string out = "{";
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) out.push_back(',');
    out.push_back('"');
    out += escape_json_string(values[i].first);
    out += "\":\"";
    out += escape_json_string(values[i].second);
    out.push_back('"');
  }
  out.push_back('}');
  return out;
}

std::string envelope_head(const std::string& version, int oper_type, const std::string& data) {
  return "{\"version\":\"" + escape_json_string(version) +
         "\",\"discover_type\":1,\"oper_type\":" + std::to_string(oper_type) +
         ",\"data\":\"" + escape_json_string(data) + "\"";
}

AuthOutput failure(int error, bool malformed = false) {
  AuthOutput output;
  output.kind = AuthOutput::Kind::Failed;
  output.error = error;
  if (malformed) output.note = "认证消息不合法";
  return output;
}

}  // namespace

AuthSession::AuthSession(AuthSessionConfig config, AccessoryAuthConfig auth_config,
                         TrustStore& store, RandomSource& random)
    : config_(std::move(config)), auth_config_(std::move(auth_config)), store_(store),
      random_(random) {}

std::vector<AuthOutput> AuthSession::feed(std::string_view bytes) {
  std::vector<AuthOutput> outputs;
  if (finished_) return outputs;

  for (const char raw : bytes) {
    const uint8_t b = static_cast<uint8_t>(raw);
    if (!started_) {
      if (b == ' ' || b == '\t' || b == '\n' || b == '\r') continue;
      if (b != '{') {
        finished_ = true;
        outputs.push_back(failure(1, true));
        return outputs;
      }
      started_ = true;
      depth_ = 0;
      in_string_ = false;
      escaped_ = false;
      pending_.clear();
    }

    pending_.push_back(raw);
    if (pending_.size() > kMaxMessageBytes) {
      finished_ = true;
      outputs.push_back(failure(1, true));
      return outputs;
    }

    if (in_string_) {
      if (escaped_) {
        escaped_ = false;
      } else if (b == '\\') {
        escaped_ = true;
      } else if (b == '"') {
        in_string_ = false;
      }
      continue;
    }

    if (b == '"') {
      in_string_ = true;
    } else if (b == '{' || b == '[') {
      ++depth_;
    } else if (b == '}' || b == ']') {
      --depth_;
      if (depth_ == 0) {
        const std::string message = pending_;
        pending_.clear();
        started_ = false;
        auto step = on_json_message(message);
        outputs.insert(outputs.end(), step.begin(), step.end());
        if (finished_) return outputs;
      }
    }
  }
  return outputs;
}

std::vector<AuthOutput> AuthSession::on_connection_closed() {
  std::vector<AuthOutput> outputs;
  if (finished_) return outputs;
  finished_ = true;
  outputs.push_back(failure(-3));
  return outputs;
}

std::vector<AuthOutput> AuthSession::on_json_message(const std::string& message) {
  std::vector<AuthOutput> outputs;
  const auto root = parse_json(message);
  if (!root.has_value() || !root->is_object()) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  const JsonValue* oper = root->find("oper_type");
  const JsonValue* data = root->find("data");
  if (oper == nullptr || data == nullptr) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  const auto oper_value = oper->as_int();
  const auto data_value = data->as_string();
  if (!oper_value.has_value() || !data_value.has_value()) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }

  if (*oper_value == 1) return on_handshake(*root, *data_value);
  if (*oper_value == 3) return on_hichain(*data_value);

  finished_ = true;
  outputs.push_back(failure(1, true));
  return outputs;
}

std::vector<AuthOutput> AuthSession::on_handshake(const JsonValue& root, const std::string& data) {
  std::vector<AuthOutput> outputs;
  if (handshake_seen_) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  const auto body = parse_json(data);
  if (!body.has_value() || !body->is_object()) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  const JsonValue* device_field = body->find("deviceId");
  const JsonValue* pin_field = body->find("has_pin");
  const JsonValue* usb_field = body->find("usb_connection");
  if (device_field == nullptr || pin_field == nullptr || usb_field == nullptr) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  const auto device_id = device_field->as_string();
  const auto has_pin = pin_field->as_bool();
  const auto usb_connection = usb_field->as_bool();
  if (!device_id.has_value() || !has_pin.has_value() || !usb_connection.has_value()) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  bool printable = !device_id->empty() && device_id->size() <= 64;
  for (const char c : *device_id) {
    if (c < ' ' || c > '~') printable = false;
  }
  if (!printable) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  if (*usb_connection != config_.usb_connection) {
    finished_ = true;
    outputs.push_back(failure(-2));
    return outputs;
  }

  handshake_seen_ = true;
  peer_device_id_ = *device_id;

  // has_pin 描述的是“手机是否还需要车机给出连接码”，不是“本机有没有连接码”。
  // 扫码连接时手机已经从二维码拿到 PIN，会发 has_pin=false；此时仍必须用本机
  // 保存的同一个 PIN 走 PAKE，不能误判成免码回连。只有既没有 PIN、又没有配对
  // 记录时，才真正无法认证。
  std::optional<Bytes> pin = config_.pin;
  if (!pin.has_value() && *has_pin) {
    const Bytes raw = random_.bytes(4);
    const uint32_t value = (static_cast<uint32_t>(raw[0]) << 24) |
                           (static_cast<uint32_t>(raw[1]) << 16) |
                           (static_cast<uint32_t>(raw[2]) << 8) | raw[3];
    char text[8];
    std::snprintf(text, sizeof(text), "%06u", static_cast<unsigned>(value % 1000000u));
    pin = Bytes(text, text + 6);
  }
  active_pin_ = pin;

  auth_config_.peer_auth_id.assign(peer_device_id_.begin(), peer_device_id_.end());
  auth_config_.pin = pin;
  authenticator_ = std::make_unique<AccessoryAuthenticator>(auth_config_, store_, random_);
  mode_ = pin.has_value() ? 1 : 2;

  AuthOutput note;
  note.kind = AuthOutput::Kind::Note;
  note.note = std::string("手机握手：has_pin=") + (*has_pin ? "true" : "false") +
              "，usb_connection=" + (*usb_connection ? "true" : "false") +
              "，本机有配对记录=" + (authenticator_->peer_trusted() ? "true" : "false");
  outputs.push_back(std::move(note));

  if (!pin.has_value() && !authenticator_->peer_trusted()) {
    finished_ = true;
    outputs.push_back(failure(-1));
    return outputs;
  }

  std::vector<std::pair<std::string, std::string>> details = config_.device_info;
  details.emplace_back("deviceId", std::string(auth_config_.self_auth_id.begin(),
                                               auth_config_.self_auth_id.end()));
  details.emplace_back("devicename", "HiCar-Windows");
  details.emplace_back("has_pin", pin.has_value() ? "true" : "false");
  const std::string info = string_map_json(details);
  std::string response = envelope_head(config_.envelope_version, 1, info);
  response += ",\"usb_connection\":";
  response += config_.usb_connection ? "true" : "false";
  if (pin.has_value() && config_.usb_connection) {
    response += ",\"pin_code\":\"" + std::string(pin->begin(), pin->end()) + "\"";
  }
  response += "}";

  AuthOutput send;
  send.kind = AuthOutput::Kind::Send;
  send.bytes.assign(response.begin(), response.end());
  outputs.push_back(std::move(send));
  return outputs;
}

std::vector<AuthOutput> AuthSession::on_hichain(const std::string& data) {
  std::vector<AuthOutput> outputs;
  if (authenticator_ == nullptr) {
    finished_ = true;
    outputs.push_back(failure(1, true));
    return outputs;
  }
  const auto actions = authenticator_->on_message(data);
  for (const auto& action : actions) {
    switch (action.kind) {
      case AuthAction::Kind::Send: {
        const auto parsed = parse_json(action.message);
        if (!parsed.has_value()) {
          finished_ = true;
          outputs.push_back(failure(1, true));
          return outputs;
        }
        const std::string inner = write_json(*parsed);
        const std::string outer = envelope_head(config_.envelope_version, 3, inner) + "}";
        AuthOutput send;
        send.kind = AuthOutput::Kind::Send;
        send.bytes.assign(outer.begin(), outer.end());
        outputs.push_back(std::move(send));
        break;
      }
      case AuthAction::Kind::Progress:
        break;
      case AuthAction::Kind::Succeeded: {
        finished_ = true;
        AuthOutput done;
        done.kind = AuthOutput::Kind::Succeeded;
        done.session_key = action.session_key;
        done.note = mode_ == 1 ? "PIN 配对成功" : "免码回连成功";
        outputs.push_back(std::move(done));
        return outputs;
      }
      case AuthAction::Kind::Failed:
        finished_ = true;
        outputs.push_back(failure(action.error));
        return outputs;
    }
  }

  AuthOutput note;
  note.kind = AuthOutput::Kind::Note;
  note.note = "认证库消息已处理";
  outputs.insert(outputs.begin(), std::move(note));
  return outputs;
}

}  // namespace hicar::auth
