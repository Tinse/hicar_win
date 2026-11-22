#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "auth/authenticator.h"
#include "auth/crypto.h"
#include "auth/json.h"
#include "auth/session.h"
#include "auth/trust_store.h"
#include "common/hex.h"

namespace {

int g_failures = 0;

void check(bool ok, const std::string& what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what.c_str());
    ++g_failures;
  }
}

const char* kDefaultVectorPath =
    "../../ref/OpenHC/core/auth/src/test/resources/io/github/gcbond/openhc/core/auth/accessory-vectors.json";

std::string vector_path() {
  const char* env = std::getenv("HICAR_AUTH_VECTORS");
  if (env != nullptr && *env != '\0') return env;

  const char* candidates[] = {
      kDefaultVectorPath,
      "../ref/OpenHC/core/auth/src/test/resources/io/github/gcbond/openhc/core/auth/accessory-vectors.json",
      "ref/OpenHC/core/auth/src/test/resources/io/github/gcbond/openhc/core/auth/accessory-vectors.json",
  };
  for (const char* candidate : candidates) {
    if (std::filesystem::exists(candidate)) return candidate;
  }
  return kDefaultVectorPath;
}

struct Scenario {
  std::string car_seed;
  std::vector<std::pair<std::string, std::string>> messages;
  std::vector<int> car_results;
  std::string session_key;
};

std::optional<Scenario> load_scenario(const std::string& path, const std::string& name) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return std::nullopt;
  std::stringstream buffer;
  buffer << stream.rdbuf();
  const auto root = hicar::auth::parse_json(buffer.str());
  if (!root.has_value()) return std::nullopt;
  const hicar::auth::JsonValue* node = root->find(name);
  if (node == nullptr || !node->is_object()) return std::nullopt;

  Scenario scenario;
  const hicar::auth::JsonValue* seed = node->find("carSeed");
  if (seed == nullptr) return std::nullopt;
  scenario.car_seed = *seed->as_string();
  const hicar::auth::JsonValue* key = node->find("sessionKey");
  if (key != nullptr) scenario.session_key = *key->as_string();

  const hicar::auth::JsonValue* results = node->find("carResults");
  if (results != nullptr && results->type == hicar::auth::JsonValue::Type::Array) {
    for (const auto& item : results->array) {
      const auto value = item.as_int();
      if (value.has_value()) scenario.car_results.push_back(static_cast<int>(*value));
    }
  }
  const hicar::auth::JsonValue* messages = node->find("messages");
  if (messages == nullptr || messages->type != hicar::auth::JsonValue::Type::Array) {
    return std::nullopt;
  }
  for (const auto& item : messages->array) {
    const hicar::auth::JsonValue* from = item.find("from");
    const hicar::auth::JsonValue* message = item.find("message");
    if (from == nullptr || message == nullptr) return std::nullopt;
    scenario.messages.emplace_back(*from->as_string(), *message->as_string());
  }
  return scenario;
}

hicar::auth::AccessoryAuthConfig synthetic_config(std::optional<std::string> pin) {
  hicar::auth::AccessoryAuthConfig config;
  config.service_package = "org.example.auth";
  config.service_type = "EXAMPLE";
  const std::string car_id = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
  const std::string phone_id = "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100";
  config.self_auth_id.assign(car_id.begin(), car_id.end());
  config.peer_auth_id.assign(phone_id.begin(), phone_id.end());
  if (pin.has_value()) config.pin = hicar::auth::Bytes(pin->begin(), pin->end());
  return config;
}

struct RunResult {
  std::vector<std::string> sends;
  std::vector<int> results;
  std::vector<hicar::auth::AuthAction> actions;
};

RunResult replay(hicar::auth::AccessoryAuthenticator& auth, const Scenario& scenario) {
  RunResult run;
  for (const auto& [from, message] : scenario.messages) {
    if (from != "phone") continue;
    const auto actions = auth.on_message(message);
    for (const auto& action : actions) {
      run.actions.push_back(action);
      switch (action.kind) {
        case hicar::auth::AuthAction::Kind::Send: run.sends.push_back(action.message); break;
        case hicar::auth::AuthAction::Kind::Progress: run.results.push_back(action.result); break;
        case hicar::auth::AuthAction::Kind::Succeeded: run.results.push_back(0); break;
        case hicar::auth::AuthAction::Kind::Failed: run.results.push_back(1); break;
      }
    }
  }
  return run;
}

bool same_strings(const std::vector<std::string>& a, const std::vector<std::string>& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool same_ints(const std::vector<int>& a, const std::vector<int>& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void test_pair_and_sts(const std::string& path) {
  const auto pair = load_scenario(path, "pair");
  const auto sts = load_scenario(path, "sts");
  if (!pair.has_value() || !sts.has_value()) {
    std::fprintf(stderr, "SKIP: 找不到认证向量 %s\n", path.c_str());
    return;
  }

  hicar::auth::MemoryTrustStore store;
  hicar::auth::SequenceRandom random(pair->car_seed);
  hicar::auth::AccessoryAuthenticator auth(synthetic_config(std::string("024680")), store, random);
  check(!auth.peer_trusted(), "配对前不应信任手机");
  const auto run = replay(auth, *pair);

  std::vector<std::string> expected;
  for (const auto& [from, message] : pair->messages) {
    if (from == "car") expected.push_back(message);
  }
  check(same_strings(run.sends, expected), "PAKE 配对应答与 C 实现逐字节一致");
  check(same_ints(run.results, pair->car_results), "配对结果码序列一致");
  check(!run.actions.empty(), "配对应有结果动作");
  if (!run.actions.empty()) {
    const auto& last = run.actions.back();
    check(last.kind == hicar::auth::AuthAction::Kind::Succeeded, "配对应成功");
    if (last.kind == hicar::auth::AuthAction::Kind::Succeeded) {
      check(hicar::to_hex(last.session_key) == pair->session_key, "配对会话密钥一致");
    }
  }
  check(store.identity_count() == 1 && store.peer_count() == 1, "配对后写入长期身份与手机记录");

  hicar::auth::SequenceRandom sts_random(sts->car_seed);
  hicar::auth::AccessoryAuthenticator reconnect(synthetic_config(std::nullopt), store, sts_random);
  check(reconnect.peer_trusted(), "重启后应信任手机");
  const auto sts_run = replay(reconnect, *sts);
  std::vector<std::string> sts_expected;
  for (const auto& [from, message] : sts->messages) {
    if (from == "car") sts_expected.push_back(message);
  }
  check(same_strings(sts_run.sends, sts_expected), "STS 免码认证应答与 C 实现逐字节一致");
  check(same_ints(sts_run.results, sts->car_results), "STS 结果码序列一致");
  if (!sts_run.actions.empty()) {
    const auto& last = sts_run.actions.back();
    check(last.kind == hicar::auth::AuthAction::Kind::Succeeded, "STS 应成功");
    if (last.kind == hicar::auth::AuthAction::Kind::Succeeded) {
      check(hicar::to_hex(last.session_key) == sts->session_key, "STS 会话密钥一致");
    }
  }
}

void test_wrong_pin(const std::string& path) {
  const auto scenario = load_scenario(path, "wrongPin");
  if (!scenario.has_value()) {
    std::fprintf(stderr, "SKIP: 找不到 wrongPin 向量\n");
    return;
  }
  hicar::auth::MemoryTrustStore store;
  hicar::auth::SequenceRandom random(scenario->car_seed);
  hicar::auth::AccessoryAuthenticator auth(synthetic_config(std::string("024680")), store, random);
  const auto run = replay(auth, *scenario);
  std::vector<std::string> expected;
  for (const auto& [from, message] : scenario->messages) {
    if (from == "car") expected.push_back(message);
  }
  check(same_strings(run.sends, expected), "错误连接码的应答与 C 实现逐字节一致");
  check(same_ints(run.results, scenario->car_results), "错误连接码的结果码一致");
  if (!run.actions.empty()) {
    const auto& last = run.actions.back();
    check(last.kind == hicar::auth::AuthAction::Kind::Failed && last.error == 17,
          "错误连接码应以 VERIFY_PROOF_FAILED 失败");
  }
  check(store.identity_count() == 0 && store.peer_count() == 0, "失败不写信任库");
}

void test_crypto_sanity() {
  using namespace hicar::auth;
  const Bytes seed(32, 0);
  const Bytes public_key = ed25519_public_from_seed(seed);
  check(public_key.size() == 32, "Ed25519 公钥长度");
  const Bytes message{'h', 'i'};
  const Bytes signature = ed25519_sign(seed, message);
  check(ed25519_verify(public_key, message, signature), "Ed25519 自验签");
  check(!ed25519_verify(public_key, Bytes{'b', 'y'}, signature), "Ed25519 错误消息应拒绝");

  const Bytes private_key(32, 7);
  const Bytes x_public = x25519_public_from_private(private_key);
  Bytes shared;
  check(x25519_agree(private_key, x_public, &shared), "X25519 自协商");
  check(shared.size() == 32, "X25519 共享秘密长度");

  const Bytes two{2};
  const Bytes result = modp_modpow(two, two, 384);
  check(result.size() == 384 && result.back() == 4, "2^2 mod p 结果");
}

void test_wired_auth_session(const std::string& path) {
  const auto scenario = load_scenario(path, "pair");
  if (!scenario.has_value()) {
    std::fprintf(stderr, "SKIP: 找不到 pair 向量\n");
    return;
  }

  hicar::auth::MemoryTrustStore store;
  hicar::auth::SequenceRandom random(scenario->car_seed);
  hicar::auth::AuthSessionConfig config;
  config.envelope_version = "TEST_1";
  config.usb_connection = true;
  config.pin = hicar::auth::Bytes{'0', '2', '4', '6', '8', '0'};
  config.device_info = {{"CAR_MODE_ID", "00048000"}};

  hicar::auth::AccessoryAuthConfig base;
  base.service_package = "org.example.auth";
  base.service_type = "EXAMPLE";
  const std::string car_id = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
  base.self_auth_id.assign(car_id.begin(), car_id.end());

  hicar::auth::AuthSession session(config, base, store, random);

  std::string phone_id = "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100";
  const std::string handshake =
      "{\"version\":\"TEST_1\",\"discover_type\":1,\"oper_type\":1,\"data\":\"{\\\"deviceId\\\":\\\"" +
      phone_id +
      "\\\",\\\"has_pin\\\":true,\\\"usb_connection\\\":true}\"}";
  const auto hello = session.feed(handshake);
  bool got_response = false;
  for (const auto& output : hello) {
    if (output.kind == hicar::auth::AuthOutput::Kind::Send) {
      got_response = true;
      const std::string text(output.bytes.begin(), output.bytes.end());
      check(text.find("\"usb_connection\":true") != std::string::npos, "有线握手应答应声明 usb_connection=true");
      check(text.find("\"pin_code\":\"024680\"") != std::string::npos, "有线握手应答应带连接码");
    }
  }
  check(got_response, "握手应回一条应答");

  bool succeeded = false;
  std::string key_hex;
  for (const auto& [from, message] : scenario->messages) {
    if (from != "phone") continue;
    const std::string envelope = "{\"version\":\"TEST_1\",\"discover_type\":1,\"oper_type\":3,\"data\":\"" +
                                 hicar::auth::escape_json_string(message) + "\"}";
    const auto outputs = session.feed(envelope);
    for (const auto& output : outputs) {
      if (output.kind == hicar::auth::AuthOutput::Kind::Succeeded) {
        succeeded = true;
        key_hex = hicar::to_hex(output.session_key);
      }
      if (output.kind == hicar::auth::AuthOutput::Kind::Failed) {
        std::fprintf(stderr, "FAIL: 认证外层会话失败，错误码 %d\n", output.error);
        ++g_failures;
      }
    }
  }
  check(succeeded, "外层认证会话应成功");
  check(key_hex == scenario->session_key, "外层认证会话密钥一致");
  check(session.finished(), "认证完成后会话应结束");
}

}  // namespace

int main() {
  const std::string path = vector_path();
  test_crypto_sanity();
  test_pair_and_sts(path);
  test_wrong_pin(path);
  test_wired_auth_session(path);

  if (g_failures != 0) {
    std::fprintf(stderr, "%d 项失败\n", g_failures);
    return 1;
  }
  std::printf("auth 测试全部通过\n");
  return 0;
}
