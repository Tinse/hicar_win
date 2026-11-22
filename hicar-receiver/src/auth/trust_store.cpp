#include "auth/trust_store.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "auth/json.h"
#include "common/hex.h"

namespace hicar::auth {

namespace {

bool same_id(const Bytes& a, const Bytes& b) { return a == b; }

std::string bytes_to_hex(const Bytes& value) { return to_hex(value); }

Bytes hex_to_bytes(const std::string& text) {
  try {
    return from_hex(text);
  } catch (const std::exception&) {
    return {};
  }
}

}  // namespace

Bytes LocalIdentity::public_key() const { return ed25519_public_from_seed(seed); }

MemoryTrustStore::MemoryTrustStore(std::string path) : path_(std::move(path)) { load(); }

const LocalIdentity* MemoryTrustStore::find_identity(const Bytes& service_id,
                                                     const Bytes& auth_id) const {
  for (const auto& identity : identities_) {
    if (same_id(identity.service_id, service_id) && same_id(identity.auth_id, auth_id)) {
      return &identity;
    }
  }
  return nullptr;
}

const TrustedPeer* MemoryTrustStore::find_peer(const Bytes& service_id,
                                               const Bytes& auth_id) const {
  for (const auto& peer : peers_) {
    if (same_id(peer.service_id, service_id) && same_id(peer.auth_id, auth_id)) return &peer;
  }
  return nullptr;
}

bool MemoryTrustStore::commit_pairing(const LocalIdentity& identity, const TrustedPeer& peer) {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if (same_id(it->service_id, identity.service_id) && same_id(it->auth_id, identity.auth_id)) {
      identities_.erase(it);
      break;
    }
  }
  identities_.push_back(identity);
  for (auto it = peers_.begin(); it != peers_.end(); ++it) {
    if (same_id(it->service_id, peer.service_id) && same_id(it->auth_id, peer.auth_id)) {
      peers_.erase(it);
      break;
    }
  }
  peers_.push_back(peer);
  if (!path_.empty()) return save();
  return true;
}

bool MemoryTrustStore::load() {
  if (path_.empty() || !std::filesystem::exists(path_)) return true;
  std::ifstream stream(path_, std::ios::binary);
  if (!stream) return false;
  std::stringstream buffer;
  buffer << stream.rdbuf();
  const auto parsed = parse_json(buffer.str());
  if (!parsed.has_value() || !parsed->is_object()) return false;

  identities_.clear();
  peers_.clear();
  const JsonValue* list = parsed->find("identities");
  if (list != nullptr && list->type == JsonValue::Type::Array) {
    for (const auto& item : list->array) {
      const JsonValue* service = item.find("service");
      const JsonValue* auth_id = item.find("authId");
      const JsonValue* seed = item.find("seed");
      if (service == nullptr || auth_id == nullptr || seed == nullptr) continue;
      LocalIdentity identity{hex_to_bytes(*service->as_string()), hex_to_bytes(*auth_id->as_string()),
                             hex_to_bytes(*seed->as_string())};
      if (identity.service_id.size() == 32 && identity.auth_id.size() >= 1 &&
          identity.auth_id.size() <= 64 && identity.seed.size() == 32) {
        identities_.push_back(std::move(identity));
      }
    }
  }
  list = parsed->find("peers");
  if (list != nullptr && list->type == JsonValue::Type::Array) {
    for (const auto& item : list->array) {
      const JsonValue* service = item.find("service");
      const JsonValue* auth_id = item.find("authId");
      const JsonValue* key = item.find("publicKey");
      if (service == nullptr || auth_id == nullptr || key == nullptr) continue;
      TrustedPeer peer{hex_to_bytes(*service->as_string()), hex_to_bytes(*auth_id->as_string()),
                       hex_to_bytes(*key->as_string())};
      if (peer.service_id.size() == 32 && peer.auth_id.size() >= 1 && peer.auth_id.size() <= 64 &&
          peer.public_key.size() == 32) {
        peers_.push_back(std::move(peer));
      }
    }
  }
  return true;
}

bool MemoryTrustStore::save() const {
  std::ostringstream out;
  out << "{\"format\":1,\"identities\":[";
  for (size_t i = 0; i < identities_.size(); ++i) {
    if (i != 0) out << ',';
    out << "{\"service\":\"" << bytes_to_hex(identities_[i].service_id) << "\",\"authId\":\""
        << bytes_to_hex(identities_[i].auth_id) << "\",\"seed\":\""
        << bytes_to_hex(identities_[i].seed) << "\"}";
  }
  out << "],\"peers\":[";
  for (size_t i = 0; i < peers_.size(); ++i) {
    if (i != 0) out << ',';
    out << "{\"service\":\"" << bytes_to_hex(peers_[i].service_id) << "\",\"authId\":\""
        << bytes_to_hex(peers_[i].auth_id) << "\",\"publicKey\":\""
        << bytes_to_hex(peers_[i].public_key) << "\",\"userType\":" << peers_[i].user_type
        << ",\"pairType\":" << peers_[i].pair_type << "}";
  }
  out << "]}";
  std::filesystem::path path(path_);
  if (path.has_parent_path()) {
    std::filesystem::create_directories(path.parent_path());
  }
  std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream << out.str();
  return true;
}

}  // namespace hicar::auth
