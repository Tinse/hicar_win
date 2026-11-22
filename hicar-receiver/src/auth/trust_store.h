#pragma once

#include <optional>
#include <string>
#include <vector>

#include "auth/crypto.h"

namespace hicar::auth {

struct LocalIdentity {
  Bytes service_id;
  Bytes auth_id;
  Bytes seed;  // Ed25519 32 字节种子

  Bytes public_key() const;
};

struct TrustedPeer {
  Bytes service_id;
  Bytes auth_id;
  Bytes public_key;
  int user_type = 1;  // 控制器
  int pair_type = 0;  // PIN 绑定
};

class TrustStore {
 public:
  virtual ~TrustStore() = default;
  virtual const LocalIdentity* find_identity(const Bytes& service_id, const Bytes& auth_id) const = 0;
  virtual const TrustedPeer* find_peer(const Bytes& service_id, const Bytes& auth_id) const = 0;
  virtual bool commit_pairing(const LocalIdentity& identity, const TrustedPeer& peer) = 0;
};

class MemoryTrustStore : public TrustStore {
 public:
  MemoryTrustStore() = default;
  explicit MemoryTrustStore(std::string path);  // 启动时读盘，commit 时写盘

  const LocalIdentity* find_identity(const Bytes& service_id, const Bytes& auth_id) const override;
  const TrustedPeer* find_peer(const Bytes& service_id, const Bytes& auth_id) const override;
  bool commit_pairing(const LocalIdentity& identity, const TrustedPeer& peer) override;

  size_t identity_count() const { return identities_.size(); }
  size_t peer_count() const { return peers_.size(); }

 private:
  bool load();
  bool save() const;

  std::string path_;
  std::vector<LocalIdentity> identities_;
  std::vector<TrustedPeer> peers_;
};

}  // namespace hicar::auth
