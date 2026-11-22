#include "auth/authenticator.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <optional>
#include <utility>

#include "auth/hichain.h"
#include "auth/json.h"
#include "common/hex.h"

namespace hicar::auth {

namespace {

constexpr size_t kChallengeLength = 16;
constexpr size_t kSaltLength = 16;
constexpr size_t kHkdfSecretLength = 32;
constexpr size_t kPakeSessionKeyLength = 16;
constexpr size_t kPakeHmacKeyLength = 32;
constexpr size_t kPakeEskLength = 32;
constexpr size_t kStsSessionKeyLength = 16;
constexpr size_t kGcmNonceLength = 12;
constexpr size_t kExchangePlainMax = 300;
constexpr size_t kStsPlainMax = 256;
constexpr size_t kModpLength = 384;

constexpr const char* kSpekeBaseInfo = "hichain_speke_base_info";
constexpr const char* kSpekeSessionKeyInfo = "hichain_speke_sessionkey_info";
constexpr const char* kReturnKeyInfo = "hichain_return_key";
constexpr const char* kStsAuthInfo = "hichain_auth_info";
constexpr const char* kExchangeRequestAad = "hichain_exchange_request";
constexpr const char* kExchangeResponseAad = "hichain_exchange_response";
constexpr const char* kExchangeAuthInfoPkcs = "hichain_exchange_pkcs";

constexpr uint32_t kVersionCurrentFirst = 1;
constexpr uint32_t kVersionCurrentSecond = 0;
constexpr uint32_t kVersionCurrentThird = 0;

struct HcFailure {
  int error = 0;
};

struct SilentFailure {
  int error = 0;
};

Bytes ascii(const std::string& text) { return Bytes(text.begin(), text.end()); }

Bytes pad16(Bytes value) {
  value.resize(kChallengeLength, 0);
  return value;
}

Bytes concat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
  return out;
}

Bytes encrypt_payload(const Bytes& key, const Bytes& plain, const Bytes& aad,
                      RandomSource& random) {
  Bytes nonce = random.bytes(kGcmNonceLength);
  Bytes cipher = aes_gcm_encrypt(key, nonce, aad, plain);
  cipher.insert(cipher.begin(), nonce.begin(), nonce.end());
  return cipher;
}

std::optional<Bytes> decrypt_payload(const Bytes& key, const Bytes& cipher, const Bytes& aad,
                                     size_t max_plain) {
  if (cipher.size() < kGcmNonceLength ||
      cipher.size() - kGcmNonceLength <= 16) {
    return std::nullopt;
  }
  Bytes nonce(cipher.begin(), cipher.begin() + kGcmNonceLength);
  Bytes body(cipher.begin() + kGcmNonceLength, cipher.end());
  Bytes plain;
  if (!aes_gcm_decrypt(key, nonce, aad, body, &plain)) return std::nullopt;
  if (plain.size() > max_plain) return std::nullopt;
  return plain;
}

bool version_supported(const Version& current, const Version& minimum) {
  const Version self{kVersionCurrentFirst, kVersionCurrentSecond, kVersionCurrentThird};
  return current >= self && minimum <= self;
}

struct PakeServer {
  enum class State { Init, StartResponse, Finish, Error };

  Bytes pin;
  int key_length = kPakeSessionKeyLength;
  Bytes self_id;
  RandomSource& random;

  State state = State::Init;
  State last_state = State::Init;

  Bytes salt;
  Bytes self_challenge;
  Bytes peer_challenge;
  Bytes esk;
  Bytes session_key;
  Bytes hmac_key;
  Bytes service_key;

  PakeServer(Bytes pin_value, int length, Bytes id, RandomSource& rng)
      : pin(std::move(pin_value)), key_length(length), self_id(std::move(id)), random(rng) {}

  void set_state(State next) {
    if (state == State::Error || state == State::Finish) return;
    if (static_cast<int>(next) < static_cast<int>(state)) return;
    if (state != next) {
      last_state = state;
      state = next;
    }
  }

  bool can_start_response() const {
    return state == State::Init || last_state == State::Init;
  }

  bool can_end_response() const {
    return state == State::StartResponse || last_state == State::StartResponse;
  }

  std::string start_response(const PakeStartRequest& request) {
    if (!can_start_response()) throw HcFailure{hcerr::kProtocolStateError};
    if (!version_supported(request.current, request.minimum)) {
      state = State::Error;
      throw HcFailure{hcerr::kVersionUnsupported};
    }
    if (state == State::Init) {
      salt = random.bytes(kSaltLength);
      self_challenge = random.bytes(kChallengeLength);
      esk = random.bytes(kPakeEskLength);
    }
    const Bytes secret = hkdf_sha256(pin, salt, ascii(kSpekeBaseInfo), kHkdfSecretLength);
    const Bytes two{2};
    const Bytes generator = modp_modpow(secret, two, kModpLength);
    const Bytes epk = modp_modpow(generator, esk, kModpLength);
    const std::string text = build_pake_response(self_challenge, salt, epk);
    set_state(State::StartResponse);
    return text;
  }

  std::string end_response(const PakeEndRequest& request) {
    if (!can_end_response()) throw HcFailure{hcerr::kProtocolStateError};
    peer_challenge = request.challenge;
    if (!modp_is_valid_public(request.epk, kModpLength)) {
      session_key.clear();
      hmac_key.clear();
      state = State::Error;
      throw HcFailure{hcerr::kGenerateSessionKeyFailed};
    }
    const Bytes shared = modp_modpow(request.epk, esk, kModpLength);
    const Bytes okm = hkdf_sha256(shared, salt, ascii(kSpekeSessionKeyInfo), kHkdfSecretLength);
    session_key.assign(okm.begin(), okm.begin() + static_cast<long>(kPakeSessionKeyLength));
    hmac_key.assign(okm.begin() + static_cast<long>(kPakeSessionKeyLength), okm.end());
    if (hmac_key.size() < kPakeHmacKeyLength) hmac_key.resize(kPakeHmacKeyLength, 0);

    const Bytes expected =
        hmac_sha256(hmac_key, concat({pad16(peer_challenge), pad16(self_challenge)}));
    if (request.kcf.size() != expected.size() ||
        !std::equal(expected.begin(), expected.end(), request.kcf.begin())) {
      state = State::Error;
      throw HcFailure{hcerr::kVerifyProofFailed};
    }
    service_key = hkdf_sha256(session_key, salt, ascii(kReturnKeyInfo),
                              static_cast<size_t>(key_length));
    const Bytes proof =
        hmac_sha256(hmac_key, concat({pad16(self_challenge), pad16(peer_challenge)}));
    set_state(State::Finish);
    return build_pake_server_confirm(proof);
  }
};

std::optional<Bytes> parse_auth_info_object(const Bytes& auth_info, Bytes* auth_id, Bytes* public_key) {
  size_t nul = auth_info.size();
  for (size_t i = 0; i < auth_info.size(); ++i) {
    if (auth_info[i] == 0) {
      nul = i;
      break;
    }
  }
  size_t start = 0;
  while (start < nul && auth_info[start] <= 0x20) ++start;
  if (start >= nul || auth_info[start] != '{') return std::nullopt;

  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  size_t end = std::string::npos;
  for (size_t i = start; i < nul; ++i) {
    const uint8_t b = auth_info[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (b == '\\') {
        escaped = true;
      } else if (b == '"') {
        in_string = false;
      }
      continue;
    }
    if (b == '"') {
      in_string = true;
    } else if (b == '{' || b == '[') {
      ++depth;
    } else if (b == '}' || b == ']') {
      --depth;
      if (depth == 0) {
        end = i + 1;
        break;
      }
    }
  }
  if (end == std::string::npos) return std::nullopt;

  std::string text(auth_info.begin() + static_cast<long>(start),
                   auth_info.begin() + static_cast<long>(end));
  const auto parsed = parse_json(text);
  if (!parsed.has_value() || !parsed->is_object()) return std::nullopt;
  const JsonValue* id = parsed->find_ci("authId");
  const JsonValue* pk = parsed->find_ci("authPk");
  if (id == nullptr || pk == nullptr) return std::nullopt;
  const auto id_text = id->as_string();
  const auto pk_text = pk->as_string();
  if (!id_text.has_value() || !pk_text.has_value()) return std::nullopt;
  try {
    Bytes id_bytes = from_hex(*id_text);
    Bytes pk_bytes = from_hex(*pk_text);
    if (id_bytes.size() < 1 || id_bytes.size() > 64) return std::nullopt;
    if (pk_bytes.size() != 32) return std::nullopt;
    *auth_id = std::move(id_bytes);
    *public_key = std::move(pk_bytes);
  } catch (const std::exception&) {
    return std::nullopt;
  }
  return auth_info;
}

struct StsServer {
  enum class State { Init, StartResponse, Finish, Error };

  Bytes self_id;
  Bytes peer_id;
  int key_length = kStsSessionKeyLength;
  RandomSource& random;
  const TrustedPeer* peer;
  const LocalIdentity* identity = nullptr;

  State state = State::Init;
  State last_state = State::Init;

  Bytes self_ephemeral_private;
  Bytes self_ephemeral_public;
  Bytes peer_ephemeral_public;
  Bytes peer_challenge;
  Bytes my_challenge;
  Bytes salt;
  Bytes session_key;
  Bytes service_key;
  std::optional<std::string> cached_start;
  std::optional<std::string> cached_end;

  StsServer(Bytes self, Bytes peer_id_value, int length, RandomSource& rng,
            const TrustedPeer* trusted, const LocalIdentity* local_identity)
      : self_id(std::move(self)), peer_id(std::move(peer_id_value)), key_length(length), random(rng),
        peer(trusted), identity(local_identity) {}

  void set_state(State next) {
    if (state == State::Error || state == State::Finish) return;
    if (static_cast<int>(next) < static_cast<int>(state)) return;
    if (state != next) {
      last_state = state;
      state = next;
    }
  }

  bool can_start_response() const { return state == State::Init || last_state == State::Init; }
  bool can_end_response() const {
    return state == State::StartResponse || last_state == State::StartResponse;
  }

  std::string start_response(const StsStartRequest& request) {
    if (cached_start.has_value()) return *cached_start;
    if (!can_start_response()) throw HcFailure{hcerr::kProtocolStateError};
    if (!version_supported(request.current, request.minimum)) {
      state = State::Error;
      throw HcFailure{hcerr::kVersionUnsupported};
    }
    peer_challenge = request.challenge;
    peer_ephemeral_public = request.epk;
    if (state == State::Init) {
      self_ephemeral_private = random.bytes(32);
      self_ephemeral_public = x25519_public_from_private(self_ephemeral_private);
      salt = random.bytes(kSaltLength);
    }
    Bytes shared;
    if (!x25519_agree(self_ephemeral_private, peer_ephemeral_public, &shared)) {
      state = State::Error;
      throw HcFailure{hcerr::kComputeStsSharedSecretFailed};
    }
    session_key = hkdf_sha256(shared, salt, ascii(kStsAuthInfo), kStsSessionKeyLength);

    const Bytes message =
        concat({self_ephemeral_public, self_id, peer_ephemeral_public, peer_id});
    const Bytes signature = ed25519_sign(identity->seed, sha256(message));
    const Bytes auth_data = encrypt_payload(session_key, signature, peer_challenge, random);
    if (state == State::Init) my_challenge = random.bytes(kChallengeLength);
    const std::string text = build_auth_start_response(
        auth_data, my_challenge, self_ephemeral_public, salt, self_id, 0);
    set_state(State::StartResponse);
    cached_start = text;
    return text;
  }

  std::string end_response(const StsEndRequest& request) {
    if (cached_end.has_value()) return *cached_end;
    if (!can_end_response()) throw HcFailure{hcerr::kProtocolStateError};
    const auto signature = decrypt_payload(session_key, request.auth_data, my_challenge, kStsPlainMax);
    if (!signature.has_value()) {
      state = State::Error;
      throw HcFailure{hcerr::kDecryptFailed};
    }
    if (signature->size() > 64) {
      state = State::Error;
      throw HcFailure{hcerr::kMemcpyError};
    }
    const Bytes message = concat({peer_ephemeral_public, peer_id, self_ephemeral_public, self_id});
    const Bytes digest = sha256(message);
    const bool verified =
        peer != nullptr && ed25519_verify(peer->public_key, digest, *signature);
    if (!verified) {
      state = State::Error;
      throw HcFailure{hcerr::kVerifyProofFailed};
    }
    const Bytes zero{0};
    const Bytes auth_return = encrypt_payload(session_key, zero, peer_challenge, random);
    service_key = hkdf_sha256(session_key, salt, ascii(kReturnKeyInfo),
                              static_cast<size_t>(key_length));
    const std::string text = build_auth_ack_response(auth_return);
    set_state(State::Finish);
    cached_end = text;
    return text;
  }
};

}  // namespace

struct AccessoryAuthenticator::Impl {
  enum class State { Init, KeyAgreement, Operation, Over };
  enum class Modular { Pake, Sts, Exchange, Other };

  struct Parsed {
    enum class Kind { PakeStart, PakeEnd, Exchange, StsStart, StsEnd, Response };
    Kind kind = Kind::PakeStart;
    PakeStartRequest pake_start;
    PakeEndRequest pake_end;
    ExchangeRequest exchange;
    StsStartRequest sts_start;
    StsEndRequest sts_end;
    int response_code = 0;
  };

  struct Nav {
    Modular modular = Modular::Other;
    int step = 0;
    bool is_request = true;
  };

  Impl(AccessoryAuthConfig config, TrustStore& store, RandomSource& rng)
      : config(std::move(config)), store(store), random(rng) {
    service_id = sha256_parts({ascii(this->config.service_package), ascii(this->config.service_type)});
    self_id = this->config.self_auth_id;
    peer_id = this->config.peer_auth_id;
    pin = this->config.pin;
    const LocalIdentity* existing = store.find_identity(service_id, self_id);
    if (existing != nullptr) {
      identity = *existing;
    } else {
      identity = LocalIdentity{service_id, self_id, random.bytes(32)};
    }
    peer_trusted = store.find_peer(service_id, peer_id) != nullptr;
  }

  bool peer_trusted = false;
  bool finished = false;
  State state = State::Init;
  State last_state = State::Init;
  int operation_code = op::kNoOperation;

  AccessoryAuthConfig config;
  TrustStore& store;
  RandomSource& random;
  Bytes service_id;
  Bytes self_id;
  Bytes peer_id;
  std::optional<Bytes> pin;
  LocalIdentity identity;

  std::optional<PakeServer> pake;
  std::optional<StsServer> sts;
  bool pake_client_built = false;
  std::optional<Bytes> session_key;

  void finish() {
    finished = true;
    pake.reset();
    sts.reset();
  }

  Parsed deserialize(int code, const JsonValue& root) {
    if (code == -1) throw HcFailure{hcerr::kBuildObjectFailed};
    const JsonValue* payload = root.find_ci("payload");
    if (payload == nullptr || !payload->is_object()) throw HcFailure{hcerr::kBuildObjectFailed};

    switch (code) {
      case code::kPakeRequest: {
        const auto parsed = parse_pake_start(*payload);
        if (!parsed.has_value()) throw HcFailure{hcerr::kBuildObjectFailed};
        Parsed out;
        out.kind = Parsed::Kind::PakeStart;
        out.pake_start = *parsed;
        return out;
      }
      case code::kPakeClientConfirm: {
        const auto parsed = parse_pake_end(*payload);
        if (!parsed.has_value()) throw HcFailure{hcerr::kBuildObjectFailed};
        Parsed out;
        out.kind = Parsed::Kind::PakeEnd;
        out.pake_end = *parsed;
        return out;
      }
      case code::kExchangeRequest: {
        const auto parsed = parse_exchange(*payload);
        if (!parsed.has_value()) throw HcFailure{hcerr::kBuildObjectFailed};
        Parsed out;
        out.kind = Parsed::Kind::Exchange;
        out.exchange = *parsed;
        return out;
      }
      case code::kAuthStartRequest: {
        const auto parsed = parse_sts_start(*payload);
        if (!parsed.has_value()) throw HcFailure{hcerr::kBuildObjectFailed};
        Parsed out;
        out.kind = Parsed::Kind::StsStart;
        out.sts_start = *parsed;
        return out;
      }
      case code::kAuthAckRequest: {
        const auto parsed = parse_sts_end(*payload);
        if (!parsed.has_value()) throw HcFailure{hcerr::kBuildObjectFailed};
        Parsed out;
        out.kind = Parsed::Kind::StsEnd;
        out.sts_end = *parsed;
        return out;
      }
      case code::kPakeResponse:
      case code::kPakeServerConfirmResponse:
      case code::kExchangeResponse:
      case code::kAuthStartResponse:
      case code::kAuthAckResponse: {
        if (!validate_response(code, *payload)) throw HcFailure{hcerr::kBuildObjectFailed};
        Parsed out;
        out.kind = Parsed::Kind::Response;
        out.response_code = code;
        return out;
      }
      case code::kAddAuthInfoRequest:
      case code::kRemoveAuthInfoRequest:
      case code::kAddAuthInfoResponse:
      case code::kRemoveAuthInfoResponse:
      case code::kSecCloneStartRequest:
      case code::kSecCloneAckRequest:
        throw HcFailure{hcerr::kBuildObjectFailed};
      default: throw HcFailure{hcerr::kUnknownMessage};
    }
  }

  Nav navigate(int code) const {
    Nav nav;
    const int base = code & 0x7FFF;
    if (base == code::kPakeRequest || base == code::kPakeClientConfirm) {
      nav.modular = Modular::Pake;
    } else if (base == code::kExchangeRequest) {
      nav.modular = Modular::Exchange;
    } else if (base == code::kAuthStartRequest || base == code::kAuthAckRequest) {
      nav.modular = Modular::Sts;
    } else {
      nav.modular = Modular::Other;
    }
    nav.step = code & 0xF;
    nav.is_request = (code & 0x8000) == 0;
    return nav;
  }

  bool is_legal(int operation, Modular modular) const {
    switch (modular) {
      case Modular::Pake:
        return operation == op::kBind || operation == op::kAuthKeyAgreement;
      case Modular::Exchange:
        return operation == op::kBind;
      case Modular::Sts:
        return operation == op::kAuthenticate || operation == op::kAddAuthInfo ||
               operation == op::kRemoveAuthInfo || operation == op::kUnbind ||
               operation == op::kSecClone;
      case Modular::Other:
        return false;
    }
    return false;
  }

  bool confirm(int operation) const {
    switch (operation) {
      case op::kBind: return pin.has_value();
      case op::kAuthenticate: return peer_trusted;
      default: return false;
    }
  }

  void check_message_support(const Nav& nav, const Parsed& parsed) {
    const bool state_ok =
        (nav.modular == Modular::Pake || nav.modular == Modular::Sts)
            ? (state == State::Init || state == State::KeyAgreement || last_state == State::Init ||
               last_state == State::KeyAgreement)
            : (state == State::KeyAgreement || state == State::Operation ||
               last_state == State::KeyAgreement || last_state == State::Operation);
    if (!state_ok) throw HcFailure{hcerr::kStateError};

    int operation = op::kNoOperation;
    if (parsed.kind == Parsed::Kind::PakeStart) {
      const int value = parsed.pake_start.operation_code;
      operation = (value == op::kBind || value == op::kAuthKeyAgreement) ? value : -1;
    } else if (parsed.kind == Parsed::Kind::StsStart) {
      const int value = parsed.sts_start.operation_code;
      const bool known = value == op::kAuthenticate || value == op::kAddAuthInfo ||
                         value == op::kRemoveAuthInfo || value == op::kUnbind ||
                         value == op::kSecClone;
      operation = known ? value : -1;
    }

    if (operation == -1) throw HcFailure{hcerr::kOperationCodeError};
    if (operation == op::kNoOperation) {
      if (!is_legal(operation_code, nav.modular)) throw HcFailure{hcerr::kMessageInconsistency};
    } else {
      if (!confirm(operation)) throw HcFailure{hcerr::kServiceConfirmError};
      operation_code = operation;
    }
  }

  void build_object(const Nav& nav) {
    switch (nav.modular) {
      case Modular::Pake:
        if (nav.is_request) {
          if (!pake.has_value()) {
            if (sts.has_value()) throw HcFailure{hcerr::kRepeatedReference};
            pake.emplace(pin.value_or(Bytes{}), kPakeSessionKeyLength, self_id, random);
          }
        } else if (!pake_client_built) {
          if (sts.has_value()) throw HcFailure{hcerr::kRepeatedReference};
          pake_client_built = true;
        }
        break;
      case Modular::Sts:
        if (nav.is_request) {
          if (!sts.has_value()) {
            if (pake.has_value() || pake_client_built) throw HcFailure{hcerr::kRepeatedReference};
            sts.emplace(self_id, peer_id, kStsSessionKeyLength, random,
                        store.find_peer(service_id, peer_id), &identity);
          }
        } else {
          throw HcFailure{hcerr::kRepeatedReference};
        }
        break;
      case Modular::Exchange:
      case Modular::Other:
        break;
    }
  }

  std::string exchange(const ExchangeRequest& request) {
    if (!pake.has_value()) throw HcFailure{hcerr::kPaKeObjectError};
    const Bytes key = pake->session_key;
    const auto plain =
        decrypt_payload(key, request.cipher, ascii(kExchangeRequestAad), kExchangePlainMax);
    if (!plain.has_value()) throw HcFailure{hcerr::kDecryptFailed};
    if (plain->size() <= 64) throw HcFailure{hcerr::kSignTooShort};

    const size_t info_size = plain->size() - 64;
    Bytes auth_info(plain->begin(), plain->begin() + static_cast<long>(info_size));
    Bytes signature(plain->begin() + static_cast<long>(info_size), plain->end());
    Bytes peer_auth_id;
    Bytes peer_public_key;
    if (!parse_auth_info_object(auth_info, &peer_auth_id, &peer_public_key)) {
      throw HcFailure{hcerr::kDecryptFailed};
    }

    const Bytes peer_digest =
        sha256(concat({pad16(pake->peer_challenge), pad16(pake->self_challenge), auth_info}));
    if (!ed25519_verify(peer_public_key, peer_digest, signature)) {
      throw HcFailure{hcerr::kVerifyExchangeFailed};
    }

    const Bytes self_info = ascii(build_exchange_auth_info(self_id, identity.public_key()));
    const Bytes self_digest =
        sha256(concat({pad16(pake->self_challenge), pad16(pake->peer_challenge), self_info}));
    const Bytes self_sign = ed25519_sign(identity.seed, self_digest);
    const Bytes cipher =
        encrypt_payload(key, concat({self_info, self_sign}), ascii(kExchangeResponseAad), random);

    TrustedPeer peer{service_id, peer_auth_id, peer_public_key};
    if (!store.commit_pairing(identity, peer)) throw HcFailure{hcerr::kSaveLtpkFailed};
    return build_exchange_response(cipher);
  }

  std::string process(const Parsed& parsed) {
    switch (parsed.kind) {
      case Parsed::Kind::PakeStart:
        if (!pake.has_value()) throw HcFailure{hcerr::kPaKeObjectError};
        return pake->start_response(parsed.pake_start);
      case Parsed::Kind::PakeEnd: {
        if (!pake.has_value()) throw HcFailure{hcerr::kPaKeObjectError};
        std::string reply = pake->end_response(parsed.pake_end);
        session_key = pake->service_key;
        return reply;
      }
      case Parsed::Kind::Exchange:
        return exchange(parsed.exchange);
      case Parsed::Kind::StsStart:
        if (!sts.has_value()) throw HcFailure{hcerr::kStsObjectError};
        return sts->start_response(parsed.sts_start);
      case Parsed::Kind::StsEnd: {
        if (!sts.has_value()) throw HcFailure{hcerr::kStsObjectError};
        std::string reply = sts->end_response(parsed.sts_end);
        session_key = sts->service_key;
        return reply;
      }
      case Parsed::Kind::Response:
        if (parsed.response_code == code::kPakeResponse ||
            parsed.response_code == code::kPakeServerConfirmResponse) {
          throw HcFailure{hcerr::kProtocolStateError};
        }
        if (parsed.response_code == code::kExchangeResponse) throw SilentFailure{hcerr::kPaKeObjectError};
        throw HcFailure{hcerr::kInnerError};
    }
    throw HcFailure{hcerr::kInnerError};
  }

  void set_result(int received_code, std::vector<AuthAction>& actions) {
    int mapped = -1;
    State target = state;
    switch (received_code) {
      case code::kPakeRequest:
      case code::kAuthStartRequest:
        mapped = 2;
        target = State::KeyAgreement;
        break;
      case code::kPakeClientConfirm:
      case code::kAuthAckRequest:
        mapped = 3;
        target = State::Operation;
        break;
      case code::kExchangeRequest:
        mapped = 0;
        target = State::Over;
        break;
      default:
        return;
    }

    int result = mapped;
    if (target == State::Operation &&
        (operation_code == op::kAuthenticate || operation_code == op::kAuthKeyAgreement)) {
      if (state != State::Over) {
        last_state = state;
        state = State::Over;
      }
      result = 0;
    } else if (state != target) {
      last_state = state;
      state = target;
    }

    if (result == 0) {
      const auto key = session_key;
      session_key.reset();
      finish();
      if (key.has_value() && key->size() == kPakeSessionKeyLength) {
        AuthAction action;
        action.kind = AuthAction::Kind::Succeeded;
        action.session_key = *key;
        actions.push_back(std::move(action));
      } else {
        AuthAction action;
        action.kind = AuthAction::Kind::Failed;
        action.error = hcerr::kInnerError;
        actions.push_back(action);
      }
    } else {
      AuthAction action;
      action.kind = AuthAction::Kind::Progress;
      action.result = result;
      actions.push_back(action);
    }
  }

  std::vector<AuthAction> receive(const JsonValue& root) {
    std::vector<AuthAction> actions;
    int received_code = 0;
    std::string reply;
    int error = 0;
    bool silent = false;
    try {
      const JsonValue* code_field = root.find_ci("message");
      const auto code_value = code_field != nullptr ? code_field->as_int() : std::nullopt;
      const int code = code_value.value_or(-1);
      const Parsed parsed = deserialize(code, root);
      received_code = code;
      const Nav nav = navigate(code);
      check_message_support(nav, parsed);
      build_object(nav);
      reply = process(parsed);
    } catch (const HcFailure& failure) {
      error = failure.error;
    } catch (const SilentFailure& failure) {
      error = failure.error;
      silent = true;
    } catch (const std::exception&) {
      error = hcerr::kInnerError;
    }

    if (error != 0) {
      if (!silent) {
        AuthAction send;
        send.kind = AuthAction::Kind::Send;
        send.message = build_inform(error);
        actions.push_back(std::move(send));
      }
      last_state = state;
      state = State::Over;
      finish();
      AuthAction failed;
      failed.kind = AuthAction::Kind::Failed;
      failed.error = error;
      actions.push_back(std::move(failed));
      return actions;
    }

    AuthAction send;
    send.kind = AuthAction::Kind::Send;
    send.message = reply;
    actions.push_back(std::move(send));
    set_result(received_code, actions);
    return actions;
  }

  std::vector<AuthAction> on_message(std::string_view text) {
    if (finished) return {};
    const auto root = parse_json(text);
    if (!root.has_value() || !root->is_object()) {
      finished = true;
      AuthAction failed;
      failed.kind = AuthAction::Kind::Failed;
      failed.error = hcerr::kInputError;
      failed.malformed = true;
      return {failed};
    }
    const JsonValue* message_field = root->find("message");
    const auto code_value = message_field != nullptr ? message_field->as_int() : std::nullopt;
    if (!code_value.has_value()) {
      finished = true;
      AuthAction failed;
      failed.kind = AuthAction::Kind::Failed;
      failed.error = hcerr::kInputError;
      failed.malformed = true;
      return {failed};
    }

    if (*code_value == code::kInformMessage) {
      int peer_error = hcerr::kInputError;
      const JsonValue* payload = root->find("payload");
      if (payload != nullptr && payload->is_object()) {
        const JsonValue* error_code = payload->find("errorCode");
        if (error_code != nullptr) {
          const auto value = error_code->as_int();
          if (value.has_value()) peer_error = static_cast<int>(*value);
        }
      }
      finish();
      AuthAction failed;
      failed.kind = AuthAction::Kind::Failed;
      failed.error = peer_error;
      return {failed};
    }
    return receive(*root);
  }
};

AccessoryAuthenticator::AccessoryAuthenticator(AccessoryAuthConfig config, TrustStore& store,
                                               RandomSource& random)
    : impl_(std::make_unique<Impl>(std::move(config), store, random)) {}

AccessoryAuthenticator::~AccessoryAuthenticator() = default;

bool AccessoryAuthenticator::peer_trusted() const { return impl_->peer_trusted; }

bool AccessoryAuthenticator::finished() const { return impl_->finished; }

std::vector<AuthAction> AccessoryAuthenticator::on_message(std::string_view message) {
  return impl_->on_message(message);
}

}  // namespace hicar::auth
