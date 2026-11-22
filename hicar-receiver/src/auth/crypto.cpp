#include "auth/crypto.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace hicar::auth {

namespace {

constexpr const char* kP3072Hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

struct PkeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct MdCtxDeleter {
  void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
};
struct CipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
struct PkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};

EVP_PKEY* raw_private_key(int type, std::span<const uint8_t> key) {
  return EVP_PKEY_new_raw_private_key(type, nullptr, key.data(), key.size());
}

}  // namespace

Bytes sha256(std::span<const uint8_t> data) {
  Bytes out(32);
  unsigned int length = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, out.data(), &length) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("SHA-256 失败");
  }
  EVP_MD_CTX_free(ctx);
  out.resize(length);
  return out;
}

Bytes sha256_parts(const std::vector<Bytes>& parts) {
  Bytes out(32);
  unsigned int length = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("SHA-256 失败");
  }
  for (const auto& part : parts) {
    if (!part.empty()) EVP_DigestUpdate(ctx, part.data(), part.size());
  }
  if (EVP_DigestFinal_ex(ctx, out.data(), &length) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("SHA-256 失败");
  }
  EVP_MD_CTX_free(ctx);
  out.resize(length);
  return out;
}

Bytes hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data) {
  Bytes out(32);
  unsigned int length = 0;
  const unsigned char* mac = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
                                  data.size(), out.data(), &length);
  if (mac == nullptr || length != 32) throw std::runtime_error("HMAC-SHA256 失败");
  return out;
}

Bytes hkdf_sha256(std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
                  std::span<const uint8_t> info, size_t length) {
  const Bytes salt_bytes(salt.begin(), salt.end());
  const Bytes prk = hmac_sha256(salt_bytes, ikm);
  Bytes out;
  out.reserve(length);
  Bytes previous;
  uint8_t counter = 1;
  while (out.size() < length) {
    Bytes input = previous;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(counter);
    previous = hmac_sha256(prk, input);
    const size_t need = length - out.size();
    const size_t take = previous.size() < need ? previous.size() : need;
    out.insert(out.end(), previous.begin(), previous.begin() + static_cast<long>(take));
    ++counter;
  }
  return out;
}

Bytes aes_gcm_encrypt(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                      std::span<const uint8_t> aad, std::span<const uint8_t> plain) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) throw std::runtime_error("AES-GCM 上下文失败");
  Bytes cipher(plain.size() + 16);
  int out_length = 0;
  int total = 0;
  bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
  if (ok && !aad.empty()) {
    ok = EVP_EncryptUpdate(ctx, nullptr, &out_length, aad.data(), static_cast<int>(aad.size())) == 1;
  }
  if (ok && !plain.empty()) {
    ok = EVP_EncryptUpdate(ctx, cipher.data(), &out_length, plain.data(),
                           static_cast<int>(plain.size())) == 1;
    total = out_length;
  }
  if (ok) {
    ok = EVP_EncryptFinal_ex(ctx, cipher.data() + total, &out_length) == 1;
    total += out_length;
  }
  if (ok) {
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, cipher.data() + total) == 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) throw std::runtime_error("AES-GCM 加密失败");
  cipher.resize(static_cast<size_t>(total) + 16);
  return cipher;
}

bool aes_gcm_decrypt(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                     std::span<const uint8_t> aad, std::span<const uint8_t> cipher_and_tag,
                     Bytes* out) {
  if (key.size() != 16 || nonce.empty() || cipher_and_tag.size() < 16) return false;
  const size_t cipher_length = cipher_and_tag.size() - 16;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) return false;
  Bytes plain(cipher_length + 16);
  int out_length = 0;
  int total = 0;
  bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
  if (ok && !aad.empty()) {
    ok = EVP_DecryptUpdate(ctx, nullptr, &out_length, aad.data(), static_cast<int>(aad.size())) == 1;
  }
  if (ok && cipher_length != 0) {
    ok = EVP_DecryptUpdate(ctx, plain.data(), &out_length, cipher_and_tag.data(),
                           static_cast<int>(cipher_length)) == 1;
    total = out_length;
  }
  Bytes tag(cipher_and_tag.begin() + static_cast<long>(cipher_length), cipher_and_tag.end());
  if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) == 1;
  if (ok) {
    ok = EVP_DecryptFinal_ex(ctx, plain.data() + total, &out_length) == 1;
    total += out_length;
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return false;
  plain.resize(static_cast<size_t>(total));
  *out = std::move(plain);
  return true;
}

Bytes ed25519_public_from_seed(std::span<const uint8_t> seed) {
  if (seed.size() != 32) throw std::invalid_argument("Ed25519 种子必须是 32 字节");
  EVP_PKEY* key = raw_private_key(EVP_PKEY_ED25519, seed);
  if (key == nullptr) throw std::runtime_error("Ed25519 私钥失败");
  Bytes out(32);
  size_t length = out.size();
  const bool ok = EVP_PKEY_get_raw_public_key(key, out.data(), &length) == 1;
  EVP_PKEY_free(key);
  if (!ok) throw std::runtime_error("Ed25519 公钥失败");
  return out;
}

Bytes ed25519_sign(std::span<const uint8_t> seed, std::span<const uint8_t> message) {
  if (seed.size() != 32) throw std::invalid_argument("Ed25519 种子必须是 32 字节");
  EVP_PKEY* key = raw_private_key(EVP_PKEY_ED25519, seed);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  Bytes signature(64);
  size_t length = signature.size();
  bool ok = key != nullptr && ctx != nullptr &&
            EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
            EVP_DigestSign(ctx, signature.data(), &length, message.data(), message.size()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  if (!ok) throw std::runtime_error("Ed25519 签名失败");
  return signature;
}

bool ed25519_verify(std::span<const uint8_t> public_key, std::span<const uint8_t> message,
                    std::span<const uint8_t> signature) {
  if (public_key.size() != 32 || signature.size() != 64) return false;
  EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(),
                                              public_key.size());
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  const bool ok = key != nullptr && ctx != nullptr &&
                  EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
                  EVP_DigestVerify(ctx, signature.data(), signature.size(), message.data(),
                                   message.size()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

Bytes x25519_public_from_private(std::span<const uint8_t> private_key) {
  if (private_key.size() != 32) throw std::invalid_argument("X25519 私钥必须是 32 字节");
  EVP_PKEY* key = raw_private_key(EVP_PKEY_X25519, private_key);
  if (key == nullptr) throw std::runtime_error("X25519 私钥失败");
  Bytes out(32);
  size_t length = out.size();
  const bool ok = EVP_PKEY_get_raw_public_key(key, out.data(), &length) == 1;
  EVP_PKEY_free(key);
  if (!ok) throw std::runtime_error("X25519 公钥失败");
  return out;
}

bool x25519_agree(std::span<const uint8_t> private_key, std::span<const uint8_t> peer_public,
                  Bytes* shared) {
  if (private_key.size() != 32 || peer_public.size() != 32) return false;
  EVP_PKEY* self = raw_private_key(EVP_PKEY_X25519, private_key);
  EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public.data(),
                                               peer_public.size());
  EVP_PKEY_CTX* ctx = self != nullptr ? EVP_PKEY_CTX_new(self, nullptr) : nullptr;
  bool ok = ctx != nullptr && peer != nullptr && EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, peer) == 1;
  size_t length = 0;
  if (ok) ok = EVP_PKEY_derive(ctx, nullptr, &length) == 1 && length == 32;
  Bytes out(32);
  if (ok) ok = EVP_PKEY_derive(ctx, out.data(), &length) == 1;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  EVP_PKEY_free(self);
  if (!ok) return false;
  // 全零结果代表小阶点，按失败处理。
  bool all_zero = true;
  for (uint8_t b : out) {
    if (b != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) return false;
  out.resize(length);
  *shared = std::move(out);
  return true;
}

Bytes modp_modpow(std::span<const uint8_t> base, std::span<const uint8_t> exponent, size_t length) {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* p = nullptr;
  BIGNUM* b = BN_bin2bn(base.data(), static_cast<int>(base.size()), nullptr);
  BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);
  BIGNUM* r = BN_new();
  bool ok = ctx != nullptr && b != nullptr && e != nullptr && r != nullptr &&
            BN_hex2bn(&p, kP3072Hex) != 0;
  if (ok) ok = BN_mod_exp(r, b, e, p, ctx) == 1;
  Bytes out(length);
  if (ok) ok = BN_bn2binpad(r, out.data(), static_cast<int>(length)) != -1;
  BN_free(r);
  BN_free(e);
  BN_free(b);
  BN_free(p);
  BN_CTX_free(ctx);
  if (!ok) throw std::runtime_error("MODP 模幂失败");
  return out;
}

bool modp_is_valid_public(std::span<const uint8_t> value, size_t length) {
  if (value.size() > length) return false;
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* p = nullptr;
  BIGNUM* one = BN_new();
  BIGNUM* upper = BN_new();
  BIGNUM* v = BN_bin2bn(value.data(), static_cast<int>(value.size()), nullptr);
  bool ok = ctx != nullptr && one != nullptr && upper != nullptr && v != nullptr &&
            BN_hex2bn(&p, kP3072Hex) != 0 && BN_one(one) == 1 && BN_copy(upper, p) != nullptr &&
            BN_sub_word(upper, 1) == 1;
  const bool valid = ok && BN_cmp(v, one) > 0 && BN_cmp(v, upper) < 0;
  BN_free(v);
  BN_free(upper);
  BN_free(one);
  BN_free(p);
  BN_CTX_free(ctx);
  return valid;
}

Bytes SystemRandom::bytes(size_t count) {
  Bytes out(count);
  if (RAND_bytes(out.data(), static_cast<int>(count)) != 1) {
    throw std::runtime_error("随机数失败");
  }
  return out;
}

SequenceRandom::SequenceRandom(std::string seed) : seed_(std::move(seed)) {}

Bytes SequenceRandom::bytes(size_t count) {
  Bytes out;
  out.reserve(count);
  while (out.size() < count) {
    if (position_ == block_.size()) {
      Bytes input(seed_.begin(), seed_.end());
      input.push_back(static_cast<uint8_t>((counter_ >> 24) & 0xFF));
      input.push_back(static_cast<uint8_t>((counter_ >> 16) & 0xFF));
      input.push_back(static_cast<uint8_t>((counter_ >> 8) & 0xFF));
      input.push_back(static_cast<uint8_t>(counter_ & 0xFF));
      ++counter_;
      block_ = sha256(input);
      position_ = 0;
    }
    out.push_back(block_[position_++]);
  }
  drawn_ += count;
  return out;
}

}  // namespace hicar::auth
