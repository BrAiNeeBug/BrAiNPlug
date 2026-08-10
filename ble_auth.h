#pragma once
// HMAC-SHA256 helper for the BrAiNPlug BLE auth challenge/response.
// mbedtls is part of the ESP-IDF / Arduino-ESP32 SDK, no extra library needed.
// NOTE: this MUST be a separate header included via esphome->includes, not inlined
// into a lambda - mbedtls headers contain top-level `extern "C" { ... }` blocks,
// which are illegal in the middle of a function body (that's what broke the
// earlier inline attempt).
#include "mbedtls/md.h"
#include <cstdint>
#include <string>
#include <vector>

inline std::vector<uint8_t> ble_hmac_sha256(const std::string &key, const std::vector<uint8_t> &msg) {
  uint8_t out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_setup(&ctx, info, 1 /* use hmac */);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key.data(), key.size());
  mbedtls_md_hmac_update(&ctx, msg.data(), msg.size());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  return std::vector<uint8_t>(out, out + 32);
}

// Constant-time-ish comparison so a failed match doesn't leak timing info via how
// many leading bytes matched.
inline bool ble_hmac_verify(const std::string &key, const std::vector<uint8_t> &nonce,
                             const std::vector<uint8_t> &response) {
  auto expected = ble_hmac_sha256(key, nonce);
  if (response.size() != expected.size()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < expected.size(); i++) diff |= (uint8_t) (expected[i] ^ response[i]);
  return diff == 0;
}

inline std::vector<uint8_t> ble_random_nonce(size_t len) {
  std::vector<uint8_t> nonce;
  nonce.reserve(len);
  for (size_t i = 0; i < len; i++) nonce.push_back((uint8_t) (esp_random() & 0xFF));
  return nonce;
}
