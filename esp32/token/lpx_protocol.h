// lpx_protocol.h — localproof proximity exchange (LPX), version 1.
//
// Shared by the station (esp32_code.ino) and the token (token.ino).
// Keep both copies identical.
//
// The exchange is a distance-bounding check in the Brands–Chaum style:
//
//   station                                   token
//   ------- BEACON(stationId, nonce) ------->           (broadcast)
//   <------ HELLO(nonce, tokenPub, commit) --           commit = H(nonce || m)
//   ------- CHAL(i, c[i]) ------------------>  |
//   <------ RESP(i, r[i] = c[i] ^ m[i]) -----  |  fast phase, timed by the
//           ... LPX_ROUNDS times ...           |  station; no crypto here
//   <------ OPEN(m, sig) --------------------       sig over the transcript
//   ------- RESULT(ok, medianRtt) ---------->       informational only
//   ------- ATTEST(payload, sig) ----------->       on a pass: the signed
//                                                   code from the QR
//
// Why it is split this way: an ECDSA signature takes tens of ms on an
// ATECC608B and varies from call to call, which would drown out the delay
// a relay adds, so a signature can't be what gets timed. The fast phase
// is a single XOR the token can answer in microseconds, but only if it
// knows m. m is committed to before the challenges are seen and revealed
// (and signed over) only afterwards, so a relay sitting next to the
// station can't answer correctly without forwarding every challenge to
// the real token and waiting for the reply.
//
// ATTEST hands the token the same signed code the station puts in its QR,
// so the token can upload it to the server itself (/api/token-proof). It
// needs no protection on the radio: the station's signature covers it,
// and it can only ever credit the token it names.
//
// Two rules make that hold:
//  - The token signs c[] and r[]. A relay that "pre-asks" the token with
//    its own challenges to learn m early ends up with a signature over the
//    wrong challenges, which the station rejects.
//  - The token answers each round index exactly once, in order. A repeat
//    with the same c gets the same answer (lost-ACK retransmits); a
//    different c aborts the session. Without this, a relay could pre-ask,
//    answer the station from m, then replay the real challenges to the
//    token afterwards so that it signs the right transcript.

#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/version.h>

#define LPX_MAGIC      0x584C  // "LX" little-endian
#define LPX_VERSION    1
#define LPX_CHANNEL    6       // both sides must sit on the same Wi-Fi channel
#define LPX_ROUNDS     24      // fast-phase rounds; one random byte each
#define LPX_NONCE_LEN  16
#define LPX_PAYLOAD_MAX 64     // the station's signed payload, see esp32_code.ino

enum LpxType : uint8_t {
  LPX_BEACON = 1,  // station -> broadcast: a session is open
  LPX_HELLO  = 2,  // token -> station: public key + commitment to m
  LPX_CHAL   = 3,  // station -> token: fast-phase challenge byte
  LPX_RESP   = 4,  // token -> station: fast-phase response byte
  LPX_OPEN   = 5,  // token -> station: reveal m + signature over transcript
  LPX_RESULT = 6,  // station -> token: outcome, for the token's UI only
  LPX_ATTEST = 7,  // station -> token: the signed code, for the token to upload
};

struct __attribute__((packed)) LpxHeader {
  uint16_t magic;
  uint8_t  version;
  uint8_t  type;
};

struct __attribute__((packed)) LpxBeacon {
  LpxHeader h;
  char      stationId[8];               // device id, 8 hex chars, no NUL
  uint8_t   nonce[LPX_NONCE_LEN];       // fresh per session
};

struct __attribute__((packed)) LpxHello {
  LpxHeader h;
  uint8_t   nonce[LPX_NONCE_LEN];       // echoes the beacon
  uint8_t   tokenPub[64];               // P-256 public key, raw X||Y
  uint8_t   commit[32];                 // lpxCommit(nonce, m)
};

struct __attribute__((packed)) LpxChal {
  LpxHeader h;
  uint8_t   round;
  uint8_t   c;
};

struct __attribute__((packed)) LpxResp {
  LpxHeader h;
  uint8_t   round;
  uint8_t   r;                          // c ^ m[round]
};

struct __attribute__((packed)) LpxOpen {
  LpxHeader h;
  uint8_t   m[LPX_ROUNDS];              // the committed secret, now revealed
  uint8_t   sig[64];                    // ECDSA P-256 raw r||s over lpxTranscriptHash
};

struct __attribute__((packed)) LpxResultMsg {
  LpxHeader h;
  uint8_t   ok;
  uint32_t  medianRttUs;
};

struct __attribute__((packed)) LpxAttest {
  LpxHeader h;
  char      stationId[8];               // device id, 8 hex chars, no NUL
  uint8_t   payloadLen;
  char      payload[LPX_PAYLOAD_MAX];   // "ts|lat|lng|tokenId|medianRttUs", zero-padded
  uint8_t   sig[64];                    // station's ECDSA r||s over "stationId|payload"
};

// Wire sizes are part of the protocol; both sides must agree exactly.
static_assert(sizeof(LpxBeacon) == 28, "LpxBeacon wire size");
static_assert(sizeof(LpxHello) == 116, "LpxHello wire size");
static_assert(sizeof(LpxChal) == 6, "LpxChal wire size");
static_assert(sizeof(LpxResp) == 6, "LpxResp wire size");
static_assert(sizeof(LpxOpen) == 92, "LpxOpen wire size");
static_assert(sizeof(LpxResultMsg) == 9, "LpxResultMsg wire size");
static_assert(sizeof(LpxAttest) == 141, "LpxAttest wire size");

static inline void lpxHeader(LpxHeader &h, LpxType type) {
  h.magic = LPX_MAGIC;
  h.version = LPX_VERSION;
  h.type = type;
}

static inline bool lpxHeaderOk(const uint8_t *data, int len, LpxType type, size_t size) {
  if (len != (int)size) return false;
  const LpxHeader *h = (const LpxHeader *)data;
  return h->magic == LPX_MAGIC && h->version == LPX_VERSION && h->type == type;
}

// ---- SHA-256 wrappers (mbedtls 3.x in core 3.x, 2.28 in core 2.x) ----

static inline void lpxShaStart(mbedtls_sha256_context &ctx) {
  mbedtls_sha256_init(&ctx);
#if MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256_starts(&ctx, 0);
#else
  mbedtls_sha256_starts_ret(&ctx, 0);
#endif
}

static inline void lpxShaUpdate(mbedtls_sha256_context &ctx, const void *data, size_t len) {
#if MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256_update(&ctx, (const unsigned char *)data, len);
#else
  mbedtls_sha256_update_ret(&ctx, (const unsigned char *)data, len);
#endif
}

static inline void lpxShaFinish(mbedtls_sha256_context &ctx, uint8_t out[32]) {
#if MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256_finish(&ctx, out);
#else
  mbedtls_sha256_finish_ret(&ctx, out);
#endif
  mbedtls_sha256_free(&ctx);
}

// commit = SHA-256("LPX1-commit" || nonce || m)
static inline void lpxCommit(const uint8_t nonce[LPX_NONCE_LEN],
                             const uint8_t m[LPX_ROUNDS], uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  lpxShaStart(ctx);
  lpxShaUpdate(ctx, "LPX1-commit", 11);
  lpxShaUpdate(ctx, nonce, LPX_NONCE_LEN);
  lpxShaUpdate(ctx, m, LPX_ROUNDS);
  lpxShaFinish(ctx, out);
}

// The token signs this hash. It binds the token's key to this station,
// this session and these exact challenges/responses, so a signature can't
// be replayed into another session or grafted onto a relayed fast phase.
//
// H = SHA-256("LPX1" || stationId[8] || nonce || tokenPub || commit || c[] || r[])
static inline void lpxTranscriptHash(const char stationId[8],
                                     const uint8_t nonce[LPX_NONCE_LEN],
                                     const uint8_t tokenPub[64],
                                     const uint8_t commit[32],
                                     const uint8_t c[LPX_ROUNDS],
                                     const uint8_t r[LPX_ROUNDS],
                                     uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  lpxShaStart(ctx);
  lpxShaUpdate(ctx, "LPX1", 4);
  lpxShaUpdate(ctx, stationId, 8);
  lpxShaUpdate(ctx, nonce, LPX_NONCE_LEN);
  lpxShaUpdate(ctx, tokenPub, 64);
  lpxShaUpdate(ctx, commit, 32);
  lpxShaUpdate(ctx, c, LPX_ROUNDS);
  lpxShaUpdate(ctx, r, LPX_ROUNDS);
  lpxShaFinish(ctx, out);
}

// Token id = first 4 bytes of SHA-256(pubkey) as 8 hex chars — the same
// scheme as the station's device id, so the server derives it identically.
static inline void lpxKeyId(const uint8_t pub[64], char out[9]) {
  mbedtls_sha256_context ctx;
  uint8_t h[32];
  lpxShaStart(ctx);
  lpxShaUpdate(ctx, pub, 64);
  lpxShaFinish(ctx, h);
  snprintf(out, 9, "%02x%02x%02x%02x", h[0], h[1], h[2], h[3]);
}

// ECDSA P-256 verify: raw X||Y public key, raw r||s signature.
static inline bool lpxVerifySig(const uint8_t pub[64], const uint8_t hash[32], const uint8_t sig[64]) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  uint8_t uncompressed[65];
  uncompressed[0] = 0x04;
  memcpy(uncompressed + 1, pub, 64);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q, uncompressed, sizeof(uncompressed));
  if (ret == 0) ret = mbedtls_ecp_check_pubkey(&grp, &Q);
  if (ret == 0) ret = mbedtls_mpi_read_binary(&r, sig, 32);
  if (ret == 0) ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
  if (ret == 0) ret = mbedtls_ecdsa_verify(&grp, hash, 32, &Q, &r, &s);

  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ret == 0;
}

// Everything the station checks after the fast phase except timing.
// Returns nullptr if the opening is valid, else a reason string.
// Pure function (no radio, no clock), so it can be tested off-device.
static inline const char *lpxCheckOpening(const char stationId[8],
                                          const uint8_t nonce[LPX_NONCE_LEN],
                                          const LpxHello &hello,
                                          const uint8_t c[LPX_ROUNDS],
                                          const uint8_t r[LPX_ROUNDS],
                                          const LpxOpen &open) {
  uint8_t commit[32];
  lpxCommit(nonce, open.m, commit);
  if (memcmp(commit, hello.commit, 32) != 0) return "commitment mismatch";

  for (int i = 0; i < LPX_ROUNDS; i++) {
    if (r[i] != (uint8_t)(c[i] ^ open.m[i])) return "wrong fast-phase answer";
  }

  uint8_t th[32];
  lpxTranscriptHash(stationId, nonce, hello.tokenPub, hello.commit, c, r, th);
  if (!lpxVerifySig(hello.tokenPub, th, open.sig)) return "bad transcript signature";
  return nullptr;
}
