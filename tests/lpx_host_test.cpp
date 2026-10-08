// lpx_host_test.cpp — runs the station's opening checks (lpxCheckOpening)
// against an honest token and several attacks, on a PC. No radio involved;
// timing is tested on hardware. tests/test_lpx_firmware.py builds and runs
// it under pytest; by hand, from the repo root:
//
//   g++ -std=c++17 -Iesp32 tests/lpx_host_test.cpp -lmbedcrypto -o /tmp/lpx && /tmp/lpx
//
// Needs mbedtls headers (Debian/Ubuntu: libmbedtls-dev). It lives here,
// not in esp32/, because Arduino compiles every .cpp in the sketch folder.

#include <cstdio>
#include <cstdlib>
#include <random>
#include "lpx_protocol.h"

static std::mt19937 prng(12345);  // test only; firmware uses the hardware RNG

static int testRng(void *, unsigned char *buf, size_t len) {
  for (size_t i = 0; i < len; i++) buf[i] = (unsigned char)(prng() & 0xFF);
  return 0;
}
static void fill(uint8_t *p, size_t n) { testRng(nullptr, p, n); }

// A software token: P-256 key, signs like token.ino's software fallback.
struct Key {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  uint8_t pub[64];
  Key() {
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecp_gen_keypair(&grp, &d, &Q, testRng, nullptr);
    uint8_t u[65];
    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, u, sizeof(u));
    memcpy(pub, u + 1, 64);
  }
  void sign(const uint8_t hash[32], uint8_t sig[64]) {
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32, testRng, nullptr);
    mbedtls_mpi_write_binary(&r, sig, 32);
    mbedtls_mpi_write_binary(&s, sig + 32, 32);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
  }
};

// One session from the station's point of view.
struct Session {
  char stationId[8];
  uint8_t nonce[LPX_NONCE_LEN];
  uint8_t m[LPX_ROUNDS];
  LpxHello hello;
  uint8_t c[LPX_ROUNDS], r[LPX_ROUNDS];
  LpxOpen open;

  Session(Key &tok) {
    memcpy(stationId, "a1b2c3d4", 8);
    fill(nonce, sizeof(nonce));
    fill(m, sizeof(m));                       // token's secret
    memcpy(hello.nonce, nonce, LPX_NONCE_LEN);
    memcpy(hello.tokenPub, tok.pub, 64);
    lpxCommit(nonce, m, hello.commit);
    fill(c, sizeof(c));                       // station's challenges
    for (int i = 0; i < LPX_ROUNDS; i++) r[i] = c[i] ^ m[i];
    memcpy(open.m, m, LPX_ROUNDS);
  }
  // The token signs the transcript it saw (by default, the real one).
  void tokenSigns(Key &k, const uint8_t *seenC = nullptr, const uint8_t *seenR = nullptr) {
    uint8_t th[32];
    lpxTranscriptHash(stationId, nonce, hello.tokenPub, hello.commit,
                      seenC ? seenC : c, seenR ? seenR : r, th);
    k.sign(th, open.sig);
  }
  const char *check() { return lpxCheckOpening(stationId, nonce, hello, c, r, open); }
};

static int failures = 0;
static void expect(const char *name, const char *got, const char *want) {
  bool ok = (got == nullptr && want == nullptr) ||
            (got && want && strcmp(got, want) == 0);
  printf("%s %-46s -> %s\n", ok ? "PASS" : "FAIL", name, got ? got : "accepted");
  if (!ok) failures++;
}

int main() {
  Key token, other;

  { Session s(token); s.tokenSigns(token);
    expect("honest token", s.check(), nullptr); }

  { Session s(token); s.tokenSigns(token); s.r[7] ^= 0x01;
    expect("one wrong fast-phase answer", s.check(), "wrong fast-phase answer"); }

  { // Relay guesses every answer without knowing m.
    Session s(token); s.tokenSigns(token); fill(s.r, sizeof(s.r));
    expect("relay guesses answers", s.check(), "wrong fast-phase answer"); }

  { // Pre-ask: relay sends c'=0 to the token early, so r'=m; answers the
    // station's real c from m. The token signs what it saw (c', r').
    Session s(token);
    uint8_t c0[LPX_ROUNDS] = {0}, r0[LPX_ROUNDS];
    for (int i = 0; i < LPX_ROUNDS; i++) r0[i] = s.m[i];
    s.tokenSigns(token, c0, r0);
    expect("pre-ask attack", s.check(), "bad transcript signature"); }

  { // Claims someone else's public key but can only sign with its own.
    Session s(token); s.tokenSigns(other);
    expect("impersonate another token's key", s.check(), "bad transcript signature"); }

  { // Reveals a different m than committed to.
    Session s(token); s.tokenSigns(token); s.open.m[0] ^= 0x80;
    expect("open with different m", s.check(), "commitment mismatch"); }

  { // Replay a whole recorded opening into a new session (new nonce).
    Session a(token); a.tokenSigns(token);
    Session b(token); b.open = a.open; memcpy(b.hello.commit, a.hello.commit, 32);
    memcpy(b.m, a.m, LPX_ROUNDS);
    for (int i = 0; i < LPX_ROUNDS; i++) b.r[i] = b.c[i] ^ a.m[i];
    expect("replay into new session", b.check(), "commitment mismatch"); }

  { // Signature made for one station, presented to another.
    Session s(token); s.tokenSigns(token); memcpy(s.stationId, "deadbeef", 8);
    expect("signature for another station", s.check(), "bad transcript signature"); }

  { // Garbage public key (not on the curve).
    Session s(token); s.tokenSigns(token); memset(s.hello.tokenPub, 0x11, 64);
    expect("invalid public key", s.check(), "bad transcript signature"); }

  // Print a key and its id so the server's derivation can be cross-checked.
  char id[9];
  lpxKeyId(token.pub, id);
  printf("KEY ");
  for (int i = 0; i < 64; i++) printf("%02x", token.pub[i]);
  printf(" %s\n", id);

  printf("%s\n", failures ? "SOME TESTS FAILED" : "all protocol checks behave as expected");
  return failures ? 1 : 0;
}
