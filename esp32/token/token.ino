// token.ino — the verifier's proximity token for localproof.
//
// Carried by the person who wants to prove presence. When a station
// beacons, the token commits to a fresh secret, answers the station's
// timed challenges, then signs the transcript with its own P-256 key.
//
// Key storage:
//  - ATECC608B present and locked (key in slot 0, provisioned like a
//    station): the private key never leaves the chip. Use this for real.
//  - No ATECC: a software key is generated once and kept in NVS. Anyone
//    who dumps the flash can clone the token, so this is for bench
//    testing only.
//
// On boot the token prints its id and public key. Register the key with
// the server the same way as a device (python_generator_v2.py pem <xy-hex>).

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <esp_idf_version.h>
#include <esp_arduino_version.h>
#include <Wire.h>
#include <Preferences.h>
#include <ArduinoECCX08.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include "lpx_protocol.h"

// I2C pins for the ATECC608B. Change these for your board.
#define TOKEN_SDA 21
#define TOKEN_SCL 22

// A session that stalls (station gone, frames lost) is dropped after this.
#define SESSION_TIMEOUT_MS 2000

static bool useAtecc = false;
static uint8_t tokenPub[64];
static char tokenId[9];
static uint8_t swKey[32];       // software fallback only
static Preferences prefs;

// Session state. Only the protocol task touches it.
struct Session {
  bool     active;
  uint32_t startedMs;
  uint8_t  stationMac[6];
  char     stationId[8];
  uint8_t  nonce[LPX_NONCE_LEN];
  uint8_t  m[LPX_ROUNDS];
  uint8_t  commit[32];
  uint8_t  c[LPX_ROUNDS];
  uint8_t  r[LPX_ROUNDS];
  uint8_t  next;                 // the only round index we will accept next
  uint8_t  lastNonce[LPX_NONCE_LEN];  // never serve the same session twice
};
static Session s;

struct Rx {
  uint8_t mac[6];
  uint8_t len;
  uint8_t data[48];              // largest inbound message is BEACON (28 bytes)
};
static QueueHandle_t rxQueue;

static int lpxRng(void *, unsigned char *buf, size_t len) {
  esp_fill_random(buf, len);
  return 0;
}

// ------------------------------------------------------------------- keys

static bool softwareKeyInit() {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) {
    if (prefs.getBytes("swkey", swKey, sizeof(swKey)) == sizeof(swKey)) {
      ret = mbedtls_mpi_read_binary(&d, swKey, sizeof(swKey));
      if (ret == 0) ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, lpxRng, NULL);
    } else {
      ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, lpxRng, NULL);
      if (ret == 0) ret = mbedtls_mpi_write_binary(&d, swKey, sizeof(swKey));
      if (ret == 0) prefs.putBytes("swkey", swKey, sizeof(swKey));
    }
  }
  uint8_t uncompressed[65];
  size_t olen = 0;
  if (ret == 0) ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                     &olen, uncompressed, sizeof(uncompressed));
  if (ret == 0 && olen == 65) memcpy(tokenPub, uncompressed + 1, 64);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ret == 0 && olen == 65;
}

static bool softwareSign(const uint8_t hash[32], uint8_t sig[64]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, sv;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&sv);
  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret == 0) ret = mbedtls_mpi_read_binary(&d, swKey, sizeof(swKey));
  if (ret == 0) ret = mbedtls_ecdsa_sign(&grp, &r, &sv, &d, hash, 32, lpxRng, NULL);
  if (ret == 0) ret = mbedtls_mpi_write_binary(&r, sig, 32);
  if (ret == 0) ret = mbedtls_mpi_write_binary(&sv, sig + 32, 32);
  mbedtls_mpi_free(&sv);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ret == 0;
}

static bool signHash(const uint8_t hash[32], uint8_t sig[64]) {
  if (useAtecc) return ECCX08.ecSign(0, hash, sig);  // raw r||s
  return softwareSign(hash, sig);
}

// ------------------------------------------------------------------ radio

static void enqueue(const uint8_t *mac, const uint8_t *data, int len) {
  if (len <= 0 || len > (int)sizeof(Rx::data)) return;
  Rx rx;
  memcpy(rx.mac, mac, 6);
  rx.len = (uint8_t)len;
  memcpy(rx.data, data, len);
  xQueueSend(rxQueue, &rx, 0);  // Wi-Fi task: never block here
}

#if ESP_IDF_VERSION_MAJOR >= 5
static void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  enqueue(info->src_addr, data, len);
}
#else
static void onRecv(const uint8_t *mac, const uint8_t *data, int len) {
  enqueue(mac, data, len);
}
#endif

static bool addPeer(const uint8_t mac[6]) {
  if (esp_now_is_peer_exist(mac)) return true;
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, mac, 6);
  peer.channel = 0;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;
  return esp_now_add_peer(&peer) == ESP_OK;
}

static void sendResp(uint8_t round) {
  LpxResp resp;
  lpxHeader(resp.h, LPX_RESP);
  resp.round = round;
  resp.r = s.r[round];
  esp_now_send(s.stationMac, (const uint8_t *)&resp, sizeof(resp));
}

// --------------------------------------------------------------- protocol

static void endSession() {
  memcpy(s.lastNonce, s.nonce, LPX_NONCE_LEN);
  s.active = false;
}

static void onBeacon(const Rx &rx) {
  if (s.active) return;  // one session at a time
  const LpxBeacon *b = (const LpxBeacon *)rx.data;
  if (memcmp(b->nonce, s.lastNonce, LPX_NONCE_LEN) == 0) return;  // already served
  if (!addPeer(rx.mac)) return;

  memcpy(s.stationMac, rx.mac, 6);
  memcpy(s.stationId, b->stationId, 8);
  memcpy(s.nonce, b->nonce, LPX_NONCE_LEN);
  esp_fill_random(s.m, LPX_ROUNDS);  // fresh secret every session
  lpxCommit(s.nonce, s.m, s.commit);
  s.next = 0;
  s.active = true;
  s.startedMs = millis();

  LpxHello hello;
  lpxHeader(hello.h, LPX_HELLO);
  memcpy(hello.nonce, s.nonce, LPX_NONCE_LEN);
  memcpy(hello.tokenPub, tokenPub, 64);
  memcpy(hello.commit, s.commit, 32);
  esp_now_send(s.stationMac, (const uint8_t *)&hello, sizeof(hello));
  Serial.printf("Station %.8s: session started\n", s.stationId);
}

static void onChallenge(const Rx &rx) {
  if (!s.active || memcmp(rx.mac, s.stationMac, 6) != 0) return;
  const LpxChal *ch = (const LpxChal *)rx.data;

  if (ch->round == s.next && s.next < LPX_ROUNDS) {
    // The hot path: one XOR and out. Nothing slow before the send.
    s.c[s.next] = ch->c;
    s.r[s.next] = ch->c ^ s.m[s.next];
    sendResp(s.next);
    s.next++;
  } else if (s.next > 0 && ch->round == s.next - 1 && ch->c == s.c[s.next - 1]) {
    sendResp(s.next - 1);  // retransmitted challenge: same question, same answer
    return;
  } else {
    // Out of order, or a different question for a round already answered.
    // That is what a pre-ask attack looks like, so refuse to continue.
    Serial.println("Unexpected challenge, aborting session");
    endSession();
    return;
  }

  if (s.next == LPX_ROUNDS) {
    // Untimed from here on: sign the transcript exactly as we saw it.
    LpxOpen open;
    lpxHeader(open.h, LPX_OPEN);
    memcpy(open.m, s.m, LPX_ROUNDS);
    uint8_t th[32];
    lpxTranscriptHash(s.stationId, s.nonce, tokenPub, s.commit, s.c, s.r, th);
    if (signHash(th, open.sig)) {
      esp_now_send(s.stationMac, (const uint8_t *)&open, sizeof(open));
    } else {
      Serial.println("Signing failed");
    }
    endSession();
  }
}

// Not authenticated: a nearby device could spoof this. Use it for the
// token's UI only — the server trusts the station's signed QR, not this.
static void onResult(const Rx &rx) {
  if (memcmp(rx.mac, s.stationMac, 6) != 0) return;
  const LpxResultMsg *res = (const LpxResultMsg *)rx.data;
  Serial.printf("Station %.8s says: %s (median %lu us)\n", s.stationId,
                res->ok ? "PASS" : "FAIL", (unsigned long)res->medianRttUs);
  // Drive a display or LED here.
}

static void protocolTask(void *) {
  Rx rx;
  for (;;) {
    if (xQueueReceive(rxQueue, &rx, pdMS_TO_TICKS(100)) != pdTRUE) {
      if (s.active && millis() - s.startedMs > SESSION_TIMEOUT_MS) endSession();
      continue;
    }
    if (lpxHeaderOk(rx.data, rx.len, LPX_CHAL, sizeof(LpxChal)))           onChallenge(rx);
    else if (lpxHeaderOk(rx.data, rx.len, LPX_BEACON, sizeof(LpxBeacon)))  onBeacon(rx);
    else if (lpxHeaderOk(rx.data, rx.len, LPX_RESULT, sizeof(LpxResultMsg))) onResult(rx);
  }
}

// ------------------------------------------------------------------ setup

void setup() {
  Serial.begin(115200);
  delay(200);
  prefs.begin("lpxtoken", false);

  Wire.begin(TOKEN_SDA, TOKEN_SCL);
  useAtecc = ECCX08.begin() && ECCX08.locked() && ECCX08.generatePublicKey(0, tokenPub);
  if (!useAtecc) {
    Serial.println("WARNING: no locked ATECC608 found, using a software key from NVS.");
    Serial.println("         Fine for bench tests; it can be cloned from flash.");
    if (!softwareKeyInit()) {
      Serial.println("Software key setup failed");
      while (1) delay(1000);
    }
  }

  lpxKeyId(tokenPub, tokenId);
  Serial.printf("Token ID: %s (%s key)\n", tokenId, useAtecc ? "ATECC608" : "software");
  Serial.print("Pubkey: ");
  for (int i = 0; i < 64; i++) Serial.printf("%02x", tokenPub[i]);
  Serial.println();

  rxQueue = xQueueCreate(8, sizeof(Rx));

  WiFi.mode(WIFI_STA);
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  for (int i = 0; i < 100 && !WiFi.STA.started(); i++) delay(5);
#endif
  esp_wifi_set_ps(WIFI_PS_NONE);  // modem sleep would add latency to every answer
  esp_wifi_set_channel(LPX_CHANNEL, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    while (1) delay(1000);
  }
  esp_now_register_recv_cb(onRecv);

  // High priority so a challenge is answered as soon as it is queued.
  xTaskCreate(protocolTask, "lpx", 6144, NULL, 20, NULL);
  Serial.println("Waiting for a station...");
}

void loop() {
  vTaskDelay(portMAX_DELAY);  // all work happens in protocolTask
}
