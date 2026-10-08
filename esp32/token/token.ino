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
// On boot the token prints its id and public key. Register it in the
// Tokens panel of the site, which reads both over USB.
//
// Use: switch it on next to a station. Within one station cycle (30 s) it
// answers the timed challenges, gets the station's signed code (the one
// the QR shows) and uploads it over Wi-Fi, which credits the token's owner
// without anyone scanning. Without a known network in range the code is
// kept in NVS and uploaded the next time the token is on near one. One
// code per power-on: switch it off and on to prove presence again.
//
// The LED (TOKEN_LED) shows where it is:
//   short flash every second   waiting for a station
//   fast blinking              exchanging or uploading
//   steady on                  done, the server recorded it
//   double flash               code stored, no known Wi-Fi in range
//   triple flash               the server refused it (see serial)
//
// Serial commands (115200 baud, one per line; the Tokens panel sends them):
//   status                       print id, key, networks, stored codes
//   wifi-add <ssid-hex> [<pass-hex>]   save a network (UTF-8 as hex) and
//                                try to join it; up to MAX_NETWORKS
//   wifi-clear                   forget all networks
// Networks are kept in NVS in plain text, like the software key.

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <mbedtls/base64.h>
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
#include "letsencrypt_roots.h"

#define TOKEN_SERVER "https://localproof.libmap.org/api/token-proof"

// On-board LED, active high (GPIO 2 on most ESP32 dev boards); -1 for none.
#define TOKEN_LED 2

// I2C pins for the ATECC608B. Change these for your board.
#define TOKEN_SDA 21
#define TOKEN_SCL 22

// A session that stalls (station gone, frames lost) is dropped after this.
#define SESSION_TIMEOUT_MS 2000
// The station signs after the exchange and sends its code shortly after.
#define ATTEST_WINDOW_MS 3000
// With codes stored from earlier and no station seen, upload after one
// station cycle (30 s) plus margin, so a station nearby gets first go.
#define LISTEN_FIRST_MS 35000
#define UPLOAD_RETRY_MS 120000
#define WIFI_CONNECT_MS 10000
#define MAX_NETWORKS 3
#define MAX_STORED 16

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
  bool     opened;               // OPEN sent: the station may send ATTEST
  uint32_t openedMs;
};
static Session s;
static volatile bool gotCode = false;  // one code per power-on

// Signed codes waiting for upload, oldest first. Only loop() touches these.
struct StoredCode {
  char    stationId[8];
  uint8_t len;
  char    payload[LPX_PAYLOAD_MAX];
  uint8_t sig[64];
};
static StoredCode stored[MAX_STORED];
static uint8_t storedCount = 0;

struct SavedNetwork {
  char ssid[33];
  char pass[64];
};
static SavedNetwork nets[MAX_NETWORKS];
static uint8_t netCount = 0;

static QueueHandle_t attestQueue;  // protocol task -> loop()

enum Verdict { ACCEPTED, REFUSED, TRY_LATER };  // the server's answer to an upload

enum LedMode { LED_LISTEN, LED_BUSY, LED_DONE, LED_STORED, LED_REJECTED };
static volatile LedMode ledMode = LED_LISTEN;

struct Rx {
  uint8_t mac[6];
  uint8_t len;
  uint8_t data[160];             // largest inbound message is ATTEST (141 bytes)
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
  if (s.active || gotCode) return;  // one session at a time, one code per power-on
  const LpxBeacon *b = (const LpxBeacon *)rx.data;
  if (memcmp(b->nonce, s.lastNonce, LPX_NONCE_LEN) == 0) return;  // already served
  if (!addPeer(rx.mac)) return;

  memcpy(s.stationMac, rx.mac, 6);
  memcpy(s.stationId, b->stationId, 8);
  memcpy(s.nonce, b->nonce, LPX_NONCE_LEN);
  esp_fill_random(s.m, LPX_ROUNDS);  // fresh secret every session
  lpxCommit(s.nonce, s.m, s.commit);
  s.next = 0;
  s.opened = false;
  s.active = true;
  ledMode = LED_BUSY;
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
      s.opened = true;
      s.openedMs = millis();
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
  if (!res->ok && !gotCode) ledMode = LED_LISTEN;
}

// The station's signed code for the session we just finished. Not checked
// here (the token doesn't know station keys); the server verifies it.
static void onAttest(const Rx &rx) {
  if (!s.opened || memcmp(rx.mac, s.stationMac, 6) != 0) return;
  if (millis() - s.openedMs > ATTEST_WINDOW_MS) return;
  const LpxAttest *a = (const LpxAttest *)rx.data;
  if (a->payloadLen == 0 || a->payloadLen > LPX_PAYLOAD_MAX) return;

  // Keep it only if it names this token ("ts|lat|lng|tokenId|rtt"); a code
  // for any other token can't credit our owner.
  char payload[LPX_PAYLOAD_MAX + 1];
  memcpy(payload, a->payload, a->payloadLen);
  payload[a->payloadLen] = 0;
  const char *p = payload;
  for (int i = 0; i < 3 && p; i++) {
    p = strchr(p, '|');
    if (p) p++;
  }
  if (!p || strncmp(p, tokenId, 8) != 0 || p[8] != '|') return;

  s.opened = false;  // the station sends it a few times; keep the first
  gotCode = true;
  xQueueSend(attestQueue, a, 0);
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
    else if (lpxHeaderOk(rx.data, rx.len, LPX_ATTEST, sizeof(LpxAttest)))   onAttest(rx);
  }
}

// --------------------------------------------------------------- storage

static void saveStored() {
  if (storedCount) prefs.putBytes("codes", stored, storedCount * sizeof(StoredCode));
  else prefs.remove("codes");
}

static void loadStored() {
  size_t n = prefs.getBytesLength("codes");
  if (n == 0 || n % sizeof(StoredCode) != 0 || n > sizeof(stored)) return;
  prefs.getBytes("codes", stored, n);
  storedCount = n / sizeof(StoredCode);
}

static void storeCode(const LpxAttest &a) {
  if (storedCount == MAX_STORED) {  // full: drop the oldest
    memmove(&stored[0], &stored[1], (MAX_STORED - 1) * sizeof(StoredCode));
    storedCount--;
  }
  StoredCode &c = stored[storedCount++];
  memcpy(c.stationId, a.stationId, 8);
  c.len = a.payloadLen;
  memcpy(c.payload, a.payload, LPX_PAYLOAD_MAX);
  memcpy(c.sig, a.sig, 64);
  saveStored();
  Serial.printf("Station %.8s: code stored (%.*s), %u waiting\n",
                c.stationId, c.len, c.payload, storedCount);
}

static void saveNetworks() {
  if (netCount) prefs.putBytes("nets", nets, netCount * sizeof(SavedNetwork));
  else prefs.remove("nets");
}

static void loadNetworks() {
  size_t n = prefs.getBytesLength("nets");
  if (n == 0 || n % sizeof(SavedNetwork) != 0 || n > sizeof(nets)) return;
  prefs.getBytes("nets", nets, n);
  netCount = n / sizeof(SavedNetwork);
}

// ------------------------------------------------------------------ wi-fi

static bool joinNetwork(const SavedNetwork &n) {
  WiFi.begin(n.ssid, n.pass);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < WIFI_CONNECT_MS) delay(100);
  bool ok = WiFi.status() == WL_CONNECTED;
  Serial.printf("Wi-Fi %s: %s\n", n.ssid, ok ? "connected" : "failed");
  if (!ok) WiFi.disconnect();
  return ok;
}

// Joins the strongest saved network in range, trying the others if it fails.
static bool joinKnownNetwork() {
  int rssi[MAX_NETWORKS];
  for (int j = 0; j < netCount; j++) rssi[j] = INT_MIN;
  int found = WiFi.scanNetworks();
  for (int i = 0; i < found; i++) {
    for (int j = 0; j < netCount; j++) {
      if (WiFi.SSID(i) == nets[j].ssid && WiFi.RSSI(i) > rssi[j]) rssi[j] = WiFi.RSSI(i);
    }
  }
  WiFi.scanDelete();
  for (;;) {
    int best = -1;
    for (int j = 0; j < netCount; j++) {
      if (rssi[j] != INT_MIN && (best < 0 || rssi[j] > rssi[best])) best = j;
    }
    if (best < 0) break;
    if (joinNetwork(nets[best])) return true;
    rssi[best] = INT_MIN;
  }
  Serial.println("Wi-Fi: no saved network reachable");
  return false;
}

// Back to listening for stations: joining a network moved the radio to
// the access point's channel.
static void leaveNetwork() {
  WiFi.disconnect();
  delay(50);
  esp_wifi_set_channel(LPX_CHANNEL, WIFI_SECOND_CHAN_NONE);
}

// ----------------------------------------------------------------- upload

static void base64url(const uint8_t *in, size_t len, char *out, size_t outSize) {
  size_t olen = 0;
  if (mbedtls_base64_encode((unsigned char *)out, outSize, &olen, in, len) != 0) olen = 0;
  out[olen] = 0;
  for (size_t i = 0; i < olen; i++) {
    if (out[i] == '+') out[i] = '-';
    else if (out[i] == '/') out[i] = '_';
  }
}

// Posts one code the way the QR would carry it. Any answer from the server
// settles it; only a network or server error keeps it for another try.
static Verdict postCode(WiFiClientSecure &tls, const StoredCode &c) {
  char payloadB64[100], sigB64[100], body[320];
  base64url((const uint8_t *)c.payload, c.len, payloadB64, sizeof(payloadB64));
  base64url(c.sig, 64, sigB64, sizeof(sigB64));
  snprintf(body, sizeof(body), "{\"device_id\":\"%.8s\",\"payload\":\"%s\",\"sig\":\"%s\"}",
           c.stationId, payloadB64, sigB64);

  HTTPClient http;
  if (!http.begin(tls, TOKEN_SERVER)) return TRY_LATER;
  http.addHeader("Content-Type", "application/json");
  int status = http.POST((uint8_t *)body, strlen(body));
  String resp = status > 0 ? http.getString() : http.errorToString(status);
  http.end();
  Serial.printf("Upload %.8s: HTTP %d %s\n", c.stationId, status, resp.c_str());

  if (status == 200) {
    resp.replace(" ", "");
    return resp.indexOf("\"success\":true") >= 0 ? ACCEPTED : REFUSED;
  }
  return status == 400 ? REFUSED : TRY_LATER;
}

static void uploadStored() {
  ledMode = LED_BUSY;
  int accepted = 0, refused = 0;
  if (joinKnownNetwork()) {
    WiFiClientSecure tls;
    tls.setCACert(LETSENCRYPT_ROOTS);
    uint8_t kept = 0;
    for (uint8_t i = 0; i < storedCount; i++) {
      Verdict v = postCode(tls, stored[i]);
      if (v == ACCEPTED) accepted++;
      else if (v == REFUSED) refused++;
      else stored[kept++] = stored[i];
    }
    storedCount = kept;
    saveStored();
  }
  leaveNetwork();

  if (refused) ledMode = LED_REJECTED;
  else if (storedCount) ledMode = LED_STORED;
  else if (accepted) ledMode = LED_DONE;
  else ledMode = LED_LISTEN;
}

// -------------------------------------------------------------------- led

static void ledTask(void *) {
  pinMode(TOKEN_LED, OUTPUT);
  auto flashes = [](int n, int onMs, int periodMs) {
    for (int i = 0; i < n; i++) {
      digitalWrite(TOKEN_LED, HIGH); vTaskDelay(pdMS_TO_TICKS(onMs));
      digitalWrite(TOKEN_LED, LOW);  vTaskDelay(pdMS_TO_TICKS(onMs));
    }
    vTaskDelay(pdMS_TO_TICKS(periodMs - 2 * n * onMs));
  };
  for (;;) {
    switch (ledMode) {
      case LED_LISTEN:   flashes(1, 50, 1000); break;
      case LED_BUSY:     flashes(1, 100, 200); break;
      case LED_DONE:     digitalWrite(TOKEN_LED, HIGH); vTaskDelay(pdMS_TO_TICKS(200)); break;
      case LED_STORED:   flashes(2, 120, 2000); break;
      case LED_REJECTED: flashes(3, 80, 2000); break;
    }
  }
}

// --------------------------------------------------------------- commands

// "48656c6c6f" -> "Hello". Hex keeps spaces and any other bytes in SSIDs
// and passwords out of the command syntax.
static bool hexToStr(const char *hex, char *out, size_t outSize) {
  size_t n = strlen(hex);
  if (n % 2 || n / 2 >= outSize) return false;
  for (size_t i = 0; i < n / 2; i++) {
    unsigned v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) return false;
    out[i] = (char)v;
  }
  out[n / 2] = 0;
  return strlen(out) == n / 2;  // no embedded NULs
}

static void printStatus() {
  Serial.printf("Token ID: %s (%s key)\n", tokenId, useAtecc ? "ATECC608" : "software");
  Serial.print("Pubkey: ");
  for (int i = 0; i < 64; i++) Serial.printf("%02x", tokenPub[i]);
  Serial.println();
  for (int i = 0; i < netCount; i++) Serial.printf("Network: %s\n", nets[i].ssid);
  Serial.printf("Stored codes: %u\n", storedCount);
}

static void runCommand(char *line) {
  char *cmd = strtok(line, " ");
  if (!cmd) return;
  if (strcmp(cmd, "status") == 0) {
    printStatus();
    Serial.println("OK status");
  } else if (strcmp(cmd, "wifi-clear") == 0) {
    netCount = 0;
    saveNetworks();
    Serial.println("OK wifi-clear");
  } else if (strcmp(cmd, "wifi-add") == 0) {
    const char *ssidHex = strtok(NULL, " ");
    const char *passHex = strtok(NULL, " ");
    SavedNetwork n = {};
    if (!ssidHex || !hexToStr(ssidHex, n.ssid, sizeof(n.ssid)) || !n.ssid[0] ||
        (passHex && !hexToStr(passHex, n.pass, sizeof(n.pass)))) {
      Serial.println("ERR wifi-add: bad SSID or password");
      return;
    }
    if (n.pass[0] && strlen(n.pass) < 8) {
      Serial.println("ERR wifi-add: a WPA password has at least 8 characters");
      return;
    }
    int slot = netCount;
    for (int i = 0; i < netCount; i++) if (strcmp(nets[i].ssid, n.ssid) == 0) slot = i;
    if (slot == MAX_NETWORKS) {
      Serial.printf("ERR wifi-add: already %d networks, clear them first\n", MAX_NETWORKS);
      return;
    }
    nets[slot] = n;
    if (slot == netCount) netCount++;
    saveNetworks();
    Serial.printf("OK wifi-add %s\n", n.ssid);
    joinNetwork(n);  // reports "Wi-Fi <ssid>: connected" or "failed"
    leaveNetwork();
  } else {
    Serial.printf("ERR unknown command: %s\n", cmd);
  }
}

static void pollSerial() {
  static char line[200];
  static size_t len = 0;
  while (Serial.available()) {
    char ch = Serial.read();
    if (ch == '\r') continue;
    if (ch == '\n') {
      line[len] = 0;
      len = 0;
      runCommand(line);
    } else if (len < sizeof(line) - 1) {
      line[len++] = ch;
    }
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
  loadNetworks();
  loadStored();
  printStatus();

  rxQueue = xQueueCreate(8, sizeof(Rx));
  attestQueue = xQueueCreate(2, sizeof(LpxAttest));
  if (TOKEN_LED >= 0) xTaskCreate(ledTask, "led", 2048, NULL, 1, NULL);

  WiFi.persistent(false);         // networks live in our own NVS namespace
  WiFi.setAutoReconnect(false);   // leaveNetwork() means it
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
  static uint32_t nextUploadMs = LISTEN_FIRST_MS;

  pollSerial();

  LpxAttest a;
  if (xQueueReceive(attestQueue, &a, 0) == pdTRUE) {
    storeCode(a);
    nextUploadMs = millis();  // upload right away
    ledMode = LED_STORED;
  }

  if (storedCount && netCount && !s.active && (int32_t)(millis() - nextUploadMs) >= 0) {
    uploadStored();
    nextUploadMs = millis() + UPLOAD_RETRY_MS;
  }
  delay(20);
}
