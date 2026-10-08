// lpx_station.h — station side of the localproof proximity exchange.
//
// Usage (see esp32_code.ino):
//   LpxResult prox;
//   if (lpxBegin()) { lpxRunSession(deviceId, LPX_WINDOW_MS, prox); lpxEnd(); }
//   if (prox.ok) { ...append prox.tokenId and prox.medianRttUs to the payload... }
//
// The station does all the timing itself. Nothing the token reports about
// time is trusted, because in localproof's threat model the token holder
// is the party who might be cheating.

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <esp_timer.h>
#include <esp_idf_version.h>
#include <esp_arduino_version.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include "lpx_protocol.h"

// ---------------------------------------------------------------- tunables

// How long the station advertises per wake-up. The radio draws ~100 mA
// while this runs, so this is the main battery cost of the feature.
#ifndef LPX_WINDOW_MS
#define LPX_WINDOW_MS 3000
#endif

#define LPX_BEACON_EVERY_MS   100
#define LPX_ROUND_TIMEOUT_MS  30    // no answer by then fails the session
#define LPX_ROUND_GAP_MS      2
#define LPX_OPEN_TIMEOUT_MS   1500  // the token's ECDSA signature is slow; untimed

// It must sit above the honest median round trip on your hardware and well
// below what an internet relay adds (typically 10+ ms each way). Measured
// on classic ESP32s (station 6b2831a8, token next to it, 2026-10-08): honest
// medians 2050-2070 us, so 3 ms is the worst honest median plus about 1 ms.
// Recalibrate from the "LPX rtt" serial lines for other hardware.
#ifndef LPX_MAX_MEDIAN_RTT_US
#define LPX_MAX_MEDIAN_RTT_US 3000
#endif

// ------------------------------------------------------------------- types

struct LpxResult {
  bool        ok;            // every check passed
  char        tokenId[9];    // SHA-256(tokenPub)[:4] as hex, valid if a token answered
  uint32_t    medianRttUs;
  uint32_t    maxRttUs;
  const char *reason;        // why it failed, for the serial log
};

struct LpxRx {
  uint8_t mac[6];
  int64_t tUs;               // receive time, taken first thing in the callback
  uint8_t len;
  uint8_t data[128];         // largest inbound message is HELLO (116 bytes)
};

static QueueHandle_t lpxQueue = nullptr;
static const uint8_t LPX_BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ---------------------------------------------------------------- radio io

static void lpxEnqueue(const uint8_t *mac, const uint8_t *data, int len, int64_t t) {
  if (!lpxQueue || len <= 0 || len > (int)sizeof(LpxRx::data)) return;
  LpxRx rx;
  rx.tUs = t;
  memcpy(rx.mac, mac, 6);
  rx.len = (uint8_t)len;
  memcpy(rx.data, data, len);
  xQueueSend(lpxQueue, &rx, 0);  // runs in the Wi-Fi task: never block here
}

#if ESP_IDF_VERSION_MAJOR >= 5
static void lpxOnRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  int64_t t = esp_timer_get_time();
  lpxEnqueue(info->src_addr, data, len, t);
}
#else
static void lpxOnRecv(const uint8_t *mac, const uint8_t *data, int len) {
  int64_t t = esp_timer_get_time();
  lpxEnqueue(mac, data, len, t);
}
#endif

static bool lpxAddPeer(const uint8_t mac[6]) {
  if (esp_now_is_peer_exist(mac)) return true;
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, mac, 6);
  peer.channel = 0;           // 0 = the current channel (LPX_CHANNEL)
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;       // integrity comes from the signed transcript
  return esp_now_add_peer(&peer) == ESP_OK;
}

// Wait for a message of one type, optionally from one MAC. Anything else
// that arrives meanwhile is dropped.
static bool lpxWait(LpxRx &rx, uint32_t timeoutMs, LpxType type, size_t size,
                    const uint8_t *fromMac) {
  int64_t deadline = esp_timer_get_time() + (int64_t)timeoutMs * 1000;
  for (;;) {
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0) return false;
    TickType_t ticks = pdMS_TO_TICKS((left + 999) / 1000);
    if (ticks == 0) ticks = 1;
    if (xQueueReceive(lpxQueue, &rx, ticks) != pdTRUE) return false;
    if (fromMac && memcmp(rx.mac, fromMac, 6) != 0) continue;
    if (!lpxHeaderOk(rx.data, rx.len, type, size)) continue;
    return true;
  }
}

static bool lpxBegin() {
  if (!lpxQueue) lpxQueue = xQueueCreate(8, sizeof(LpxRx));
  if (!lpxQueue) return false;
  xQueueReset(lpxQueue);

  WiFi.mode(WIFI_STA);
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  for (int i = 0; i < 100 && !WiFi.STA.started(); i++) delay(5);
#endif
  esp_wifi_set_ps(WIFI_PS_NONE);  // modem sleep would add latency jitter
  if (esp_wifi_set_channel(LPX_CHANNEL, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
  if (esp_now_init() != ESP_OK) return false;
  esp_now_register_recv_cb(lpxOnRecv);
  return lpxAddPeer(LPX_BROADCAST);
}

static void lpxEnd() {
  esp_now_unregister_recv_cb();
  esp_now_deinit();
  WiFi.mode(WIFI_OFF);
}

// ----------------------------------------------------------------- session

static bool lpxFinish(const uint8_t tokenMac[6], LpxResult &res, bool ok, const char *reason) {
  res.ok = ok;
  res.reason = reason;
  LpxResultMsg msg;
  lpxHeader(msg.h, LPX_RESULT);
  msg.ok = ok;
  msg.medianRttUs = res.medianRttUs;
  esp_now_send(tokenMac, (const uint8_t *)&msg, sizeof(msg));
  delay(5);                    // let the frame leave before the peer goes
  esp_now_del_peer(tokenMac);
  Serial.printf("LPX %s: %s (token %s, median %lu us, max %lu us)\n",
                ok ? "PASS" : "FAIL", reason, res.tokenId,
                (unsigned long)res.medianRttUs, (unsigned long)res.maxRttUs);
  return ok;
}

// Runs one proximity session. Returns true only if a token completed the
// exchange, every answer was correct, its signature verified and the
// median round trip was under LPX_MAX_MEDIAN_RTT_US.
static bool lpxRunSession(const char *stationId, uint32_t windowMs, LpxResult &res) {
  memset(&res, 0, sizeof(res));
  res.reason = "no token in range";

  uint8_t nonce[LPX_NONCE_LEN];
  esp_fill_random(nonce, sizeof(nonce));  // true RNG while the radio is on

  LpxBeacon beacon;
  lpxHeader(beacon.h, LPX_BEACON);
  memcpy(beacon.stationId, stationId, 8);
  memcpy(beacon.nonce, nonce, LPX_NONCE_LEN);

  // 1. Advertise until a token answers with a HELLO for this nonce.
  LpxRx rx;
  LpxHello hello;
  uint8_t tokenMac[6];
  bool gotHello = false;
  uint32_t start = millis();
  uint32_t lastBeacon = start - LPX_BEACON_EVERY_MS;
  while (millis() - start < windowMs) {
    if (millis() - lastBeacon >= LPX_BEACON_EVERY_MS) {
      esp_now_send(LPX_BROADCAST, (const uint8_t *)&beacon, sizeof(beacon));
      lastBeacon = millis();
    }
    if (!lpxWait(rx, 10, LPX_HELLO, sizeof(LpxHello), nullptr)) continue;
    memcpy(&hello, rx.data, sizeof(hello));
    if (memcmp(hello.nonce, nonce, LPX_NONCE_LEN) != 0) continue;  // stale session
    memcpy(tokenMac, rx.mac, 6);
    gotHello = true;
    break;
  }
  if (!gotHello) return false;

  lpxKeyId(hello.tokenPub, res.tokenId);
  if (!lpxAddPeer(tokenMac)) {
    res.reason = "could not add token as peer";
    return false;
  }

  // 2. Fast phase. One challenge in flight at a time; the station times
  //    each round from just before sending to the callback's timestamp.
  uint8_t c[LPX_ROUNDS], r[LPX_ROUNDS];
  uint32_t rtt[LPX_ROUNDS];
  esp_fill_random(c, sizeof(c));

  for (uint8_t i = 0; i < LPX_ROUNDS; i++) {
    LpxChal chal;
    lpxHeader(chal.h, LPX_CHAL);
    chal.round = i;
    chal.c = c[i];

    int64_t t0 = esp_timer_get_time();
    if (esp_now_send(tokenMac, (const uint8_t *)&chal, sizeof(chal)) != ESP_OK)
      return lpxFinish(tokenMac, res, false, "send failed");

    bool got = false;
    int64_t deadline = t0 + (int64_t)LPX_ROUND_TIMEOUT_MS * 1000;
    while (!got) {
      int64_t left = deadline - esp_timer_get_time();
      if (left <= 0) break;
      if (!lpxWait(rx, (uint32_t)((left + 999) / 1000), LPX_RESP, sizeof(LpxResp), tokenMac)) break;
      const LpxResp *resp = (const LpxResp *)rx.data;
      if (resp->round != i) continue;  // late duplicate from an earlier round
      r[i] = resp->r;
      rtt[i] = (uint32_t)(rx.tUs - t0);
      got = true;
    }
    if (!got) return lpxFinish(tokenMac, res, false, "fast-phase round timed out");
    delay(LPX_ROUND_GAP_MS);
  }

  // Median rather than max: MAC-level retransmissions make the odd honest
  // round slow, while a relay slows every round. A relay can't make rounds
  // fast by guessing, since every answer is checked below (1/256 per round).
  uint32_t sorted[LPX_ROUNDS];
  memcpy(sorted, rtt, sizeof(rtt));
  for (int i = 1; i < LPX_ROUNDS; i++) {         // insertion sort, 24 items
    uint32_t v = sorted[i];
    int j = i - 1;
    while (j >= 0 && sorted[j] > v) { sorted[j + 1] = sorted[j]; j--; }
    sorted[j + 1] = v;
  }
  res.medianRttUs = sorted[LPX_ROUNDS / 2];
  res.maxRttUs = sorted[LPX_ROUNDS - 1];

  Serial.print("LPX rtt us:");
  for (int i = 0; i < LPX_ROUNDS; i++) Serial.printf(" %lu", (unsigned long)rtt[i]);
  Serial.println();

  // 3. Opening. Untimed: this is where the token's slow signature happens.
  if (!lpxWait(rx, LPX_OPEN_TIMEOUT_MS, LPX_OPEN, sizeof(LpxOpen), tokenMac))
    return lpxFinish(tokenMac, res, false, "no opening from token");
  LpxOpen open;
  memcpy(&open, rx.data, sizeof(open));

  // 4. Commitment, answers, signature (see lpxCheckOpening), then timing.
  const char *bad = lpxCheckOpening(stationId, nonce, hello, c, r, open);
  if (bad) return lpxFinish(tokenMac, res, false, bad);

  if (res.medianRttUs > LPX_MAX_MEDIAN_RTT_US)
    return lpxFinish(tokenMac, res, false, "too slow, possible relay");

  return lpxFinish(tokenMac, res, true, "token in range");
}
