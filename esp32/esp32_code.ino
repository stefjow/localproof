#include <RTClib.h>
#include <TinyGPS++.h>
#include <SoftwareSerial.h>
#include <GxEPD2_BW.h>
#include "qrcodegen.h"  // vendored QR generator (ricmoo/QRCode, MIT)
#include <Wire.h>
#include <Preferences.h>
#include <Fonts/FreeSansBold9pt7b.h>
#include <ArduinoECCX08.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/version.h>
#include <string.h>

// Device identity: copy secrets.h.example to secrets.h and fill in the
// values from `python python_generator_v2.py keygen` / `secrets`.
#include "secrets.h"

// SETUP
//String baseUrl = "http://localhost:5005/"; // Dynamic base URL
String baseUrl = "https://localproof.libmap.org/";
const char *deviceId = DEVICE_ID;

Preferences preferences;

// Create an instance of the DS3231 RTC
RTC_DS3231 rtc;

// Create an instance of the TinyGPS++ object
TinyGPSPlus gps;

// Define the serial connection for the GPS module
SoftwareSerial gpsSerial(16, 17); // TX, RX

// Define the GPIO pin to control GPS power
#define GPS_POWER_PIN 4 // Change this to the GPIO pin you're using

#define CS_PIN    26
#define DC_PIN    25
#define RST_PIN   33 //ACHTUNG FALSCH BESCHRIFTET!!
#define BUSY_PIN  27

// Define the display type (1.54" b/w)
GxEPD2_BW<GxEPD2_154_D67, GxEPD2_154_D67::HEIGHT> display(GxEPD2_154_D67(/*CS=*/ CS_PIN, /*DC=*/ DC_PIN, /*RST=*/ RST_PIN, /*BUSY=*/ BUSY_PIN));

// The signed URL is ~170 chars; QR version 8 (49x49 modules, binary
// capacity 194 bytes at ECC L) fits it on the 200x200 display at
// 4px per module.
#define QR_VERSION 8

void drawQRCode(const char *text);
void displaySettingUpMessage();
void displayErrorMessage(const char *text);

// ATECC608 secure element (I2C 0x60). When present and locked, slot 0
// signs and the private key never exists outside the chip. Without it,
// signing falls back to the software key in secrets.h.
bool useAtecc = false;

// mbedtls RNG callback backed by the ESP32 hardware RNG
static int espRng(void *ctx, unsigned char *buf, size_t len) {
  esp_fill_random(buf, len);
  return 0;
}

// Convert a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs) to
// raw r||s, 32 bytes each, big-endian, zero-padded on the left. This is
// the format the server (pycryptodome, fips-186-3 mode) expects.
bool derToRawSignature(const uint8_t *der, size_t derLen, uint8_t raw[64]) {
  memset(raw, 0, 64);
  if (derLen < 8 || der[0] != 0x30) return false;
  size_t pos = 2;                           // skip SEQUENCE header (short form)
  if (der[1] & 0x80) pos += der[1] & 0x7F;  // skip long-form length bytes
  for (int part = 0; part < 2; part++) {
    if (pos + 2 > derLen || der[pos] != 0x02) return false;
    size_t len = der[pos + 1];
    pos += 2;
    if (pos + len > derLen) return false;
    // strip leading zero-padding, then right-align into 32 bytes
    while (len > 32 && der[pos] == 0x00) { pos++; len--; }
    if (len > 32) return false;
    memcpy(raw + part * 32 + (32 - len), der + pos, len);
    pos += len;
  }
  return true;
}

// Sign message with the device's ECDSA P-256 key — in the ATECC608 if
// present, else in software with the key from secrets.h. Writes raw
// r||s (64 bytes) into sig. Returns true on success.
bool signMessage(const uint8_t *msg, size_t msgLen, uint8_t sig[64]) {
  uint8_t hash[32];
#if MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256(msg, msgLen, hash, 0);
#else
  mbedtls_sha256_ret(msg, msgLen, hash, 0);
#endif

  if (useAtecc) {
    // ecSign returns raw r||s directly
    if (ECCX08.ecSign(0, hash, sig)) return true;
    Serial.println("ATECC signing failed");
    return false;
  }

#ifndef DEVICE_PRIVATE_KEY_PEM
  Serial.println("No ATECC and no software key configured");
  return false;
#else
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
#if MBEDTLS_VERSION_MAJOR >= 3
  int ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)DEVICE_PRIVATE_KEY_PEM,
                                 strlen(DEVICE_PRIVATE_KEY_PEM) + 1, NULL, 0, espRng, NULL);
#else
  int ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)DEVICE_PRIVATE_KEY_PEM,
                                 strlen(DEVICE_PRIVATE_KEY_PEM) + 1, NULL, 0);
#endif
  if (ret != 0) {
    Serial.printf("Key parse failed: -0x%04X\n", -ret);
    mbedtls_pk_free(&pk);
    return false;
  }

  uint8_t der[MBEDTLS_ECDSA_MAX_LEN];
  size_t derLen = 0;
#if MBEDTLS_VERSION_MAJOR >= 3
  ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                        der, sizeof(der), &derLen, espRng, NULL);
#else
  ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                        der, &derLen, espRng, NULL);
#endif
  mbedtls_pk_free(&pk);
  if (ret != 0) {
    Serial.printf("Signing failed: -0x%04X\n", -ret);
    return false;
  }

  return derToRawSignature(der, derLen, sig);
#endif // DEVICE_PRIVATE_KEY_PEM
}

// URL-safe base64 (padding kept, as the server's urlsafe_b64decode expects)
bool base64url(const uint8_t *data, size_t dataLen, char *out, size_t outSize) {
  size_t b64Len = 0;
  if (mbedtls_base64_encode((unsigned char *)out, outSize, &b64Len, data, dataLen) != 0)
    return false;
  for (size_t i = 0; i < b64Len; i++) {
    if (out[i] == '+') out[i] = '-';
    if (out[i] == '/') out[i] = '_';
  }
  out[b64Len] = '\0';
  return true;
}

void setup() {
  Serial.begin(115200);

  // Initialize the GPS power control pin
  //pinMode(GPS_POWER_PIN, OUTPUT);
  //digitalWrite(GPS_POWER_PIN, HIGH); // Turn on the GPS module

  // Initialize preferences (stores the GPS fix across deep sleep)
  preferences.begin("localproof", false);

  gpsSerial.begin(9600); // Start the GPS serial connection
  SPI.begin(18, -1, 23, -1);  // SCK=18, MISO not used (-1), MOSI=23, CS=-1
  display.init(115200, false, 10, false); // Initialize the e-ink display
  // Initialize the RTC
  if (!rtc.begin()) {
    Serial.println("Couldn't find RTC");
    displayErrorMessage("RTC not found. Halting.");
    while (1); // Halt if RTC is not found
  }

  // Detect the ATECC608 secure element (must be locked with a key in
  // slot 0; see esp32/README.md)
  useAtecc = ECCX08.begin() && ECCX08.locked();
  Serial.println(useAtecc ? "Signer: ATECC608 slot 0"
                          : "Signer: software key (no ATECC found)");

  // Check the reset reason
  esp_reset_reason_t resetReason = esp_reset_reason();

  // On power-up or software reset, block until the GPS delivers a real
  // time AND location fix: no QR codes are generated before the device
  // knows where and when it is. A cold start can take a long time, so
  // there is deliberately no timeout. Deep-sleep wakes skip this — the
  // fix is stored in NVS and reused for the rest of the power cycle.
  if (resetReason == ESP_RST_POWERON || resetReason == ESP_RST_SW) {
    preferences.putBool("synced", false);

    Serial.println("Waiting for GPS fix (no QR codes until then)...");
    displaySettingUpMessage();

    unsigned long lastReport = 0;
    // isValid() only means a field was parsed — before a real fix the
    // module reports a dummy date (GPS epoch), so require a plausible
    // year and a fresh location.
    while (!(gps.location.isValid() && gps.location.age() < 1500 &&
             gps.time.isValid() && gps.date.isValid() && gps.date.year() >= 2025)) {
      while (gpsSerial.available() > 0) {
        gps.encode(gpsSerial.read());
      }
      if (millis() - lastReport >= 10000) {
        lastReport = millis();
        Serial.print("GPS: chars=");
        Serial.print(gps.charsProcessed());
        Serial.print(" sats=");
        Serial.print(gps.satellites.isValid() ? gps.satellites.value() : 0);
        Serial.print(" hdop=");
        Serial.println(gps.hdop.isValid() ? gps.hdop.hdop() : 99.9);
        if (gps.charsProcessed() < 10) {
          Serial.println("WARNING: no NMEA data from GPS module - check wiring/power");
        }
      }
    }

    rtc.adjust(DateTime(gps.date.year(), gps.date.month(), gps.date.day(),
               gps.time.hour(), gps.time.minute(), gps.time.second()));
    preferences.putFloat("lat", gps.location.lat());
    preferences.putFloat("lng", gps.location.lng());
    preferences.putBool("synced", true);
    Serial.print("GPS location acquired: ");
    Serial.print(gps.location.lat(), 6);
    Serial.print(F(","));
    Serial.println(gps.location.lng(), 6);
    Serial.println("RTC time set from GPS");

    // GPS is no longer needed this power cycle (it could now be powered
    // off via the 2N2222 on GPS_POWER_PIN).
    //digitalWrite(GPS_POWER_PIN, LOW);
  }

  // Hibernate the display to save power
  display.hibernate();
}

void loop() {
  // Get the current time from the RTC
  DateTime currentTime = rtc.now();

  // Check if the RTC time is valid
  if (!currentTime.isValid()) {
    Serial.println("RTC time is invalid!");
    return;
  }

  // Retrieve latitude and longitude from NVS
  float lat = preferences.getFloat("lat", 0.0); // Default to 0.0 if not found
  float lng = preferences.getFloat("lng", 0.0); // Default to 0.0 if not found

  // 1. Build the payload and the signed message. The payload string is
  //    signed exactly as transmitted, prefixed with the device id so a
  //    signature cannot be transplanted onto another device.
  uint32_t ts = currentTime.unixtime();
  char payload[64];
  snprintf(payload, sizeof(payload), "%lu|%.6f|%.6f", (unsigned long)ts, lat, lng);
  char message[96];
  snprintf(message, sizeof(message), "%s|%s", deviceId, payload);
  Serial.println(message);

  // 2. Sign with the device's private key
  uint8_t sig[64];
  if (!signMessage((const uint8_t *)message, strlen(message), sig)) {
    displayErrorMessage("Signing failed.");
    while (1);
  }

  // 3. Base64url-encode payload and signature
  char payloadB64[96];
  char sigB64[96];
  if (!base64url((const uint8_t *)payload, strlen(payload), payloadB64, sizeof(payloadB64)) ||
      !base64url(sig, sizeof(sig), sigB64, sizeof(sigB64))) {
    displayErrorMessage("Encoding failed.");
    while (1);
  }

  // 4. Build the URL
  String url = baseUrl + "v2/" + String(deviceId) + "/" + String(payloadB64) + "/" + String(sigB64);
  Serial.println("Generated URL: " + url);

  // Convert the URL to a char array for the QR code library
  char urlBuffer[224];
  url.toCharArray(urlBuffer, sizeof(urlBuffer));

  // Draw the QR code on the display
  drawQRCode(urlBuffer);

  // Put the display into low-power mode
  display.hibernate();

  // Sleep until just after the next 30-second mark
  currentTime = rtc.now();
  int currentSecond = currentTime.second();
  int sleepSeconds = (30 - (currentSecond % 30)) % 30;

  // Edge case
  if (sleepSeconds == 0) {
    sleepSeconds = 30;
  }

  // Add 1 additional second to avoid loop running more than once
  sleepSeconds = sleepSeconds + 1;

  Serial.println("Entering deep sleep... for " + String(sleepSeconds) + " seconds.");
  esp_deep_sleep(sleepSeconds * 1000000ULL);
}

void drawQRCode(const char *text)
{
  // Create the QR code
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(QR_VERSION)];
  qrcode_initText(&qrcode, qrcodeData, QR_VERSION, 0, text);

  // Calculate the size of each QR code module (pixel) to fill the screen
  uint16_t screenWidth = display.width();
  uint16_t screenHeight = display.height();
  uint16_t qrSize = qrcode.size;
  uint16_t moduleSize = min(screenWidth, screenHeight) / qrSize;

  // Center the QR code on the screen
  uint16_t xOffset = (screenWidth - (qrSize * moduleSize)) / 2;
  uint16_t yOffset = (screenHeight - (qrSize * moduleSize)) / 2;

  // Draw the QR code
  display.setFullWindow();
  display.firstPage();
  do
  {
    display.fillScreen(GxEPD_WHITE);
    for (uint8_t y = 0; y < qrSize; y++)
    {
      for (uint8_t x = 0; x < qrSize; x++)
      {
        if (qrcode_getModule(&qrcode, x, y))
        {
          display.fillRect(xOffset + x * moduleSize, yOffset + y * moduleSize, moduleSize, moduleSize, GxEPD_BLACK);
        }
      }
    }
  }
  while (display.nextPage());
}

// Print text horizontally centered with its baseline/top at y
void drawCenteredText(const char *text, int16_t y) {
  int16_t bx, by;
  uint16_t bw, bh;
  display.getTextBounds(text, 0, y, &bx, &by, &bw, &bh);
  display.setCursor((display.width() - bw) / 2 - bx, y);
  display.print(text);
}

// 1px-wide circle drawn as alternating arcs (onDeg on, offDeg off)
void drawDashedCircle(int16_t cx, int16_t cy, int16_t r, uint8_t onDeg, uint8_t offDeg) {
  for (int deg = 0; deg < 360; deg++) {
    if (deg % (onDeg + offDeg) < onDeg) {
      float rad = deg * 0.0174533f;
      display.drawPixel(cx + (int16_t)roundf(r * cosf(rad)),
                        cy + (int16_t)roundf(r * sinf(rad)), GxEPD_BLACK);
    }
  }
}

void displaySettingUpMessage() {
  display.setFullWindow();
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);

    // Radar motif: solid center fading into dashed outer rings
    const int16_t cx = 100, cy = 80;
    display.fillCircle(cx, cy, 4, GxEPD_BLACK);
    display.drawCircle(cx, cy, 16, GxEPD_BLACK);
    display.drawCircle(cx, cy, 17, GxEPD_BLACK);
    drawDashedCircle(cx, cy, 31, 8, 7);
    drawDashedCircle(cx, cy, 45, 5, 10);

    // Crosshair ticks just outside the outer ring
    display.drawFastHLine(cx - 58, cy, 10, GxEPD_BLACK);
    display.drawFastHLine(cx + 49, cy, 10, GxEPD_BLACK);
    display.drawFastVLine(cx, cy - 58, 10, GxEPD_BLACK);
    display.drawFastVLine(cx, cy + 49, 10, GxEPD_BLACK);

    display.setTextColor(GxEPD_BLACK);
    display.setFont(&FreeSansBold9pt7b);
    drawCenteredText("Searching for GPS", 168);

    char sub[32];
    snprintf(sub, sizeof(sub), "localproof  -  %s", deviceId);
    display.setFont(NULL);  // built-in 6x8 font
    drawCenteredText(sub, 184);
  } while (display.nextPage());
}

void displayErrorMessage(const char *text) {
  display.setFullWindow();
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);
    display.setCursor(10, 30);
    display.setTextColor(GxEPD_BLACK);
    display.setFont(&FreeSansBold9pt7b);
    display.println(text);
  } while (display.nextPage());
}
