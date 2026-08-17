#include <RTClib.h>
#include <TinyGPS++.h>
#include <SoftwareSerial.h>
#include <GxEPD2_BW.h>
#include <QRCode_Library.h>
#include <Wire.h>
#include <Preferences.h>
#include <Fonts/FreeSansBold9pt7b.h>
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
String baseUrl = "https://map.localproof.org/";
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

unsigned long setupStartTime = millis();
const unsigned long timeoutDuration = 10 * 60 * 1000; // 10 minutes

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

// Sign message with the device's ECDSA P-256 key. Writes raw r||s (64
// bytes) into sig. Returns true on success.
bool signMessage(const uint8_t *msg, size_t msgLen, uint8_t sig[64]) {
  uint8_t hash[32];
#if MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256(msg, msgLen, hash, 0);
#else
  mbedtls_sha256_ret(msg, msgLen, hash, 0);
#endif

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

  // Check the reset reason
  esp_reset_reason_t resetReason = esp_reset_reason();

  // Only set the RTC time from GPS on power-up or software reset
  if (resetReason == ESP_RST_POWERON || resetReason == ESP_RST_SW) {
    displaySettingUpMessage();

    // Wait for GPS to get a fix or timeout
    bool gpsFixAcquired = false;
    bool gpsLocationValid = false;
    while (millis() - setupStartTime < timeoutDuration) {
      // Check for GPS data
      while (gpsSerial.available() > 0) {
        gps.encode(gpsSerial.read());
      }

      // Check if GPS has a valid fix (time and date)
      if (gps.time.isValid() && gps.date.isValid()) {
        gpsFixAcquired = true;

        // Check if GPS has valid location data
        if (gps.location.isValid()) {
          gpsLocationValid = true;
          break; // Exit the loop if GPS fix and location are acquired
        }
      }
    }

    // Check if the GPS fix and location were acquired
    if (gpsFixAcquired && gpsLocationValid) {
      // Set the RTC time from the GPS (GPS time is UTC, which is what the
      // signed timestamps must use)
      rtc.adjust(DateTime(gps.date.year(), gps.date.month(), gps.date.day(),
                 gps.time.hour(), gps.time.minute(), gps.time.second()));
      Serial.println("RTC time set from GPS");

      // Save the location to NVS
      preferences.putFloat("lat", gps.location.lat());
      preferences.putFloat("lng", gps.location.lng());
      Serial.print(gps.location.lat(), 6);
      Serial.print(F(","));
      Serial.println(gps.location.lng(), 6);

      // Turn off the GPS module to save power
      //digitalWrite(GPS_POWER_PIN, LOW);
      Serial.println("GPS module turned off.");
    } else {
      // Timeout or invalid location occurred
      if (!gpsFixAcquired) {
        displayErrorMessage("GPS signal not found.");
      } else {
        displayErrorMessage("GPS location invalid.");
      }
      Serial.println("GPS signal or location not found within timeout.");
    }
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

void displaySettingUpMessage() {
  display.setFullWindow();
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);
    display.setCursor(10, 30);
    display.setTextColor(GxEPD_BLACK);
    display.setFont(&FreeSansBold9pt7b);
    display.println("Searching for GPS signal...");
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
