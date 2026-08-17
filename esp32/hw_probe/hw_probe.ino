// Utility sketch: I2C bus scan, ATECC608 detection/status, and RTC
// sync over serial. Not part of the product firmware.
//
// Serial commands (115200):
//   SETTIME <unix epoch>   set the DS3231 (UTC)
//   STATUS                 print current RTC epoch

#include <Wire.h>
#include <RTClib.h>
#include <ArduinoECCX08.h>

RTC_DS3231 rtc;
bool rtcOk = false;
bool eccOk = false;

int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

void printHex(const byte *buf, int len) {
  for (int i = 0; i < len; i++) {
    if (buf[i] < 16) Serial.print('0');
    Serial.print(buf[i], HEX);
  }
  Serial.println();
}

void probeEccAt(uint8_t addr) {
  ECCX08Class ecc(Wire, addr);
  if (!ecc.begin()) return;
  Serial.print("ATECC found at 0x");
  Serial.println(addr, HEX);
  Serial.print("  serial number: ");
  Serial.println(ecc.serialNumber());
  Serial.print("  locked: ");
  Serial.println(ecc.locked() ? "yes" : "no");
  if (ecc.locked()) {
    byte pub[64];
    if (ecc.generatePublicKey(0, pub)) {
      Serial.print("  slot0 public key (X||Y hex): ");
      printHex(pub, 64);
    } else {
      Serial.println("  slot0 public key: not readable (no key or slot config)");
    }
    byte rnd[32];
    if (ecc.random(rnd, sizeof(rnd))) {
      Serial.print("  TRNG sample: ");
      printHex(rnd, 8);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Wire.begin();

  Serial.println("=== HW PROBE ===");

  // Scan with a preceding ATECC wake pulse: the chip sleeps and only ACKs
  // its address while awake (watchdog keeps it up ~1.3s after wake).
  // Wake condition = SDA held low >60us: a write to address 0x00 at 100kHz.
  Serial.println("I2C scan (with ATECC wake, 3 rounds):");
  Wire.setClock(100000);
  for (int round = 0; round < 3; round++) {
    Wire.beginTransmission(0x00);   // wake pulse
    Wire.endTransmission();
    delayMicroseconds(1500);        // tWHI: chip needs 1.5ms after wake
    Serial.print("  round ");
    Serial.print(round);
    Serial.print(":");
    for (uint8_t addr = 1; addr < 127; addr++) {
      Wire.beginTransmission(addr);
      if (Wire.endTransmission() == 0) {
        Serial.print(" 0x");
        Serial.print(addr, HEX);
      }
    }
    Serial.println();
    delay(100);
  }

  // RTC
  rtcOk = rtc.begin();
  if (rtcOk) {
    Serial.print("RTC epoch: ");
    Serial.println(rtc.now().unixtime());
  } else {
    Serial.println("RTC not found!");
  }

  // ATECC at known addresses (0x60 default, 0x35, 0x6A Trust&Go, 0x6C TrustFLEX)
  probeEccAt(0x60);
  probeEccAt(0x35);
  probeEccAt(0x6A);
  probeEccAt(0x6C);

  eccOk = ECCX08.begin();   // default instance, Wire @ 0x60

  Serial.println("=== READY (SETTIME <epoch> | STATUS | SIGN <sha256 hex>) ===");
}

void loop() {
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.startsWith("SETTIME ")) {
    uint32_t epoch = strtoul(line.c_str() + 8, NULL, 10);
    if (epoch > 1700000000UL && rtcOk) {
      rtc.adjust(DateTime(epoch));
      Serial.print("RTC set to ");
      Serial.println(rtc.now().unixtime());
    } else {
      Serial.println("SETTIME rejected");
    }
  } else if (line == "STATUS") {
    Serial.print("RTC epoch: ");
    Serial.println(rtcOk ? rtc.now().unixtime() : 0);
  } else if (line.startsWith("SIGN ")) {
    // sign a 32-byte SHA-256 digest (64 hex chars) with slot 0
    if (!eccOk) { Serial.println("SIGN failed: no ATECC"); return; }
    const char *hex = line.c_str() + 5;
    byte digest[32];
    bool ok = strlen(hex) >= 64;
    for (int i = 0; ok && i < 32; i++) {
      int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
      if (hi < 0 || lo < 0) ok = false; else digest[i] = (hi << 4) | lo;
    }
    byte sig[64];
    unsigned long t0 = micros();
    if (ok && ECCX08.ecSign(0, digest, sig)) {
      unsigned long dt = micros() - t0;
      Serial.print("SIG ");
      printHex(sig, 64);
      Serial.print("sign time: ");
      Serial.print(dt / 1000.0, 1);
      Serial.println(" ms");
    } else {
      Serial.println("SIGN failed");
    }
  }
}
