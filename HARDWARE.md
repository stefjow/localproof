# Hardware

![Device](pictures/device.jpeg)

The device is designed to work fully offline: it derives time and location from GPS satellites and signs its own presence claims on-chip, so no network or trusted server is involved during operation.

## Components

- **ESP32 microcontroller** — drives the display, GPS, RTC and secure element.
- **NEO-6M GPS module** — location and UTC time from GPS satellites.
- **DS3231 RTC** (I2C 0x68) — keeps time between the initial GPS fix and the next power cycle.
- **ATECC608B secure element** (I2C 0x60) — holds the ECDSA P-256 private key in slot 0. The key is generated inside the chip and cannot be read out.
- **Waveshare 1.54" black/white e-paper** — ~2 s refresh (colour equivalents are ~8 s), zero power to hold an image.
- **2N2222 NPN transistor** — wired to switch the GPS module off from a GPIO pin. Not yet driven by firmware; scheduled with the battery module.
- Breadboard, 5.1 kΩ pull-up, jumper wires.

## Operation

1. **Boot.** The device waits for a full GPS time and location fix before doing anything else. The display shows a "Searching for GPS" screen and the serial port prints satellite diagnostics (`chars`, `sats`, `hdop`, `inview`, `snr`) every 10 seconds. There is no timeout — a cold start can take a long time on a poor sky view. Once fixed, the RTC is set and the location is written to NVS; deep-sleep wakes within the same power cycle reuse the stored fix.
2. **Signing.** Every 30 seconds the device builds `device_id|timestamp|lat|lng`, takes its SHA-256 digest, and signs the digest with ECDSA P-256 — inside the ATECC608 (~140 ms) if present, otherwise in software via mbedtls as a fallback.
3. **QR.** Payload and signature are base64url-encoded into a URL of the form `https://localproof.libmap.org/v2/<id>/<payload>/<sig>` and rendered as a version-8 QR (49×49 modules). Nothing in the URL is secret; the value is that only this device could have signed it, and only within the last 45 seconds.
4. **Sleep.** The ESP32 deep-sleeps until the next 30 s boundary. The DS3231 keeps time across sleep.

![QR on display](pictures/screen.jpeg)

The server verifies the signature and freshness, then challenges the scanning browser to answer a fresh nonce together with its own geolocation. See the [main README](README.md#how-verification-works) for the full flow.

![Verification response](pictures/verification.jpeg)

## Open items

- **Battery module.** Enable duty-cycled operation: sleep the ESP32 between QR refreshes and only power the GPS when a new fix is needed.
- **Casing.** 3D-printed enclosure.
