### The Hardware Setup

![Device Setup](pictures/device.jpeg?raw=true)

The first challenge was to ensure the device could keep accurate time without relying on an internet connection. I started with an ESP8266 microcontroller and its built-in Wi-Fi module, but I wanted the device to work completely offline. A friend lent me a GPS module, and I discovered that it could also receive accurate time data from GPS satellites.

The hardware setup:

- **ESP32 Microcontroller**: Upgrade from the ESP8266 because I needed more GPIO pins.
- **NEO-6M GPS Module**: To acquire location and time data.
- **DS3231 Real-Time Clock (RTC) Module**: To maintain accurate time (I2C 0x68).
- **ATECC608B Secure Element**: Holds the device's ECDSA P-256 signing key in slot 0 (I2C 0x60). The key is generated inside the chip and can never be read out, so the device cannot be cloned — not even with full access to the ESP32's flash.
- **Waveshare 1.54" Black/White E-Paper Display**: I chose a black-and-white display over a color one because the refresh rate is much faster (2 seconds vs. 8 seconds).
- **2N2222 NPN Bipolar Transistor**: To switch off the GPS module once it acquires the location and time.
- **Breadboard and Cables**: For prototyping.
- **5.1K Resistor**: For circuit stability.

---

### Operation breakdown

1. **Boot-Up**: On power-up, the device acquires a GPS signal to get the current UTC time and its location. The RTC is synced from GPS and the location is stored in flash (NVS). If no fix arrives within 10 minutes (e.g. indoors), the device falls back to the RTC's battery-backed time.
2. **GPS Shutdown**: Once the GPS module has acquired its data, it's turned off using the 2N2222 transistor.
3. **Signing**: Every 30 seconds, the device builds the message `device_id|timestamp|lat|lng` and signs its SHA-256 digest with ECDSA P-256 — inside the ATECC608 if present (~140ms), otherwise in software via mbedtls.
4. **QR Code Creation**: The validation URL carries the plaintext payload and the signature (base64url): `https://map.localproof.org/v2/<id>/<payload>/<signature>`. Nothing in it is secret — its value is that only this device could have signed it, and only within the last 45 seconds.
5. **Display**: The QR code (version 8, 49×49 modules) is rendered on the e-paper screen.
6. **Deep Sleep**: The device deep-sleeps until the next half-minute mark to save power.

![QR Code Display](pictures/screen.jpeg?raw=true)

I set up a Flask server to verify the QR codes. When a code is scanned, the server returns a JSON response confirming the validity.

At this stage, the device is fully functional. It can generate and display QR codes, and the Flask server can verify them.

![Verification JSON](pictures/verification.jpeg)

---

### Next Steps

1. ~~**Hardware Security Module (HSM)**~~: Done — an ATECC608B now holds the signing key; devices can no longer be duplicated.
2. **Web Implementation**: More user-friendly web interface for device registration (public-key based) and verification.
3. **Battery Module**: Adding a battery will make the device portable.
4. **Casing Design**: Designing a 3D-printed casing.

If you’re interested in following this project, feel free to reach out or leave a comment. I’ll be sharing updates of my progress!

[Project on GitHub](https://github.com/sweing/localproof)


---