# ESP32 Code and Simulators

This directory contains the code for ESP32 devices and Python-based simulators to test the system.

---

## Files

- **`esp32_code.ino`**: Main ESP32 code. Signs `device_id|ts|lat|lng` with ECDSA P-256 — in the ATECC608 secure element when present (I2C 0x60, locked, key in slot 0), otherwise in software (mbedtls) — and displays the resulting `/v2/...` URL as a QR code.
- **`hw_probe/`**: Diagnostic sketch — I2C wake-scan, ATECC status and public-key readout, RTC sync over serial (`SETTIME <epoch>`), and test signing (`SIGN <sha256 hex>`).
- **`secrets.h.example`**: Template for the device identity (`secrets.h` is gitignored).
- **`python_generator_v2.py`**: Simulates the device — key generation, signed QR codes, and ATECC public-key conversion (`pem` command).

---

## Provisioning a device

### With an ATECC608 secure element (recommended)

1. Flash `hw_probe/hw_probe.ino` and open the serial monitor (115200). It
   prints the chip's lock status and its slot-0 public key as X||Y hex.
2. Convert the public key to PEM and register it on the server:
   ```bash
   python python_generator_v2.py pem <xy-hex>
   ```
3. Create `secrets.h` with just the device id (the software key block can
   be omitted): copy `secrets.h.example` and set `DEVICE_ID`.
4. Flash `esp32_code.ino`. The firmware detects the chip automatically
   (serial prints `Signer: ATECC608 slot 0`).

### Without a secure element (software key)

1. Generate a keypair (once per device):
   ```bash
   python python_generator_v2.py keygen
   ```
   The private key is written to `keys/<device_id>_private.pem` (gitignored);
   the public key PEM is printed — register it on the server for this device.

2. Create the sketch's `secrets.h`:
   ```bash
   python python_generator_v2.py secrets > secrets.h
   ```

3. Open `esp32_code.ino` in Arduino IDE or PlatformIO and upload.

The sketch targets Arduino-ESP32 core 3.x (mbedtls 3.x); core 2.x
(mbedtls 2.28) is handled via `MBEDTLS_VERSION_MAJOR` guards.

---

## Simulator

Generate a signed QR code without hardware (uses the same key as step 1):

```bash
python python_generator_v2.py qr
```

The QR image lands in `static/` and the validation URL is printed for testing.

---

## Documentation

For more details, refer to the [main project README](../README.md).
