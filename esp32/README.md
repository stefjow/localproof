# ESP32 Code and Simulators

This directory contains the code for ESP32 devices and Python-based simulators to test the system.

---

## Files

- **`esp32_code.ino`**: Main ESP32 code. Signs `device_id|ts|lat|lng` with ECDSA P-256 — in the ATECC608 secure element when present (I2C 0x60, locked, key in slot 0), otherwise in software (mbedtls) — and displays the resulting `/v2/...` URL as a QR code.
- **`hw_probe/`**: Diagnostic sketch — I2C wake-scan, ATECC status and public-key readout, RTC sync over serial (`SETTIME <epoch>`), and test signing (`SIGN <sha256 hex>`).
- **`secrets.h.example`**: Optional template for the software-key fallback (`secrets.h` is gitignored). With an ATECC608 present, no `secrets.h` is needed — the device id is derived from the chip's public key.
- **`python_generator_v2.py`**: Simulates the device — key generation, signed QR codes, and ATECC public-key conversion (`pem` command).

---

## Provisioning a device

The device id is not a manual label. On first boot the firmware computes
`SHA-256(pubkey)[:4]` as 8 hex chars, caches it in NVS, and shows it on
the searching screen. That id is what the owner registers on the server.

### With an ATECC608 secure element (recommended)

1. Flash `esp32_code.ino` (no `secrets.h` needed — the chip's key is used).
2. Power on; the searching screen shows the derived device id.
3. Read the chip's public key out with `hw_probe/hw_probe.ino` and convert
   it for registration:
   ```bash
   python python_generator_v2.py pem <xy-hex>
   ```
   Paste the printed PEM into the site's registration popup; the server
   derives the same id and creates the device row.

### Without a secure element (software key)

1. Generate a keypair (once per device):
   ```bash
   python python_generator_v2.py keygen
   ```
   The private key lands in `keys/device_private.pem` (gitignored); the
   PEM public key and the derived device id are printed.

2. Emit `secrets.h` for the sketch:
   ```bash
   python python_generator_v2.py secrets > secrets.h
   ```

3. Open `esp32_code.ino` in Arduino IDE or PlatformIO and upload. Register
   the public key on the server as above.

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
