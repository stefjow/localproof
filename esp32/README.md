# ESP32 Code and Simulators

This directory contains the code for ESP32 devices and Python-based simulators to test the system.

---

## Files

- **`esp32_code.ino`**: Main ESP32 code. Signs `device_id|ts|lat|lng` with an ECDSA P-256 key (mbedtls) and displays the resulting `/v2/...` URL as a QR code.
- **`secrets.h.example`**: Template for the device identity (`secrets.h` is gitignored).
- **`python_generator_v2.py`**: Simulates the device — key generation and signed QR codes.
- **`python_generator.py`**: Legacy v1 simulator (AES-encrypted TOTP codes).

---

## Provisioning a device

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
