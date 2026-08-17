# localproof

Proof of presence and location for ESP32 devices.

Each device signs `device_id|timestamp|lat|lng` with an ECDSA P-256 key that lives inside an ATECC608B secure element. The private key is generated on-chip and cannot be read out, so the server only stores the corresponding public key. The signed payload is displayed as a QR code that rotates every 30 seconds. Time and coordinates come from a GPS module, so the device runs without any network connection.

The site is hosted at [localproof.libmap.org](https://localproof.libmap.org). Hardware notes: [HARDWARE.md](HARDWARE.md).

<img src="pictures/device.jpeg" height="260"/> <img src="pictures/screen.jpeg" height="260"/> <img src="pictures/verification.jpeg" height="260"/> <img src="pictures/popup.jpeg" height="260"/>

---

## How verification works

Scanning the QR opens a URL of the form `/v2/<device_id>/<payload>/<signature>` (both parts base64url). The server then:

1. Verifies the ECDSA signature against the device's registered public key.
2. Checks the payload timestamp against a 45-second freshness window.
3. Issues a one-time nonce and renders a page that requests browser geolocation.
4. Accepts the nonce back (within 15 seconds) together with the scanner's coordinates, and compares them to the device's registered position; more than 500 m apart is rejected, denied geolocation is recorded as *location unverified*.

### What a successful validation shows

That a live browser, at a plausible location, answered a fresh challenge within seconds of the QR being displayed. It does not defend against a cooperating on-site relay (someone at the device streaming the QR and spoofing geolocation); ruling that out would require a proximity channel such as NFC or UWB, which a display-only device cannot provide.

### Why these pieces

- **On-chip key.** A device can be physically opened and its flash dumped without leaking the signing key, so cloning requires physical possession of a specific chip.
- **Freshness window.** Bounds how long a captured QR remains useful without depending on any clock the attacker controls.
- **Nonce + geolocation.** Separates "someone saw a URL" from "someone was there when it was displayed". The URL alone is not a proof.
- **GPS time.** Removes the need for network time sync; the RTC is set once per power cycle from GPS.

---

## Stack

- **Firmware:** Arduino/ESP32, NEO-6M GPS, DS3231 RTC, ATECC608B, 1.54" Waveshare e-paper.
- **Backend:** Flask + SQLite, gunicorn in production. Devices, users and validation logs live in one database; only public keys are stored.
- **Frontend:** MapLibre globe with per-device history and per-user validation lists.
- **Tests:** pytest end-to-end suite covering the full scan → nonce → signature → location flow. CI on every push.

## Repository layout

```
esp32/            firmware, provisioning tools, device simulator
website/          Flask app, schema, templates, static assets
tests/            end-to-end validation tests
pictures/         photos used in the docs
HARDWARE.md       hardware build notes
requirements.txt
```

## Getting started

```bash
git clone https://github.com/stefjow/localproof.git
cd localproof
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cd website
python create_database.py
python app.py         # http://localhost:5005
```

For production, set `SECRET_KEY` in `website/.env` and run under gunicorn:

```bash
gunicorn -w 2 -b 127.0.0.1:5005 app:app
```

## Tests

```bash
pytest
```

## ESP32

Provisioning and firmware details are in [esp32/README.md](esp32/README.md).

---

MIT licensed. See [LICENSE](LICENSE).
