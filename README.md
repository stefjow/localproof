# localproof

**Proof of Presence and Location Using ESP32 Devices**

This project implements a proof-of-presence system using ESP32 microcontrollers. Each device signs `device_id|timestamp|lat|lng` with an ECDSA P-256 key — preferably inside an ATECC608 secure element, so the key cannot be extracted or cloned — and displays the result as a QR code that rotates every 30 seconds.

Scanning the QR opens a validation URL. The server does not trust the URL alone: it issues a one-time nonce challenge that the scanner's browser must answer within seconds, along with its geolocation, which is cross-checked against the device's registered location. Replayed links, reused challenges and stale codes (45s freshness window) are rejected.

Time synchronization is provided by GPS, enabling operation without internet connectivity. A simple stack (ESP32 hardware, a Flask backend, and a Leaflet.js frontend) is used to generate, verify, and visualize presence data.

The website is hosted at [localproof.org](https://localproof.org/).

[Hardware specifics](https://github.com/sweing/localproof/blob/main/HARDWARE.md)

<img src="pictures/device.jpeg?raw=true" height="300"/> <img src="pictures/screen.jpeg?raw=true" height="300"/> <img src="pictures/verification.jpeg?raw=true" height="300"/> <img src="pictures/popup.jpeg?raw=true" height="300"/> 

---

## Features

- **Hardware-anchored signatures**: ECDSA P-256 via an ATECC608 secure element (with a software-key fallback) — the server stores only public keys, so neither a server compromise nor a full flash dump can clone a device.
- **Nonce challenge flow**: opening a QR URL does not validate; the browser must answer a fresh one-time challenge, killing cached/forwarded links.
- **Scanner geolocation cross-check**: browser location is compared against the device's registered position (>500m fails; denied geolocation downgrades to "location unverified").
- **Real-Time Map**: interactive map showing device locations and validation attempts.
- **Flask backend**: SQLite database for devices and validation logs, end-to-end pytest suite, CI.

### What a validation proves (and what it doesn't)

A successful validation proves that *someone with a live browser, at a plausible location, answered a fresh challenge within seconds of the device displaying the code*. A live real-time relay by a cooperating person at the location (streaming the QR and spoofing geolocation) is not prevented — relay resistance beyond this would require a bidirectional proximity channel (NFC/UWB) rather than a display-only device.

---

## Repository Structure

```
localproof/
├── esp32/                       # ESP32 firmware, tools and simulators
│   ├── esp32_code.ino           # Main firmware (ECDSA-signed QR codes)
│   ├── qrcodegen.{h,c}          # Vendored QR generator (ricmoo/QRCode, MIT)
│   ├── secrets.h.example        # Device identity template (secrets.h is gitignored)
│   ├── hw_probe/                # Diagnostic sketch: I2C scan, ATECC status, RTC sync
│   ├── python_generator_v2.py   # Device simulator: keygen, signed QRs, key conversion
│   ├── static/                  # Generated QR images
│   └── README.md                # Provisioning and firmware documentation
├── website/                     # Flask backend and frontend
│   ├── app.py                   # Flask application
│   ├── create_database.py       # Schema creation + migrations (safe to re-run)
│   ├── .env.example             # SECRET_KEY etc. (.env is gitignored)
│   ├── landing_page.html        # Landing page
│   ├── static/                  # CSS, JS, images
│   ├── templates/               # HTML templates
│   └── README.md                # Website-specific documentation
├── tests/                       # End-to-end pytest suite
├── .github/workflows/ci.yml     # CI: full test suite on push/PR
├── pictures/                    # Photos for the README and HARDWARE.md
├── HARDWARE.md                  # Hardware build description
├── requirements.txt             # Python dependencies
└── LICENSE                      # Project license (MIT)
```

---

## Getting Started

### Prerequisites

- Python 3.8+
- Flask
- SQLite
- ESP32 development environment (Arduino IDE or PlatformIO)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sweing/localproof.git
   cd localproof
   ```
2. Setting up virtual environment & install requirements:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Create database and run the Flask app:
   ```bash
   cd website
   python create_database.py
   python app.py
   ```

4. Access the website at `http://localhost:5005`.

### Production deployment

Set a fixed session key and run under gunicorn instead of the Flask dev server:

```bash
cd website
cp .env.example .env   # then set SECRET_KEY (see comment in the file)
gunicorn -w 2 -b 127.0.0.1:5005 app:app
```

### Running the tests

End-to-end tests for the validation flow (QR scan → nonce challenge → signature,
location and max-validation checks) live in `tests/`. From the repo root:

```bash
pytest
```

---

## ESP32 Code

The ESP32 code and simulators are located in the `esp32/` directory. Refer to the [ESP32 README](esp32/README.md) for details on setting up and running the code.

---

## Contributing

Contributions are welcome!

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
