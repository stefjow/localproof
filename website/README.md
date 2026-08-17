# localproof Website

This directory contains the Flask backend and frontend for the web app.

---

## Features

- **Interactive Map**: Displays device locations and validation attempts.
- **Validation API**: Verifies ECDSA-signed QR codes from ESP32 devices
  (`/v2/<id>/<payload>/<signature>`).
  Every scan must complete a one-time nonce challenge within 15 seconds,
  and the scanner's browser geolocation is cross-checked against the
  device's registered position.
- **Database**: SQLite database for storing devices (public keys) and
  validation logs. `create_database.py` also carries the schema
  migrations and is safe to re-run.

---

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Create database and run the Flask app:
   ```bash
   cd website
   python create_database.py
   python app.py
   ```

3. Access the website at `http://localhost:5005`.

---

## Documentation

For more details, refer to the [main project README](../README.md).