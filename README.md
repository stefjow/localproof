# localproof

**Proof of Presence and Location Using ESP32 Devices**

This project implements an proof-of-presence system using ESP32 microcontrollers. Each device generates a cryptographically signed QR code that rotates every 30 seconds.

Time synchronization is provided by GPS, enabling operation without internet connectivity. A simple stack (ESP32 hardware, a Flask backend, and a Leaflet.js frontend) is used to generate, verify, and visualize presence data.

The website is hosted at [localproof.org](https://localproof.org/).

[Hardware specifics](https://github.com/sweing/localproof/blob/main/HARDWARE.md)

<img src="pictures/device.jpeg?raw=true" height="300"/> <img src="pictures/screen.jpeg?raw=true" height="300"/> <img src="pictures/verification.jpeg?raw=true" height="300"/> <img src="pictures/popup.jpeg?raw=true" height="300"/> 

---

## Features

- **ESP32 Integration**: Devices generate encrypted QR codes with GPS coordinates and TOTP codes.
- **Real-Time Map**: Interactive map showing device locations and validation attempts.
- **Secure Validation**: AES-256 encryption and TOTP-based validation for tamper-proof data.
- **Scalable Backend**: Flask-powered API with SQLite database for storing devices and logs.

---

## Repository Structure

- **`esp32/`**: Code for ESP32 devices and Python-based simulators.
- **`website/`**: Flask backend and frontend for the web app.
- **`README.md`**: This file.
- **`LICENSE`**: Project license.


```
localproof/
├── esp32/                     # ESP32 code and related files
│   ├── esp32_code.ino         # Main ESP32 code
│   ├── python_generator.py    # Python code to simulate ESP32 behavior
│   ├── static/                # Folder to store generated QRs
│   └── README.md              # ESP32-specific documentation
├── website/                   # Flask website code
│   ├── app.py                 # Flask application
│   ├── create_database.py     # Python script to generate database (run once)
│   ├── landing_page.html      # Landing page
│   ├── static/                # Static files (CSS, JS, images)
│   ├── templates/             # HTML templates
│   └── README.md              # Website-specific documentation
├── pictures/                  # Photos for BLOGPOST.md
├── README.md                  # Main project README
├── BLOGPOST.md                # Blog post
├── requirements.txt           # Python dependencies
└── LICENSE                    # Project license
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
   git clone https://github.com/your-username/localproof.git
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

### Running the tests

End-to-end tests for the validation flow (QR scan → nonce challenge → TOTP,
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
