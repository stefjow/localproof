"""Simulator for the v2 (signature) scheme.

Instead of encrypting a TOTP code (v1), the device signs
"device_id|ts|lat|lng" with an ECDSA P-256 private key. The server only
stores the public key, so nothing on the server can forge a device.

Usage:
    python python_generator_v2.py keygen   # once per device, prints the
                                           # public key PEM to register
    python python_generator_v2.py qr       # generate a signed QR code

On the real device the same signature is produced by mbedtls (software)
or an ATECC608 secure element (hardware), both of which speak ECDSA P-256.
"""
import base64
import os
import sys
import time

import qrcode
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# base_url = "https://map.localproof.org"
base_url = "http://localhost:5005"

device_id = "0001"
device_lat = 48.188920
device_lng = 16.376279

KEY_DIR = "keys"


def key_path(device_id):
    return os.path.join(KEY_DIR, f"{device_id}_private.pem")


def generate_keypair(device_id):
    """Generate a P-256 keypair. The private key stays with the device
    (here: a local PEM file); the printed public key goes to the server."""
    os.makedirs(KEY_DIR, exist_ok=True)
    path = key_path(device_id)
    if os.path.exists(path):
        raise SystemExit(f"Refusing to overwrite existing key: {path}")

    key = ECC.generate(curve='P-256')
    with open(path, 'wt') as f:
        f.write(key.export_key(format='PEM'))
    print(f"Private key saved to '{path}' (keep it on the device, never commit it)")
    print("\nPublic key to register on the server:\n")
    print(key.public_key().export_key(format='PEM'))


def sign_payload(private_key, device_id, ts, lat, lng):
    """Sign 'device_id|ts|lat|lng', return (payload_b64, sig_b64).

    The payload string is signed exactly as transmitted, so the server can
    verify without re-formatting floats.
    """
    payload = f"{ts}|{lat:.6f}|{lng:.6f}"
    message = f"{device_id}|{payload}".encode('utf-8')
    signature = DSS.new(private_key, 'fips-186-3').sign(SHA256.new(message))
    return (
        base64.urlsafe_b64encode(payload.encode('utf-8')).decode('ascii'),
        base64.urlsafe_b64encode(signature).decode('ascii'),
    )


def generate_signed_qr(device_id, lat, lng):
    with open(key_path(device_id), 'rt') as f:
        private_key = ECC.import_key(f.read())

    ts = int(time.time())
    payload_b64, sig_b64 = sign_payload(private_key, device_id, ts, lat, lng)
    validation_url = f"{base_url}/v2/{device_id}/{payload_b64}/{sig_b64}"

    print(f"Signed at ts={ts}")
    print(f"Validation URL: {validation_url}")

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(validation_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    os.makedirs("static", exist_ok=True)
    img_path = f"static/{device_id}_signed_qr.png"
    img.save(img_path)
    print(f"QR code saved as '{img_path}' (version {qr.version})")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else 'qr'
    if command == 'keygen':
        generate_keypair(device_id)
    elif command == 'qr':
        generate_signed_qr(device_id, device_lat, device_lng)
    else:
        raise SystemExit(f"Unknown command '{command}' (use 'keygen' or 'qr')")
