"""End-to-end tests for the QR validation flow (nonce challenge).

Each test runs against a fresh SQLite database in a temp directory and
reproduces the ESP32/simulator payload (AES-256-CBC over "totp|lat|lng"),
so drift between the device crypto and the server contract fails here.

Run from the repo root:
    pytest
"""
import base64
import os
import re
import sys
import time

import pyotp
import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBSITE_DIR = os.path.join(REPO_ROOT, 'website')
sys.path.insert(0, WEBSITE_DIR)

import app as appmod  # noqa: E402

SECRET = 'JBSWY3DPEHPK3PXP'  # base32, as pyotp expects
DEVICE_ID = '0001'
DEV_LAT, DEV_LNG = 48.1889, 16.3763


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Fresh database in a temp cwd (app.py opens 'database.db' relatively)."""
    monkeypatch.chdir(tmp_path)
    with open(os.path.join(WEBSITE_DIR, 'create_database.py')) as f:
        exec(f.read(), {'__name__': 'create_database'})
    appmod.add_device(DEVICE_ID, SECRET, DEV_LAT, DEV_LNG,
                      max_validations=2, username='tester')
    appmod.app.config['TESTING'] = True
    return appmod.app.test_client()


def make_qr_path(secret=SECRET, lat=DEV_LAT, lng=DEV_LNG, totp_code=None):
    """Build the URL path exactly as the ESP32/simulator does."""
    key = secret.encode().ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    code = totp_code or pyotp.TOTP(secret).now()
    ct = cipher.encrypt(pad(f'{code}|{lat}|{lng}'.encode(), AES.block_size))
    return f'/{DEVICE_ID}/' + base64.urlsafe_b64encode(iv + ct).decode()


def open_qr(client, path=None):
    """Step 1: open the QR URL and extract the challenge nonce."""
    resp = client.get(path or make_qr_path())
    html = resp.get_data(as_text=True)
    match = re.search(r"nonce: '([^']+)'", html)
    return resp, (match.group(1) if match else None), html


def complete(client, nonce, **extra):
    """Step 2: answer the challenge."""
    body = {'nonce': nonce}
    body.update(extra)
    return client.post('/validate/complete', json=body).get_json()


def wait_for_cycle_headroom(seconds=3):
    """Avoid flakiness from a TOTP cycle boundary in the middle of a test."""
    remaining = 30 - (time.time() % 30)
    if remaining < seconds:
        time.sleep(remaining)


def test_scan_issues_challenge(client):
    resp, nonce, html = open_qr(client)
    assert resp.status_code == 200
    assert nonce is not None
    assert 'Verifying presence' in html


def test_valid_scan_with_matching_location(client):
    _, nonce, _ = open_qr(client)
    result = complete(client, nonce, scanner_lat=DEV_LAT + 0.001, scanner_lng=DEV_LNG)
    assert result['success'] is True
    assert result['location_verified'] is True
    assert abs(result['esp_lat'] - DEV_LAT) < 1e-4
    assert abs(result['esp_lng'] - DEV_LNG) < 1e-4


def test_nonce_reuse_rejected(client):
    _, nonce, _ = open_qr(client)
    assert complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)['success'] is True
    result = complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert 'Reused' in result['status']


def test_unknown_nonce_rejected(client):
    result = complete(client, 'not-a-real-nonce')
    assert result['success'] is False


def test_missing_nonce_rejected(client):
    resp = client.post('/validate/complete', json={})
    assert resp.status_code == 400


def test_location_mismatch_fails(client):
    _, nonce, _ = open_qr(client)
    # scanner ~55km north of the device
    result = complete(client, nonce, scanner_lat=DEV_LAT + 0.5, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Location Mismatch'


def test_denied_geolocation_downgrades(client):
    _, nonce, _ = open_qr(client)
    result = complete(client, nonce)
    assert result['success'] is True
    assert result['location_verified'] is False
    assert 'unverified' in result['status']


def test_max_validations_enforced(client):
    wait_for_cycle_headroom()
    for _ in range(2):
        _, nonce, _ = open_qr(client)
        assert complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)['success'] is True
    _, nonce, _ = open_qr(client)
    result = complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Max Validations Exceeded'


def test_expired_nonce_rejected(client):
    _, nonce, _ = open_qr(client)
    conn = appmod.get_db_connection()
    conn.execute("UPDATE pending_validations SET created_at = '2020-01-01 00:00:00' WHERE nonce = ?", (nonce,))
    conn.commit()
    conn.close()
    result = complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Challenge Expired'


def test_invalid_totp_fails(client):
    _, nonce, _ = open_qr(client, make_qr_path(totp_code='000000'))
    result = complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Invalid Link'


def test_wrong_key_fails_decryption(client):
    _, nonce, _ = open_qr(client, make_qr_path(secret='WRONGKEYWRONGKEY'))
    result = complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Invalid Data Encryption'


def test_unknown_device_fails_without_challenge(client):
    resp = client.get('/9999/AAAA')
    assert b'Invalid Device ID' in resp.data
    assert b"nonce: '" not in resp.data


def test_logs_record_scanner_location_and_reason(client):
    wait_for_cycle_headroom()
    _, nonce, _ = open_qr(client)
    complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    _, nonce, _ = open_qr(client)
    complete(client, nonce)

    conn = appmod.get_db_connection()
    rows = conn.execute(
        "SELECT reason, scanner_lat FROM validation_logs WHERE status = 'success' ORDER BY id"
    ).fetchall()
    conn.close()
    assert [row['reason'] for row in rows] == ['Valid TOTP', 'Valid TOTP (location unverified)']
    assert rows[0]['scanner_lat'] is not None
    assert rows[1]['scanner_lat'] is None
