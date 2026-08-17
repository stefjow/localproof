"""End-to-end tests for the v2 (ECDSA signature) validation scheme.

Uses sign_payload() from the actual simulator (esp32/python_generator_v2.py),
so the signing contract between device and server is tested, not a copy.
"""
import base64
import os
import re
import sys
import time

import pytest
from Crypto.PublicKey import ECC

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, 'website'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'esp32'))

import app as appmod  # noqa: E402
from python_generator_v2 import sign_payload  # noqa: E402

DEVICE_ID = '0001'
DEV_LAT, DEV_LNG = 48.1889, 16.3763

DEVICE_KEY = ECC.generate(curve='P-256')
WRONG_KEY = ECC.generate(curve='P-256')


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    website_dir = os.path.join(REPO_ROOT, 'website')
    with open(os.path.join(website_dir, 'create_database.py')) as f:
        exec(f.read(), {'__name__': 'create_database'})
    appmod.add_device(DEVICE_ID, lat=DEV_LAT, lng=DEV_LNG,
                      max_validations=2, username='tester',
                      pubkey=DEVICE_KEY.public_key().export_key(format='PEM'))
    appmod.add_device('NOKEY', lat=DEV_LAT, lng=DEV_LNG,
                      max_validations=1, username='tester')
    appmod.app.config['TESTING'] = True
    return appmod.app.test_client()


def make_signed_path(device_id=DEVICE_ID, ts=None, lat=DEV_LAT, lng=DEV_LNG,
                     key=DEVICE_KEY, sign_as=None):
    """Build the v2 URL path as the device would.

    sign_as lets a test sign for a different device_id than the URL claims
    (signature transplant).
    """
    ts = ts if ts is not None else int(time.time())
    payload_b64, sig_b64 = sign_payload(key, sign_as or device_id, ts, lat, lng)
    return f'/v2/{device_id}/{payload_b64}/{sig_b64}'


def open_qr(client, path):
    resp = client.get(path)
    html = resp.get_data(as_text=True)
    match = re.search(r"nonce: '([^']+)'", html)
    return resp, (match.group(1) if match else None), html


def complete(client, nonce, **extra):
    body = {'nonce': nonce}
    body.update(extra)
    return client.post('/validate/complete', json=body).get_json()


def scan_and_complete(client, path, **extra):
    _, nonce, _ = open_qr(client, path)
    assert nonce is not None
    return complete(client, nonce, **extra)


def test_valid_signed_scan(client):
    result = scan_and_complete(client, make_signed_path(),
                               scanner_lat=DEV_LAT + 0.001, scanner_lng=DEV_LNG)
    assert result['success'] is True
    assert result['location_verified'] is True
    assert abs(result['esp_lat'] - DEV_LAT) < 1e-4


def test_tampered_payload_fails(client):
    # Sign for one location, claim another in the payload
    ts = int(time.time())
    payload_b64, sig_b64 = sign_payload(DEVICE_KEY, DEVICE_ID, ts, DEV_LAT, DEV_LNG)
    tampered = base64.urlsafe_b64encode(
        f'{ts}|{DEV_LAT + 1:.6f}|{DEV_LNG:.6f}'.encode()
    ).decode()
    result = scan_and_complete(client, f'/v2/{DEVICE_ID}/{tampered}/{sig_b64}',
                               scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Invalid Signature'


def test_wrong_key_fails(client):
    result = scan_and_complete(client, make_signed_path(key=WRONG_KEY),
                               scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Invalid Signature'


def test_signature_transplant_fails(client):
    # Signature valid for device 'NOKEY' presented under DEVICE_ID's URL
    result = scan_and_complete(client, make_signed_path(sign_as='NOKEY'),
                               scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Invalid Signature'


def test_stale_code_expired(client):
    result = scan_and_complete(client, make_signed_path(ts=int(time.time()) - 120),
                               scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Code Expired'


def test_future_code_expired(client):
    result = scan_and_complete(client, make_signed_path(ts=int(time.time()) + 120),
                               scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Code Expired'


def test_max_validations_per_signed_code(client):
    ts = int(time.time())
    path = make_signed_path(ts=ts)
    for _ in range(2):
        assert scan_and_complete(client, path, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)['success'] is True
    result = scan_and_complete(client, path, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Max Validations Exceeded'

    # A fresh code resets the budget — counting is per code, not per clock cycle
    result = scan_and_complete(client, make_signed_path(ts=ts + 1),
                               scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is True


def test_location_mismatch_fails(client):
    result = scan_and_complete(client, make_signed_path(),
                               scanner_lat=DEV_LAT + 0.5, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Location Mismatch'


def test_denied_geolocation_downgrades(client):
    result = scan_and_complete(client, make_signed_path())
    assert result['success'] is True
    assert result['location_verified'] is False


def test_nonce_reuse_rejected(client):
    _, nonce, _ = open_qr(client, make_signed_path())
    assert complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)['success'] is True
    result = complete(client, nonce, scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert 'Reused' in result['status']


def test_device_without_pubkey_rejected(client):
    resp, nonce, _ = open_qr(client, make_signed_path(device_id='NOKEY', key=DEVICE_KEY, sign_as='NOKEY'))
    assert b'Invalid Device ID' in resp.data
    assert nonce is None


def test_code_ts_logged(client):
    ts = int(time.time())
    scan_and_complete(client, make_signed_path(ts=ts), scanner_lat=DEV_LAT, scanner_lng=DEV_LNG)
    conn = appmod.get_db_connection()
    row = conn.execute(
        "SELECT reason, code_ts FROM validation_logs WHERE status = 'success'"
    ).fetchone()
    conn.close()
    assert row['reason'] == 'Valid Signature'
    assert row['code_ts'] == ts
