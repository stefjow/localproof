"""End-to-end tests for public-key device registration (/add-device)."""
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

DEV_LAT, DEV_LNG = 48.1889, 16.3763


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with open(os.path.join(REPO_ROOT, 'website', 'create_database.py')) as f:
        exec(f.read(), {'__name__': 'create_database'})
    appmod.app.config['TESTING'] = True
    return appmod.app.test_client()


@pytest.fixture
def logged_in(client):
    client.post('/register', data={'username': 'alice', 'password': 'pw'})
    resp = client.post('/login', data={'username': 'alice', 'password': 'pw'}).get_json()
    assert resp['success']
    return client


def add_device(client, **overrides):
    body = {'device_id': 'AB12', 'pubkey': None, 'lat': DEV_LAT, 'lng': DEV_LNG,
            'max_validations': 1}
    body.update(overrides)
    return client.post('/add-device', json=body).get_json()


def test_requires_login(client):
    key = ECC.generate(curve='P-256')
    resp = client.post('/add-device', json={
        'device_id': 'AB12',
        'pubkey': key.public_key().export_key(format='PEM'),
    })
    assert resp.status_code in (302, 401)  # redirected to login / unauthorized


def test_register_and_validate_with_browser_style_key(logged_in):
    # the browser generates the pair and uploads only the public key
    key = ECC.generate(curve='P-256')
    result = add_device(logged_in, pubkey=key.public_key().export_key(format='PEM'))
    assert result['success'] is True

    # the device (simulator) signs with the private key -> full v2 flow
    ts = int(time.time())
    p64, s64 = sign_payload(key, 'AB12', ts, DEV_LAT, DEV_LNG)
    resp = logged_in.get(f'/v2/AB12/{p64}/{s64}')
    nonce = re.search(r"nonce: '([^']+)'", resp.get_data(as_text=True)).group(1)
    result = logged_in.post('/validate/complete', json={
        'nonce': nonce, 'scanner_lat': DEV_LAT, 'scanner_lng': DEV_LNG}).get_json()
    assert result['success'] is True
    assert result['location_verified'] is True


def test_invalid_pubkey_rejected(logged_in):
    result = add_device(logged_in, pubkey='not a key')
    assert result['success'] is False
    assert 'public key' in result['message'].lower()


def test_private_key_rejected(logged_in):
    key = ECC.generate(curve='P-256')
    result = add_device(logged_in, pubkey=key.export_key(format='PEM'))
    assert result['success'] is False


def test_wrong_curve_rejected(logged_in):
    key = ECC.generate(curve='P-384')
    result = add_device(logged_in, pubkey=key.public_key().export_key(format='PEM'))
    assert result['success'] is False


def test_missing_pubkey_rejected(logged_in):
    result = add_device(logged_in, pubkey=None)
    assert result['success'] is False


def test_duplicate_device_id_rejected(logged_in):
    key = ECC.generate(curve='P-256')
    pem = key.public_key().export_key(format='PEM')
    assert add_device(logged_in, pubkey=pem)['success'] is True
    result = add_device(logged_in, pubkey=pem)
    assert result['success'] is False
    assert 'already exists' in result['message']


def test_inactive_devices_api_does_not_leak_keys(logged_in):
    key = ECC.generate(curve='P-256')
    add_device(logged_in, pubkey=key.public_key().export_key(format='PEM'))
    devices = logged_in.get('/api/my-inactive-devices').get_json()
    assert len(devices) == 1
    assert 'secret' not in devices[0]
    assert 'pubkey' not in devices[0]
    assert devices[0]['device_id'] == 'AB12'
