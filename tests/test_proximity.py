"""Proximity tokens: registration, crediting rules, and the firmware checks.

The station attests a token by appending tokenId|medianRttUs to its signed
payload (esp32/lpx_station.h). sign_payload() from the simulator produces
the same payload, so the device/server contract is tested, not a copy.
"""
import base64
import filecmp
import os
import re
import shutil
import subprocess
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
DEVICE_KEY = ECC.generate(curve='P-256')
DEVICE_PEM = DEVICE_KEY.public_key().export_key(format='PEM')
DEVICE_ID = appmod.derive_device_id(DEVICE_PEM)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with open(os.path.join(REPO_ROOT, 'website', 'create_database.py')) as f:
        exec(f.read(), {'__name__': 'create_database'})
    appmod.add_device(DEVICE_ID, lat=DEV_LAT, lng=DEV_LNG, max_validations=5,
                      username='owner', pubkey=DEVICE_PEM)
    appmod.app.config['TESTING'] = True
    return appmod.app.test_client()


def login(client, username):
    client.get('/logout')
    client.post('/register', data={'username': username, 'password': 'pw'})
    assert client.post('/login', data={'username': username, 'password': 'pw'}).get_json()['success']


def add_token(client):
    pem = ECC.generate(curve='P-256').public_key().export_key(format='PEM')
    resp = client.post('/add-token', json={'pubkey': pem}).get_json()
    assert resp['success'] is True, resp
    return resp['token_id'], pem


def scan(client, token_id=None, rtt_us=None, payload_b64=None, sig_b64=None):
    if payload_b64 is None:
        payload_b64, sig_b64 = sign_payload(DEVICE_KEY, DEVICE_ID, int(time.time()),
                                            DEV_LAT, DEV_LNG, token_id=token_id, rtt_us=rtt_us)
    html = client.get(f'/v2/{DEVICE_ID}/{payload_b64}/{sig_b64}').get_data(as_text=True)
    nonce = re.search(r"nonce: '([^']+)'", html).group(1)
    return client.post('/validate/complete', json={
        'nonce': nonce, 'scanner_lat': DEV_LAT, 'scanner_lng': DEV_LNG}).get_json()


def last_log():
    conn = appmod.get_db_connection()
    row = conn.execute('SELECT * FROM validation_logs ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------- crediting

def test_owner_gets_proximity(client):
    login(client, 'alice')
    token_id, _ = add_token(client)
    result = scan(client, token_id, 2140)
    assert result['success'] is True
    assert result['proximity_verified'] is True
    row = last_log()
    assert row['reason'] == 'Valid Signature + Proximity (2140 us)'
    assert row['token_id'] == token_id and row['token_rtt_us'] == 2140


def test_plain_qr_has_no_proximity(client):
    login(client, 'alice')
    add_token(client)
    result = scan(client)
    assert result['success'] is True
    assert result['proximity_verified'] is False
    assert last_log()['reason'] == 'Valid Signature'


def test_someone_elses_token_not_credited(client):
    # Bob scans the QR that attests Alice's token: a normal validation for
    # Bob, no proximity. This is the "accomplice holds the QR" case.
    login(client, 'alice')
    token_id, _ = add_token(client)
    login(client, 'bob')
    result = scan(client, token_id, 2140)
    assert result['success'] is True
    assert result['proximity_verified'] is False
    # Bob's log must not reveal that Alice's token was at the station.
    row = last_log()
    assert row['token_id'] is None and row['token_rtt_us'] is None


def test_anonymous_scan_not_credited(client):
    login(client, 'alice')
    token_id, _ = add_token(client)
    client.get('/logout')
    result = scan(client, token_id, 2140)
    assert result['success'] is True
    assert result['proximity_verified'] is False


def test_server_rtt_limit(client, monkeypatch):
    login(client, 'alice')
    token_id, _ = add_token(client)
    monkeypatch.setattr(appmod, 'MAX_TOKEN_RTT_US', 2500)
    assert scan(client, token_id, 2500)['proximity_verified'] is True
    assert scan(client, token_id, 2501)['proximity_verified'] is False


def test_revoked_token_not_credited(client):
    login(client, 'alice')
    token_id, _ = add_token(client)
    assert client.delete(f'/delete-token/{token_id}').get_json()['success'] is True
    assert scan(client, token_id, 2140)['proximity_verified'] is False


# ---------------------------------------------------------------- integrity

def test_appended_token_breaks_signature(client):
    # A token attestation added after signing (i.e. not by the station).
    login(client, 'alice')
    token_id, _ = add_token(client)
    ts = int(time.time())
    _, sig_b64 = sign_payload(DEVICE_KEY, DEVICE_ID, ts, DEV_LAT, DEV_LNG)
    forged = base64.urlsafe_b64encode(
        f'{ts}|{DEV_LAT:.6f}|{DEV_LNG:.6f}|{token_id}|2140'.encode()).decode()
    result = scan(client, payload_b64=forged, sig_b64=sig_b64)
    assert result['success'] is False
    assert result['status'] == 'Invalid Signature'


@pytest.mark.parametrize('extra', ['|abcd1234', '|ABCD1234|100', '|abcd123|100', '|abcd1234|fast'])
def test_malformed_token_fields(client, extra):
    ts = int(time.time())
    payload = f'{ts}|{DEV_LAT:.6f}|{DEV_LNG:.6f}{extra}'
    from Crypto.Hash import SHA256
    from Crypto.Signature import DSS
    sig = DSS.new(DEVICE_KEY, 'fips-186-3').sign(SHA256.new(f'{DEVICE_ID}|{payload}'.encode()))
    result = scan(client, payload_b64=base64.urlsafe_b64encode(payload.encode()).decode(),
                  sig_b64=base64.urlsafe_b64encode(sig).decode())
    assert result['success'] is False
    assert result['status'] == 'Invalid Data Format'


# ------------------------------------------------------------- registration

def test_token_registration_rules(client):
    login(client, 'alice')
    token_id, pem = add_token(client)
    assert re.fullmatch(r'[0-9a-f]{8}', token_id)
    assert token_id == appmod.derive_device_id(pem)  # same scheme as firmware
    assert client.post('/add-token', json={'pubkey': pem}).get_json()['success'] is False
    assert client.post('/add-token', json={'pubkey': 'nope'}).get_json()['success'] is False
    assert [t['token_id'] for t in client.get('/api/my-tokens').get_json()] == [token_id]

    login(client, 'bob')
    assert client.get('/api/my-tokens').get_json() == []
    assert client.delete(f'/delete-token/{token_id}').get_json()['success'] is False


def test_add_token_requires_login(client):
    pem = ECC.generate(curve='P-256').public_key().export_key(format='PEM')
    resp = client.post('/add-token', json={'pubkey': pem})
    assert resp.status_code in (302, 401)


# ----------------------------------------------------------------- firmware

def test_token_header_copy_in_sync():
    # Arduino can't include from outside a sketch folder, so the token
    # carries its own copy of the protocol header.
    assert filecmp.cmp(os.path.join(REPO_ROOT, 'esp32', 'lpx_protocol.h'),
                       os.path.join(REPO_ROOT, 'esp32', 'token', 'lpx_protocol.h'),
                       shallow=False), 'esp32/token/lpx_protocol.h differs from esp32/lpx_protocol.h'


def test_firmware_protocol_checks(tmp_path):
    """Builds tests/lpx_host_test.cpp against the real lpx_protocol.h and
    runs the station's opening checks against honest and attacking tokens."""
    gxx = shutil.which('g++')
    if not gxx or not os.path.exists('/usr/include/mbedtls/ecdsa.h'):
        pytest.skip('needs g++ and mbedtls headers (apt install libmbedtls-dev)')
    exe = tmp_path / 'lpx_host_test'
    subprocess.run([gxx, '-std=c++17', '-I', os.path.join(REPO_ROOT, 'esp32'),
                    os.path.join(REPO_ROOT, 'tests', 'lpx_host_test.cpp'),
                    '-lmbedcrypto', '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout

    # The firmware's token id must match the server's derivation.
    key_line = next(line for line in out.stdout.splitlines() if line.startswith('KEY '))
    _, xy_hex, fw_id = key_line.split()
    xy = bytes.fromhex(xy_hex)
    key = ECC.construct(curve='P-256', point_x=int.from_bytes(xy[:32], 'big'),
                        point_y=int.from_bytes(xy[32:], 'big'))
    assert appmod.derive_device_id(key.export_key(format='PEM')) == fw_id
