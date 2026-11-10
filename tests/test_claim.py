"""Claiming a logged-out scan by logging in afterwards.

A scan made while logged out is logged as "unknown". The browser that made
it keeps a note in its session, and logging in within CLAIM_WINDOW_SECONDS
attributes the validation to that account.
"""
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
    for name in ('alice', 'bob'):
        appmod.app.test_client().post('/register', data={'username': name, 'password': 'pw'})
    return appmod.app.test_client()


def login(client, username):
    resp = client.post('/login', data={'username': username, 'password': 'pw'}).get_json()
    assert resp['success'] is True
    return resp


def scan(client, ts=None, token_id=None, rtt_us=None, **scanner):
    scanner = scanner or {'scanner_lat': DEV_LAT, 'scanner_lng': DEV_LNG}
    p64, s64 = sign_payload(DEVICE_KEY, DEVICE_ID, ts or int(time.time()), DEV_LAT, DEV_LNG,
                            token_id=token_id, rtt_us=rtt_us)
    page = client.get(f'/v2/{DEVICE_ID}/{p64}/{s64}').get_data(as_text=True)
    nonce = re.search(r"nonce: '([^']+)'", page).group(1)
    return client.post('/validate/complete', json={'nonce': nonce, **scanner}).get_json()


def scanners():
    """Who each successful validation is logged for, oldest first."""
    conn = appmod.get_db_connection()
    rows = conn.execute("SELECT username FROM validation_logs WHERE status = 'success' ORDER BY id").fetchall()
    conn.close()
    return [r['username'] for r in rows]


def test_logging_in_claims_the_scan(client):
    assert scan(client)['success'] is True
    assert scanners() == ['unknown']
    assert login(client, 'alice')['claimed'] == 1
    assert scanners() == ['alice']
    mine = client.get('/api/my-validations').get_json()
    assert [v['device_id'] for v in mine] == [DEVICE_ID]


def test_login_without_a_scan_claims_nothing(client):
    assert login(client, 'alice')['claimed'] == 0


def test_another_browser_cannot_claim_it(client):
    assert scan(client)['success'] is True
    other = appmod.app.test_client()
    assert login(other, 'bob')['claimed'] == 0
    assert scanners() == ['unknown']


def test_claim_expires(client, monkeypatch):
    assert scan(client)['success'] is True
    monkeypatch.setattr(appmod, 'CLAIM_WINDOW_SECONDS', -1)
    assert login(client, 'alice')['claimed'] == 0
    assert scanners() == ['unknown']


def test_a_scan_is_claimed_once(client):
    assert scan(client)['success'] is True
    assert login(client, 'alice')['claimed'] == 1
    client.get('/logout')
    assert login(client, 'bob')['claimed'] == 0
    assert scanners() == ['alice']


def test_failed_scan_is_not_claimable(client):
    result = scan(client, scanner_lat=DEV_LAT + 0.02, scanner_lng=DEV_LNG)
    assert result['status'] == 'Location Mismatch'
    assert login(client, 'alice')['claimed'] == 0
    assert client.get('/api/my-validations').get_json() == []


def test_scans_made_while_logged_in_are_left_alone(client):
    login(client, 'alice')
    assert scan(client)['success'] is True
    client.get('/logout')
    assert login(client, 'bob')['claimed'] == 0
    assert scanners() == ['alice']


def test_several_scans_are_all_claimed(client):
    now = int(time.time())
    assert scan(client, ts=now - 2)['success'] is True
    assert scan(client, ts=now)['success'] is True
    assert login(client, 'alice')['claimed'] == 2
    assert scanners() == ['alice', 'alice']


def test_code_already_credited_by_token_upload_is_not_claimed_twice(client):
    """Alice's token uploaded the code; her logged-out scan of the same QR
    must not become a second validation for her."""
    login(client, 'alice')
    pem = ECC.generate(curve='P-256').public_key().export_key(format='PEM')
    token_id = client.post('/add-token', json={'pubkey': pem}).get_json()['token_id']
    client.get('/logout')
    ts = int(time.time())
    p64, s64 = sign_payload(DEVICE_KEY, DEVICE_ID, ts, DEV_LAT, DEV_LNG, token_id=token_id, rtt_us=2000)
    upload = client.post('/api/token-proof', json={'device_id': DEVICE_ID, 'payload': p64, 'sig': s64}).get_json()
    assert upload['success'] is True
    assert scan(client, ts=ts, token_id=token_id, rtt_us=2000)['success'] is True
    assert scanners() == ['alice', 'unknown']
    assert login(client, 'alice')['claimed'] == 0
    assert scanners() == ['alice', 'unknown']
