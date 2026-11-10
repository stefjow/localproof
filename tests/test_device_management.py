"""End-to-end tests for owner device management (my-devices, update-device, my-validations)."""
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


def register_and_login(client, username, password='pw'):
    client.post('/register', data={'username': username, 'password': password})
    resp = client.post('/login', data={'username': username, 'password': password}).get_json()
    assert resp['success']


def logout(client):
    client.get('/logout')


def add_device_with_key(client, **extra):
    """Register a fresh device and return (device_id, private_key).
    The server derives device_id from the pubkey."""
    key = ECC.generate(curve='P-256')
    pem = key.public_key().export_key(format='PEM')
    body = {'pubkey': pem, 'lat': DEV_LAT, 'lng': DEV_LNG, 'max_validations': 1}
    body.update(extra)
    resp = client.post('/add-device', json=body).get_json()
    assert resp['success'] is True, resp
    return resp['device_id'], key


def validate_once(client, device_id, key):
    ts = int(time.time())
    p64, s64 = sign_payload(key, device_id, ts, DEV_LAT, DEV_LNG)
    resp = client.get(f'/v2/{device_id}/{p64}/{s64}')
    m = re.search(r"nonce: '([^']+)'", resp.get_data(as_text=True))
    assert m, resp.get_data(as_text=True)[:1000]
    result = client.post('/validate/complete', json={
        'nonce': m.group(1), 'scanner_lat': DEV_LAT, 'scanner_lng': DEV_LNG}).get_json()
    assert result['success'] is True, result
    return result


# -- update-device --------------------------------------------------------

def test_update_device_requires_login(client):
    resp = client.put('/update-device/AB12', json={'name': 'x'})
    assert resp.status_code in (302, 401)


def test_owner_can_update_name_and_description(client):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    resp = client.put(f'/update-device/{device_id}',
                      json={'name': 'Front door', 'description': 'Reception'}).get_json()
    assert resp['success'] is True
    devices = client.get('/api/my-devices').get_json()
    assert devices[0]['name'] == 'Front door'
    assert devices[0]['description'] == 'Reception'


def test_owner_can_update_max_validations(client):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    resp = client.put(f'/update-device/{device_id}', json={'max_validations': 7}).get_json()
    assert resp['success'] is True
    devices = client.get('/api/my-devices').get_json()
    assert devices[0]['max_validations'] == 7


def test_owner_toggle_active_hides_from_map(client):
    register_and_login(client, 'alice')
    device_id, key = add_device_with_key(client)
    validate_once(client, device_id, key)  # flips active=TRUE

    # active=TRUE -> shows on map
    body = client.get('/').get_data(as_text=True)
    assert device_id in body

    resp = client.put(f'/update-device/{device_id}', json={'active': False}).get_json()
    assert resp['success'] is True

    body = client.get('/').get_data(as_text=True)
    assert device_id not in body  # deactivated devices are hidden

    # re-activate
    resp = client.put(f'/update-device/{device_id}', json={'active': True}).get_json()
    assert resp['success'] is True
    body = client.get('/').get_data(as_text=True)
    assert device_id in body


def test_max_validations_below_1_is_clamped(client):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    resp = client.put(f'/update-device/{device_id}', json={'max_validations': 0}).get_json()
    assert resp['success'] is True
    devices = client.get('/api/my-devices').get_json()
    assert devices[0]['max_validations'] == 1


def test_non_owner_cannot_update(client):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    logout(client)
    register_and_login(client, 'bob')
    resp = client.put(f'/update-device/{device_id}', json={'name': 'hijack'}).get_json()
    assert resp['success'] is False
    assert 'owner' in resp['message'].lower()


def test_update_nonexistent_device(client):
    register_and_login(client, 'alice')
    resp = client.put('/update-device/NOPE', json={'name': 'x'}).get_json()
    assert resp['success'] is False


def test_empty_update_rejected(client):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    resp = client.put(f'/update-device/{device_id}', json={}).get_json()
    assert resp['success'] is False


# -- my-devices -----------------------------------------------------------

def test_my_devices_requires_login(client):
    resp = client.get('/api/my-devices')
    assert resp.status_code in (302, 401)


def test_my_devices_only_shows_own_and_no_pubkey(client):
    register_and_login(client, 'alice')
    add_device_with_key(client)
    logout(client)
    register_and_login(client, 'bob')
    bob_id, _ = add_device_with_key(client)

    devices = client.get('/api/my-devices').get_json()
    assert [d['device_id'] for d in devices] == [bob_id]
    assert 'pubkey' not in devices[0]
    assert 'secret' not in devices[0]


def test_my_devices_includes_metadata(client):
    register_and_login(client, 'alice')
    add_device_with_key(client, name='My Rig', description='Test bench')
    devices = client.get('/api/my-devices').get_json()
    assert devices[0]['name'] == 'My Rig'
    assert devices[0]['description'] == 'Test bench'
    assert devices[0]['active'] in (0, False)


# -- my-validations -------------------------------------------------------

def test_my_validations_requires_login(client):
    resp = client.get('/api/my-validations')
    assert resp.status_code in (302, 401)


def test_my_validations_filters_by_username_and_orders_desc(client):
    register_and_login(client, 'alice')
    alice_id, key_a = add_device_with_key(client)
    validate_once(client, alice_id, key_a)
    logout(client)

    register_and_login(client, 'bob')
    bob_id, key_b = add_device_with_key(client)
    validate_once(client, bob_id, key_b)

    rows = client.get('/api/my-validations').get_json()
    assert all(r['device_id'] == bob_id for r in rows)
    assert all(r['status'] == 'success' for r in rows)
    timestamps = [r['timestamp'] for r in rows]
    assert timestamps == sorted(timestamps, reverse=True)


# -- add-device with name/description -------------------------------------

def test_add_device_accepts_optional_metadata(client):
    register_and_login(client, 'alice')
    add_device_with_key(client, name='Front door', description='Reception')
    devices = client.get('/api/my-devices').get_json()
    assert devices[0]['name'] == 'Front door'
    assert devices[0]['description'] == 'Reception'


# -- coordinates -------------------------------------------------------------
# The map page writes device coordinates into its script, so the server only
# stores real numbers in range.

@pytest.mark.parametrize('lat,lng', [
    ('0,alert(1)', DEV_LNG),      # a string would be stored as text
    (DEV_LAT, '<script>'),
    (91, DEV_LNG),                # MapLibre throws on these
    (DEV_LAT, -343.6237),
    (float('nan'), DEV_LNG),
    (DEV_LAT, float('inf')),
])
def test_add_device_rejects_bad_coordinates(client, lat, lng):
    register_and_login(client, 'alice')
    pem = ECC.generate(curve='P-256').public_key().export_key(format='PEM')
    resp = client.post('/add-device', json={
        'pubkey': pem, 'lat': lat, 'lng': lng, 'max_validations': 1}).get_json()
    assert resp['success'] is False
    assert client.get('/api/my-devices').get_json() == []


def test_add_device_without_position_still_allowed(client):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client, lat=None, lng=None)
    d = client.get('/api/my-devices').get_json()[0]
    assert d['device_id'] == device_id
    assert d['lat'] is None and d['lng'] is None


@pytest.mark.parametrize('field,value', [
    ('lat', 91), ('lat', 'north'), ('lat', float('nan')),
    ('lng', 181), ('lng', -343.6237), ('lng', float('inf')),
])
def test_update_device_rejects_bad_coordinates(client, field, value):
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    resp = client.put(f'/update-device/{device_id}', json={field: value}).get_json()
    assert resp['success'] is False
    d = client.get('/api/my-devices').get_json()[0]
    assert (d['lat'], d['lng']) == (DEV_LAT, DEV_LNG)


def test_map_page_survives_a_text_coordinate_row(client):
    """A row written before the check existed must not reach the script."""
    register_and_login(client, 'alice')
    device_id, _ = add_device_with_key(client)
    import sqlite3
    conn = sqlite3.connect('database.db')
    conn.execute("UPDATE devices SET active = 1, lat = '0,window.pwned=1' WHERE device_id = ?",
                 (device_id,))
    conn.commit()
    conn.close()
    page = client.get('/').get_data(as_text=True)
    assert 'pwned' not in page


# -- what the scan result card is drawn from ---------------------------------

def scan(client, device_id, key, **scanner):
    p64, s64 = sign_payload(key, device_id, int(time.time()), DEV_LAT, DEV_LNG)
    page = client.get(f'/v2/{device_id}/{p64}/{s64}').get_data(as_text=True)
    nonce = re.search(r"nonce: '([^']+)'", page).group(1)
    return client.post('/validate/complete', json={'nonce': nonce, **scanner}).get_json()


def test_scan_result_names_the_device_and_gives_the_distance(client):
    register_and_login(client, 'alice')
    device_id, key = add_device_with_key(client, name='Front door')
    # about 111 m north of the device
    result = scan(client, device_id, key, scanner_lat=DEV_LAT + 0.001, scanner_lng=DEV_LNG)
    assert result['success'] is True
    assert result['device_id'] == device_id
    assert result['device_name'] == 'Front door'
    assert 105 <= result['distance_m'] <= 115
    assert result['token_rtt_us'] is None


def test_scan_without_location_has_no_distance(client):
    register_and_login(client, 'alice')
    device_id, key = add_device_with_key(client)
    result = scan(client, device_id, key)
    assert result['success'] is True
    assert result['location_verified'] is False
    assert result['distance_m'] is None


def test_location_mismatch_says_how_far_and_where_the_device_is(client):
    register_and_login(client, 'alice')
    device_id, key = add_device_with_key(client, name='Front door')
    # about 2.2 km north of the device
    result = scan(client, device_id, key, scanner_lat=DEV_LAT + 0.02, scanner_lng=DEV_LNG)
    assert result['success'] is False
    assert result['status'] == 'Location Mismatch'
    assert result['device_name'] == 'Front door'
    assert 2100 <= result['distance_m'] <= 2300
    assert (result['device_lat'], result['device_lng']) == (DEV_LAT, DEV_LNG)


def test_scan_page_names_the_scanned_device(client):
    register_and_login(client, 'alice')
    device_id, key = add_device_with_key(client, name='Front <b>door</b>')
    p64, s64 = sign_payload(key, device_id, int(time.time()), DEV_LAT, DEV_LNG)
    page = client.get(f'/v2/{device_id}/{p64}/{s64}').get_data(as_text=True)
    assert f'"device_id": "{device_id}"' in page
    assert '<b>door</b>' not in page  # JSON-encoded for the script, not raw

