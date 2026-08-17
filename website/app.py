from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import datetime
import bcrypt
import os
import secrets
from math import radians, sin, cos, asin, sqrt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    # Random fallback keeps the app safe to run without a .env, but sessions
    # won't survive restarts and multi-worker deployments need a fixed key.
    app.secret_key = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set, using a random key. Set it in .env for production.")

# Nonce challenge settings
NONCE_TTL_SECONDS = 15       # how long the browser has to answer the challenge
MAX_SCANNER_DISTANCE_M = 500 # max allowed distance between scanner and device

# v2 (signature) scheme: max age of a signed code, covering the device's
# 30s display cycle plus clock skew and the challenge round trip
CODE_FRESHNESS_SECONDS = 45

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Database connection helper function
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def parse_public_key_pem(pem):
    """Validate a device public key: must be a P-256 public key.
    Returns the normalized PEM, or None if invalid."""
    try:
        key = ECC.import_key(pem)
    except (ValueError, IndexError, TypeError):
        return None
    if key.has_private() or key.curve not in ('NIST P-256', 'p256'):
        return None
    return key.export_key(format='PEM')

def verify_device_signature(pubkey_pem, message: bytes, signature: bytes) -> bool:
    """Verify an ECDSA P-256 signature (raw r||s, 64 bytes) over message."""
    try:
        key = ECC.import_key(pubkey_pem)
        DSS.new(key, 'fips-186-3').verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError, IndexError):
        return False

def haversine_m(lat1, lng1, lat2, lng2):
    """Distance between two coordinates in meters."""
    lat1, lng1, lat2, lng2 = map(radians, (lat1, lng1, lat2, lng2))
    a = sin((lat2 - lat1) / 2) ** 2 + cos(lat1) * cos(lat2) * sin((lng2 - lng1) / 2) ** 2
    return 6371000 * 2 * asin(sqrt(a))

# Hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Verify a password
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'])
    return None

# Routes for login, register, and logout
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password are required'})
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and verify_password(password, user['password']):
        user_obj = User(user['id'], user['username'])
        login_user(user_obj)
        return jsonify({'success': True, 'username': user['username']})
    return jsonify({'success': False, 'error': 'Invalid username or password'})

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password or username == "unknown":
        return jsonify({'success': False, 'error': 'Username and password are required'})
    conn = get_db_connection()
    try:
        hashed_password = hash_password(password)
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Username already exists'})

@app.route('/check-login')
def check_login():
    if current_user.is_authenticated:
        return jsonify({'logged_in': True, 'username': current_user.username})
    return jsonify({'logged_in': False})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/api/my-inactive-devices')
@login_required
def get_my_inactive_devices():
    conn = get_db_connection()
    devices = conn.execute(
        '''SELECT device_id, lat, lng, max_validations, active
           FROM devices WHERE active = FALSE AND username = ?''',
        (current_user.username,)
    ).fetchall()
    conn.close()

    # Convert Row objects to dictionaries
    devices_list = [dict(device) for device in devices]
    return jsonify(devices_list)

@app.route('/api/my-devices')
@login_required
def get_my_devices():
    """All devices owned by current_user. Excludes pubkey."""
    conn = get_db_connection()
    devices = conn.execute(
        '''SELECT device_id, name, description, lat, lng, max_validations, active, timestamp
           FROM devices WHERE username = ?
           ORDER BY timestamp DESC''',
        (current_user.username,)
    ).fetchall()
    conn.close()
    return jsonify([dict(d) for d in devices])

@app.route('/api/my-validations')
@login_required
def get_my_validations():
    """Validation attempts made by current_user (as scanner)."""
    conn = get_db_connection()
    logs = conn.execute(
        '''SELECT timestamp, device_id, status, reason, scanner_lat, scanner_lng, code_ts
           FROM validation_logs WHERE username = ?
           ORDER BY timestamp DESC''',
        (current_user.username,)
    ).fetchall()
    conn.close()
    return jsonify([dict(log) for log in logs])

# Update validation logs to include username
def log_validation(device_id, status, reason, lat=None, lng=None, scanner_lat=None, scanner_lng=None, code_ts=None):
    username = current_user.username if current_user.is_authenticated else "unknown"
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO validation_logs (timestamp, device_id, status, reason, lat, lng, ip, username, scanner_lat, scanner_lng, code_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        device_id,
        status,
        reason,
        lat,
        lng,
        request.remote_addr,
        username,
        scanner_lat,
        scanner_lng,
        code_ts
    ))
    conn.commit()
    conn.close()

@app.route('/validation-logs/<device_id>', methods=['GET'])
def get_validation_logs(device_id):
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT timestamp, status, reason, username
        FROM validation_logs
        WHERE device_id = ?
        ORDER BY timestamp DESC
    ''', (device_id,)).fetchall()
    conn.close()
    return jsonify([dict(log) for log in logs])

@app.route('/', methods=['GET'])
def show_map():
    username = current_user.username if current_user.is_authenticated else "unknown"
    conn = get_db_connection()

    # Fetch devices that have at least one successful validation
    devices = conn.execute('''
    SELECT *
    FROM devices
    WHERE active = TRUE
    ''').fetchall()

    conn.close()
    return render_template('map.html', devices=devices, username=username)

@app.route('/v2/<device_id>/<payload_b64>/<sig_b64>', methods=['GET'])
def validate_signed(device_id, payload_b64, sig_b64):
    """
    Step 1 of the challenge flow. The QR carries a plaintext payload
    "ts|lat|lng" and an ECDSA P-256 signature over "device_id|ts|lat|lng".
    Opening the URL does NOT validate yet: the server issues a one-time
    nonce and renders the map in a pending state. The browser must answer
    via POST /validate/complete within NONCE_TTL_SECONDS, sending the
    nonce and (if permitted) its geolocation.
    """
    conn = get_db_connection()
    devices = conn.execute('''
        SELECT *
        FROM devices
        WHERE active = TRUE
        OR device_id = ?
    ''', (device_id,)).fetchall()
    device = conn.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,)).fetchone()

    username = current_user.username if current_user.is_authenticated else "unknown"

    if not device or not device['pubkey']:
        conn.close()
        log_validation(device_id, "failed", "Invalid Device ID" if not device else "Device Has No Public Key")
        return render_template('map.html', devices=devices, username=username,
                               status="Invalid Device ID", success="false")

    nonce = secrets.token_urlsafe(16)
    conn.execute(
        "INSERT INTO pending_validations (nonce, device_id, data_enc, created_at) VALUES (?, ?, ?, ?)",
        (nonce, device_id, payload_b64 + '.' + sig_b64,
         datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

    return render_template('map.html', devices=devices, username=username, nonce=nonce)

def complete_validation_v2(pending, device, scanner_lat, scanner_lng):
    """Step 2 of the challenge flow: verify signature, freshness and location."""
    device_id = pending['device_id']

    try:
        payload_b64, sig_b64 = pending['data_enc'].split('.')
        payload = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        signature = base64.urlsafe_b64decode(sig_b64)
        ts_str, esp_lat_str, esp_lng_str = payload.split('|')
        code_ts = int(ts_str)
        esp_lat = float(esp_lat_str)
        esp_lng = float(esp_lng_str)
    except (ValueError, IndexError, UnicodeDecodeError):
        log_validation(device_id, "failed", "Invalid Data Format", scanner_lat=scanner_lat, scanner_lng=scanner_lng)
        return jsonify({'success': False, 'status': 'Invalid Data Format'})

    # The signed message includes the device_id from the URL, so a signature
    # cannot be transplanted onto another device.
    message = f"{device_id}|{payload}".encode('utf-8')
    if not verify_device_signature(device['pubkey'], message, signature):
        log_validation(device_id, "failed", "Invalid Signature", esp_lat, esp_lng, scanner_lat, scanner_lng, code_ts)
        return jsonify({'success': False, 'status': 'Invalid Signature'})

    # Freshness: the signed timestamp replaces TOTP
    age = datetime.datetime.now().timestamp() - code_ts
    if age > CODE_FRESHNESS_SECONDS or age < -10:
        log_validation(device_id, "failed", "Code Expired", esp_lat, esp_lng, scanner_lat, scanner_lng, code_ts)
        return jsonify({'success': False, 'status': 'Code Expired'})

    # Scanner location cross-check, same policy as v1
    location_verified = False
    if scanner_lat is not None and scanner_lng is not None \
            and device['lat'] is not None and device['lng'] is not None:
        distance_m = haversine_m(float(scanner_lat), float(scanner_lng), device['lat'], device['lng'])
        if distance_m > MAX_SCANNER_DISTANCE_M:
            log_validation(device_id, "failed", f"Location Mismatch ({int(distance_m)}m away)",
                           esp_lat, esp_lng, scanner_lat, scanner_lng, code_ts)
            return jsonify({'success': False, 'status': 'Location Mismatch'})
        location_verified = True

    # max_validations counts per signed code (code_ts), not per wall-clock
    # cycle, so a boundary can never double the budget.
    conn = get_db_connection()
    validations_for_code = conn.execute(
        "SELECT COUNT(*) FROM validation_logs WHERE device_id = ? AND code_ts = ? AND status = 'success'",
        (device_id, code_ts)
    ).fetchone()[0]

    if validations_for_code >= device['max_validations']:
        conn.close()
        log_validation(device_id, "failed", "Max Validations Exceeded", esp_lat, esp_lng, scanner_lat, scanner_lng, code_ts)
        return jsonify({'success': False, 'status': 'Max Validations Exceeded'})

    reason = "Valid Signature" if location_verified else "Valid Signature (location unverified)"
    log_validation(device_id, "success", reason, esp_lat, esp_lng, scanner_lat, scanner_lng, code_ts)

    conn.execute('UPDATE devices SET active = TRUE WHERE device_id = ?', (device_id,))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'status': 'Valid Link' if location_verified else 'Valid Link (location unverified)',
        'device_id': device_id,
        'esp_lat': esp_lat,
        'esp_lng': esp_lng,
        'device_lat': device['lat'],
        'device_lng': device['lng'],
        'location_verified': location_verified
    })

@app.route('/validate/complete', methods=['POST'])
def complete_validation():
    """
    Step 2 of the challenge flow: consume the nonce and run the actual
    validation (signature, freshness, max_validations, scanner location).
    """
    data = request.get_json(silent=True) or {}
    nonce = data.get('nonce')
    scanner_lat = data.get('scanner_lat')
    scanner_lng = data.get('scanner_lng')

    if not nonce:
        return jsonify({'success': False, 'status': 'Missing Challenge'}), 400

    conn = get_db_connection()

    # Consume the nonce atomically: only one request can ever flip used 0 -> 1,
    # so a relayed/replayed completion loses the race.
    consumed = conn.execute(
        'UPDATE pending_validations SET used = 1 WHERE nonce = ? AND used = 0',
        (nonce,)
    )
    conn.commit()
    if consumed.rowcount == 0:
        conn.close()
        return jsonify({'success': False, 'status': 'Invalid or Reused Challenge'})

    pending = conn.execute('SELECT * FROM pending_validations WHERE nonce = ?', (nonce,)).fetchone()
    device = conn.execute('SELECT * FROM devices WHERE device_id = ?', (pending['device_id'],)).fetchone()
    conn.close()

    device_id = pending['device_id']

    issued_at = datetime.datetime.strptime(pending['created_at'], '%Y-%m-%d %H:%M:%S')
    if (datetime.datetime.utcnow() - issued_at).total_seconds() > NONCE_TTL_SECONDS:
        log_validation(device_id, "failed", "Challenge Expired", scanner_lat=scanner_lat, scanner_lng=scanner_lng)
        return jsonify({'success': False, 'status': 'Challenge Expired'})

    if not device:
        log_validation(device_id, "failed", "Invalid Device ID")
        return jsonify({'success': False, 'status': 'Invalid Device ID'})

    return complete_validation_v2(pending, device, scanner_lat, scanner_lng)

@app.route('/add-device', methods=['POST'])
@login_required  # Ensure the user is logged in
def add_device_route():
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You must be logged in to add a device.'})

    data = request.get_json()
    device_id = data.get('device_id')
    pubkey = data.get('pubkey')
    lat = data.get('lat')
    lng = data.get('lng')
    max_validations = data.get('max_validations')
    name = (data.get('name') or '').strip()[:80]
    description = (data.get('description') or '').strip()[:200]

    if not device_id or not pubkey:
        return jsonify({'success': False, 'message': 'Device ID and public key are required.'})

    pubkey = parse_public_key_pem(pubkey)
    if not pubkey:
        return jsonify({'success': False, 'message': 'Invalid public key (expecting a P-256 public key in PEM format).'})

    # Validate max_validations
    try:
        max_validations = int(max_validations)
        if max_validations < 1:
            max_validations = 1  # Default to 1 if invalid
    except (TypeError, ValueError):
        max_validations = 1  # Default to 1 if missing or invalid

    # Check if the device_id already exists
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT device_id FROM devices WHERE device_id = ?', (device_id,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Device ID already exists. Please try again.'})

    try:
        add_device(device_id, '', lat, lng, max_validations, current_user.username, pubkey,
                   name=name, description=description)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

def add_device(device_id, secret='', lat=None, lng=None, max_validations=1, username=None, pubkey=None,
               name='', description=''):
    """
    Adds a device to the database.

    :param device_id: Unique ID of the device.
    :param secret: Unused, accepted only for backward compatibility.
    :param lat: Latitude of the device's location (optional).
    :param lng: Longitude of the device's location (optional).
    :param max_validations: Max validations per signed code.
    :param username: Username of the user who added the device.
    :param pubkey: ECDSA P-256 public key in PEM format.
    :param name: Owner-editable display name (optional).
    :param description: Owner-editable description (optional).
    """
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO devices (device_id, lat, lng, max_validations, username, pubkey, name, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (device_id, lat, lng, max_validations, username, pubkey, name, description))
    conn.commit()
    conn.close()
    print(f"Device '{device_id}' added successfully by user '{username}'.")

@app.route('/update-device/<device_id>', methods=['PUT'])
@login_required
def update_device(device_id):
    """Owner-only partial update of device metadata."""
    data = request.get_json(silent=True) or {}

    conn = get_db_connection()
    device = conn.execute('SELECT username FROM devices WHERE device_id = ?', (device_id,)).fetchone()
    if not device:
        conn.close()
        return jsonify({'success': False, 'message': 'Device not found.'})
    if device['username'] != current_user.username:
        conn.close()
        return jsonify({'success': False, 'message': 'You are not the owner of this device.'})

    fields = []
    values = []

    if 'name' in data:
        fields.append('name = ?')
        values.append((data.get('name') or '').strip()[:80])
    if 'description' in data:
        fields.append('description = ?')
        values.append((data.get('description') or '').strip()[:200])
    if 'lat' in data:
        try:
            fields.append('lat = ?')
            values.append(float(data['lat']) if data['lat'] is not None else None)
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid lat.'})
    if 'lng' in data:
        try:
            fields.append('lng = ?')
            values.append(float(data['lng']) if data['lng'] is not None else None)
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid lng.'})
    if 'max_validations' in data:
        try:
            mv = int(data['max_validations'])
            if mv < 1:
                mv = 1
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid max_validations.'})
        fields.append('max_validations = ?')
        values.append(mv)
    if 'active' in data:
        fields.append('active = ?')
        values.append(1 if data['active'] else 0)

    if not fields:
        conn.close()
        return jsonify({'success': False, 'message': 'No updatable fields provided.'})

    values.append(device_id)
    try:
        conn.execute(f'UPDATE devices SET {", ".join(fields)} WHERE device_id = ?', values)
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

@app.route('/my-devices', methods=['GET'])
@login_required
def my_devices_page():
    return render_template('my_devices.html', username=current_user.username)

@app.route('/my-validations', methods=['GET'])
@login_required
def my_validations_page():
    return render_template('my_validations.html', username=current_user.username)

@app.route('/devices/<device_id>/history', methods=['GET'])
def device_history_page(device_id):
    conn = get_db_connection()
    device = conn.execute(
        'SELECT device_id, name, description, lat, lng, active, username FROM devices WHERE device_id = ?',
        (device_id,)
    ).fetchone()
    conn.close()
    username = current_user.username if current_user.is_authenticated else "unknown"
    return render_template(
        'device_history.html',
        device=dict(device) if device else None,
        device_id=device_id,
        username=username,
    )

@app.route('/delete-device/<device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You must be logged in to delete a device.'})

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the device exists and is owned by the current user
    cursor.execute('SELECT username FROM devices WHERE device_id = ?', (device_id,))
    device = cursor.fetchone()
    if not device:
        conn.close()
        return jsonify({'success': False, 'message': 'Device not found.'})
    if device[0] != current_user.username:
        conn.close()
        return jsonify({'success': False, 'message': 'You are not the owner of this device.'})

    # Delete the device
    try:
        cursor.execute('DELETE FROM devices WHERE device_id = ?', (device_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

if __name__ == '__main__':
    # Dev server only — use gunicorn in production (see README).
    app.run(host='0.0.0.0', port=5005, debug=os.environ.get('FLASK_DEBUG') == '1')