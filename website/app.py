from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import pyotp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
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

def decrypt_totp(key, cipher_text):
    key = key.encode('utf-8').ljust(32, b'\0')[:32]
    iv_and_ciphertext = base64.urlsafe_b64decode(cipher_text)
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plain_text.decode('utf-8')

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
        'SELECT * FROM devices WHERE active = FALSE AND username = ?',
        (current_user.username,)
    ).fetchall()
    conn.close()
    
    # Convert Row objects to dictionaries
    devices_list = [dict(device) for device in devices]
    return jsonify(devices_list)

# Update validation logs to include username
def log_validation(device_id, status, reason, lat=None, lng=None, scanner_lat=None, scanner_lng=None):
    username = current_user.username if current_user.is_authenticated else "unknown"
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO validation_logs (timestamp, device_id, status, reason, lat, lng, ip, username, scanner_lat, scanner_lng)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        scanner_lng
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

@app.route('/<device_id>/<data_enc>', methods=['GET'])
def validate_totp(device_id, data_enc):
    """
    Step 1 of the challenge flow: opening the QR URL does NOT validate yet.
    The server issues a one-time nonce and renders the map in a pending
    state. The browser must answer via POST /validate/complete within
    NONCE_TTL_SECONDS, sending the nonce and (if permitted) its geolocation.
    """
    conn = get_db_connection()
    devices = conn.execute('''
        SELECT *
        FROM devices
        WHERE active = TRUE
        OR device_id = ?
    ''', (device_id,)).fetchall()
    device = conn.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,)).fetchone()

    if not device:
        conn.close()
        log_validation(device_id, "failed", "Invalid Device ID")
        return render_template('map.html', devices=devices, status="Invalid Device ID", success="false")

    nonce = secrets.token_urlsafe(16)
    conn.execute(
        'INSERT INTO pending_validations (nonce, device_id, data_enc, created_at) VALUES (?, ?, ?, ?)',
        (nonce, device_id, data_enc, datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

    return render_template('map.html', devices=devices, nonce=nonce)

@app.route('/validate/complete', methods=['POST'])
def complete_validation():
    """
    Step 2 of the challenge flow: consume the nonce and run the actual
    validation (decrypt, TOTP, max_validations, scanner location check).
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

    try:
        decrypted_data = decrypt_totp(device['secret'], pending['data_enc'])
    except Exception:
        log_validation(device_id, "failed", "Decryption Error", scanner_lat=scanner_lat, scanner_lng=scanner_lng)
        return jsonify({'success': False, 'status': 'Invalid Data Encryption'})

    try:
        totp_number, esp_lat, esp_lng = decrypted_data.split('|')
        esp_lat = float(esp_lat)
        esp_lng = float(esp_lng)
    except (ValueError, IndexError):
        log_validation(device_id, "failed", "Invalid Data Format", scanner_lat=scanner_lat, scanner_lng=scanner_lng)
        return jsonify({'success': False, 'status': 'Invalid Decrypted Data Format'})

    # Get the current TOTP cycle start time
    totp = pyotp.TOTP(device['secret'])
    current_time = datetime.datetime.now()
    time_step = totp.interval
    cycle_start = current_time.timestamp() - (current_time.timestamp() % time_step)
    cycle_start_str = datetime.datetime.utcfromtimestamp(cycle_start).strftime('%Y-%m-%d %H:%M:%S')

    # valid_window=1 tolerates the challenge round trip crossing a cycle boundary
    if not totp.verify(totp_number, valid_window=1):
        log_validation(device_id, "failed", "Invalid TOTP", esp_lat, esp_lng, scanner_lat, scanner_lng)
        return jsonify({'success': False, 'status': 'Invalid Link'})

    # Cross-check the scanner's browser geolocation against the registered
    # device location. No geolocation (denied/unavailable) downgrades the
    # validation instead of failing it; a clear mismatch fails.
    location_verified = False
    if scanner_lat is not None and scanner_lng is not None \
            and device['lat'] is not None and device['lng'] is not None:
        distance_m = haversine_m(float(scanner_lat), float(scanner_lng), device['lat'], device['lng'])
        if distance_m > MAX_SCANNER_DISTANCE_M:
            log_validation(device_id, "failed", f"Location Mismatch ({int(distance_m)}m away)",
                           esp_lat, esp_lng, scanner_lat, scanner_lng)
            return jsonify({'success': False, 'status': 'Location Mismatch'})
        location_verified = True

    conn = get_db_connection()
    validations_in_cycle = conn.execute(
        'SELECT COUNT(*) FROM validation_logs WHERE device_id = ? AND timestamp >= ? AND status = "success"',
        (device_id, cycle_start_str)
    ).fetchone()[0]

    if validations_in_cycle >= device['max_validations']:
        conn.close()
        log_validation(device_id, "failed", "Max Validations Exceeded", esp_lat, esp_lng, scanner_lat, scanner_lng)
        return jsonify({'success': False, 'status': 'Max Validations Exceeded'})

    reason = "Valid TOTP" if location_verified else "Valid TOTP (location unverified)"
    log_validation(device_id, "success", reason, esp_lat, esp_lng, scanner_lat, scanner_lng)

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

@app.route('/add-device', methods=['POST'])
@login_required  # Ensure the user is logged in
def add_device_route():
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'You must be logged in to add a device.'})

    data = request.get_json()
    device_id = data.get('device_id')
    secret = data.get('secret')
    lat = data.get('lat')
    lng = data.get('lng')
    max_validations = data.get('max_validations')

    if not device_id or not secret:
        return jsonify({'success': False, 'message': 'Device ID and secret are required.'})

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
        add_device(device_id, secret, lat, lng, max_validations, current_user.username)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

def add_device(device_id, secret, lat=None, lng=None, max_validations=1, username=None):
    """
    Adds a device to the database.
    
    :param device_id: Unique ID of the device.
    :param secret: TOTP secret for the device.
    :param lat: Latitude of the device's location (optional).
    :param lng: Longitude of the device's location (optional).
    :param max_validations: Max validations per window.
    :param username: Username of the user who added the device.
    """
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO devices (device_id, secret, lat, lng, max_validations, username)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (device_id, secret, lat, lng, max_validations, username))
    conn.commit()
    conn.close()
    print(f"Device '{device_id}' added successfully by user '{username}'.")

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