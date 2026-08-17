import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    pubkey TEXT,
    lat REAL,
    lng REAL,
    max_validations INTEGER,
    username TEXT,
    active BOOLEAN DEFAULT FALSE,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# Create a table for validation logs
cursor.execute('''
CREATE TABLE IF NOT EXISTS validation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    lat REAL,
    lng REAL,
    ip TEXT,
    username TEXT
)
''')

# Create a table for users
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
''')

# Create a table for pending validation challenges (nonces).
# A row is created when a QR URL is opened and consumed exactly once
# when the browser completes the challenge via /validate/complete.
cursor.execute('''
CREATE TABLE IF NOT EXISTS pending_validations (
    nonce TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    data_enc TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used INTEGER DEFAULT 0
)
''')

# Migrations (no-ops on fresh databases):
# - scanner location and signed-code timestamp columns on validation_logs
# - ECDSA public key (PEM) on devices for the signature scheme
for table, column in (
    ('validation_logs', 'scanner_lat REAL'),
    ('validation_logs', 'scanner_lng REAL'),
    ('validation_logs', 'code_ts INTEGER'),
    ('devices', 'pubkey TEXT'),
):
    try:
        cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column}')
    except sqlite3.OperationalError:
        pass  # column already exists

# v1 (AES+TOTP) teardown: drop its leftover columns from older databases
for table, column in (
    ('devices', 'secret'),
    ('pending_validations', 'scheme'),
):
    try:
        cursor.execute(f'ALTER TABLE {table} DROP COLUMN {column}')
    except sqlite3.OperationalError:
        pass  # column already gone

# Commit changes and close the connection
conn.commit()
conn.close()