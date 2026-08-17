import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
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

# Add scanner location columns to validation_logs (no-op on fresh databases,
# migrates existing ones)
for column in ('scanner_lat REAL', 'scanner_lng REAL'):
    try:
        cursor.execute(f'ALTER TABLE validation_logs ADD COLUMN {column}')
    except sqlite3.OperationalError:
        pass  # column already exists

# Commit changes and close the connection
conn.commit()
conn.close()