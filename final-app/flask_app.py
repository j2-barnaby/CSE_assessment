import os
import re
import uuid
import base64
import sqlite3
import logging
from io import BytesIO
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename

# STEP 1 CHANGE (F-03 / F-04, ASD STIG V-222604, V-222511):
# Removed the hard-coded Fernet key and the start-up code that sourced
# ~/.bashrc, decrypted $API_CHECK and executed it with subprocess(shell=True).
# That payload exfiltrated encryption keys from the log to canarytokens.com.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# STEP 2 CHANGE (F-05 / F-06 / F-13): files are no longer written to /tmp.
# They go to a dedicated directory backed by a named Docker volume, so they
# survive restarts and cannot collide with other temporary files.
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "files.db")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
MAX_NAME_LEN = 200

app = Flask(__name__)
# STEP 2 CHANGE (F-13, ASD V-222606 / Web SRG V-206433): reject oversized
# uploads before they are read into memory (denial-of-service protection).
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

UUID_RE = re.compile(r"^[0-9a-f]{32}$")

# NOTE: logging is replaced with STIG-compliant audit logging in Step 5.
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
                    handlers=[
                        logging.FileHandler("/app/logs/flask_app.log"),
                        logging.StreamHandler()
                    ])


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_storage():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id            TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                size_bytes    INTEGER NOT NULL,
                created_at    TEXT NOT NULL
            )""")


def blob_path(file_id):
    # file_id is always a server-generated UUID (validated), never user input,
    # so the path cannot escape DATA_DIR (fixes F-06 path traversal).
    return os.path.join(DATA_DIR, f"{file_id}.enc")


def clean_filename(name):
    # STEP 2 CHANGE (F-06 / F-12, ASD V-222606, V-222609): the user's filename
    # is only kept as a display label. secure_filename strips path separators,
    # "..", and unsafe characters; length is capped.
    name = secure_filename(name or "") or "file"
    if len(name) > MAX_NAME_LEN:
        root, ext = os.path.splitext(name)
        name = root[:MAX_NAME_LEN - len(ext)] + ext
    return name


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
# STEP 2 CHANGE (F-01, ASD V-222587 / Web SRG data-at-rest):
# The original used XOR with a 1-byte key (only 256 possible keys - trivially
# brute-forced). Replaced with AES-256-GCM, a NIST-approved algorithm
# (FIPS 197 / SP 800-38D) that provides confidentiality AND integrity.
#  - a fresh random 256-bit key per file
#  - a fresh random 96-bit nonce per encryption (never reused with a key)
#  - the file ID is bound in as associated data, so a ciphertext cannot be
#    swapped onto another file record without detection
# The key is returned to the user ONCE and is never stored or logged by the
# server, so a stolen disk / volume reveals nothing (F-02).
# Accepted risk: algorithm is FIPS-approved, but the OpenSSL module inside
# python-cryptography is not running in FIPS-validated mode (see POA&M).
def encrypt_bytes(plaintext, file_id):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, file_id.encode())
    return key, nonce + ciphertext


def decrypt_bytes(blob, key, file_id):
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, file_id.encode())


def encode_key(key):
    return base64.urlsafe_b64encode(key).decode()


def decode_key(text):
    try:
        key = base64.urlsafe_b64decode(text.strip().encode())
    except Exception:
        return None
    return key if len(key) == 32 else None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file is None:
        return jsonify({"error": "No file provided"}), 400

    display_name = clean_filename(file.filename)
    data = file.read()
    file_id = uuid.uuid4().hex

    key, blob = encrypt_bytes(data, file_id)

    # O_EXCL: never overwrite an existing file; 0600: owner-only permissions
    fd = os.open(blob_path(file_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(blob)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO files (id, original_name, size_bytes, created_at) VALUES (?, ?, ?, ?)",
            (file_id, display_name, len(data), datetime.now(timezone.utc).isoformat()))

    # STEP 2 CHANGE (F-02): no key and no server path in the log
    app.logger.info(f'File encrypted id={file_id} name={display_name} size={len(data)}')

    # STEP 2 CHANGE (F-02): no internal path disclosed; key shown once only
    resp = jsonify({
        "message": "File encrypted and stored. Save this key - it cannot be recovered.",
        "file_id": file_id,
        "filename": display_name,
        "encryption_key": encode_key(key),
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200


@app.route('/decrypt', methods=['GET'])
def decrypt_form():
    with get_db() as conn:
        files = conn.execute(
            "SELECT id, original_name, created_at FROM files ORDER BY created_at DESC").fetchall()
    return render_template('decrypt.html', files=files)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    file_id = (request.form.get('file_id') or '').strip()
    key = decode_key(request.form.get('key') or '')

    if not UUID_RE.match(file_id) or key is None:
        return jsonify({"error": "Invalid file or key format"}), 400

    with get_db() as conn:
        row = conn.execute("SELECT original_name FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None or not os.path.exists(blob_path(file_id)):
        return jsonify({"error": "File not found"}), 404

    with open(blob_path(file_id), 'rb') as f:
        blob = f.read()

    try:
        plaintext = decrypt_bytes(blob, key, file_id)
    except InvalidTag:
        app.logger.warning(f'Decryption failed id={file_id}')
        return jsonify({"error": "Decryption failed: wrong key or file has been tampered with"}), 400

    app.logger.info(f'File decrypted id={file_id}')
    return send_file(BytesIO(plaintext), as_attachment=True,
                     download_name=row['original_name'])


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": f"File too large (max {MAX_UPLOAD_MB} MB)"}), 413


init_storage()

# STEP 3 CHANGE (F-07 / F-08): in the container the app is served by gunicorn
# on a Unix socket (see flask_dockerfile), not the Flask development server.
# This block is only for local development and binds to loopback only.
if __name__ == "__main__":
    app.run(host='127.0.0.1')
