import os
import re
import sys
import json
import time
import uuid
import atexit
import base64
import sqlite3
import logging
from io import BytesIO
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template, request, send_file, jsonify, g
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# STEP 1 CHANGE (F-03 / F-04, ASD STIG V-222604, V-222511):
# Removed the hard-coded Fernet key and the start-up code that sourced
# ~/.bashrc, decrypted $API_CHECK and executed it with subprocess(shell=True).
# That payload exfiltrated encryption keys from the log to canarytokens.com.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# STEP 2 CHANGE (F-05 / F-06 / F-13): files are no longer written to /tmp.
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "files.db")
LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
AUDIT_LOG = os.path.join(LOG_DIR, "audit.log")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
MAX_NAME_LEN = 200
APP_VERSION = "2.0.0"

app = Flask(__name__)
# STEP 2 CHANGE (F-13, ASD V-222606 / Web SRG V-206433)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# STEP 5 CHANGE (F-14, ASD V-222470): trust exactly ONE proxy hop (nginx) for
# the client address. Flask is only reachable through nginx's Unix socket, so
# the X-Forwarded-For value nginx sets cannot be spoofed by a client.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

UUID_RE = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------------------
# STEP 5 CHANGE (F-14): STIG-compliant audit logging
# ---------------------------------------------------------------------------
# The original logged free text at DEBUG level, included the encryption key
# (F-02) and recorded neither destination address nor startup/shutdown.
#
# Every audit record is now one JSON object per line containing:
#   when     timestamp (UTC, ISO 8601, ms)          ASD V-222441/V-222442
#   what     event type + outcome (success/failure) ASD V-222443/V-222444/V-222445
#   where    destination IP:port and request path   ASD V-222470
#   source   client IP (from nginx)                 ASD V-222446/V-222447
#   who      user identity (anonymous until Step 6) ASD V-222448
#   request_id  correlates with the nginx access log
# JSON encoding escapes newlines/control characters, so a malicious filename
# or User-Agent cannot forge extra log lines (log injection).
# Keys, file contents and passwords are NEVER logged.
class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc)
                          .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
            "outcome": getattr(record, "outcome", None),
            "pid": record.process,
        }
        entry.update(getattr(record, "fields", {}))
        return json.dumps({k: v for k, v in entry.items() if v is not None})


def setup_audit_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    # STEP 5 CHANGE (ASD V-222500/V-222501): log file readable and writable
    # by the application account only (Step 4 retest showed -rw-r--r--).
    if not os.path.exists(AUDIT_LOG):
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
    os.chmod(AUDIT_LOG, 0o600)

    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)          # INFO, not DEBUG
    logger.propagate = False
    formatter = JsonFormatter()
    for handler in (logging.FileHandler(AUDIT_LOG), logging.StreamHandler(sys.stdout)):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


audit = setup_audit_logger()


def audit_event(event, outcome="success", level=logging.INFO, **fields):
    """Write one audit record. Request context is added automatically."""
    try:
        ctx = {
            "user": getattr(g, "user", None) or "anonymous",
            "src_ip": request.remote_addr,
            "dst": request.headers.get("X-Server-Addr"),
            "method": request.method,
            "path": request.path,
            "request_id": getattr(g, "request_id", None),
        }
    except RuntimeError:          # outside a request (startup / shutdown)
        ctx = {}
    ctx.update(fields)
    audit.log(level, event, extra={"event": event, "outcome": outcome, "fields": ctx})


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
    # STEP 4 CHANGE (ASD V-222430/V-222587): DB readable by the app user only
    os.chmod(DB_PATH, 0o600)


def blob_path(file_id):
    # file_id is always a validated server-generated UUID (fixes F-06)
    return os.path.join(DATA_DIR, f"{file_id}.enc")


def clean_filename(name):
    # STEP 2 CHANGE (F-06 / F-12, ASD V-222606, V-222609)
    name = secure_filename(name or "") or "file"
    if len(name) > MAX_NAME_LEN:
        root, ext = os.path.splitext(name)
        name = root[:MAX_NAME_LEN - len(ext)] + ext
    return name


# ---------------------------------------------------------------------------
# Encryption - STEP 2 CHANGE (F-01, ASD V-222587): AES-256-GCM
# ---------------------------------------------------------------------------
# Fresh random 256-bit key and 96-bit nonce per file; file ID bound as AAD.
# The key is returned to the user once and never stored or logged (F-02).
# Accepted risk: FIPS-approved algorithm, but not a FIPS-validated module.
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
# Request lifecycle - STEP 5 CHANGE: every request is audited
# ---------------------------------------------------------------------------
@app.before_request
def start_request():
    g.start = time.perf_counter()
    # reuse nginx's request ID so app and proxy logs can be correlated
    rid = request.headers.get("X-Request-ID", "")
    g.request_id = rid if re.fullmatch(r"[0-9a-f]{32}", rid) else uuid.uuid4().hex
    g.user = None


@app.after_request
def finish_request(response):
    response.headers["X-Request-ID"] = g.request_id
    audit_event("http_request",
                outcome="success" if response.status_code < 400 else "failure",
                status=response.status_code,
                duration_ms=round((time.perf_counter() - g.start) * 1000, 1),
                user_agent=(request.headers.get("User-Agent") or "")[:200])
    return response


def error_response(message, status):
    """Generic user-facing error with a reference ID (ASD V-222610)."""
    return jsonify({"error": message, "request_id": getattr(g, "request_id", None)}), status


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
        audit_event("file_encrypt", "failure", logging.WARNING, reason="no file field")
        return error_response("No file provided", 400)

    display_name = clean_filename(file.filename)
    data = file.read()
    file_id = uuid.uuid4().hex

    key, blob = encrypt_bytes(data, file_id)

    fd = os.open(blob_path(file_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(blob)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO files (id, original_name, size_bytes, created_at) VALUES (?, ?, ?, ?)",
            (file_id, display_name, len(data), datetime.now(timezone.utc).isoformat()))

    # STEP 2/5 CHANGE (F-02): no key, no server path in the log
    audit_event("file_encrypt", file_id=file_id, filename=display_name, size_bytes=len(data))

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
        audit_event("file_decrypt", "failure", logging.WARNING, reason="invalid input format")
        return error_response("Invalid file or key format", 400)

    with get_db() as conn:
        row = conn.execute("SELECT original_name FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None or not os.path.exists(blob_path(file_id)):
        audit_event("file_decrypt", "failure", logging.WARNING, file_id=file_id, reason="not found")
        return error_response("File not found", 404)

    with open(blob_path(file_id), 'rb') as f:
        blob = f.read()

    try:
        plaintext = decrypt_bytes(blob, key, file_id)
    except InvalidTag:
        # security-relevant: wrong key or tampered ciphertext
        audit_event("file_decrypt", "failure", logging.WARNING, file_id=file_id,
                    reason="authentication tag mismatch (wrong key or tampered file)")
        return error_response("Decryption failed: wrong key or file has been tampered with", 400)

    audit_event("file_decrypt", file_id=file_id, filename=row['original_name'])
    return send_file(BytesIO(plaintext), as_attachment=True,
                     download_name=row['original_name'])


# ---------------------------------------------------------------------------
# STEP 5 CHANGE (ASD V-222610): error messages
# Users get a short generic message plus a reference ID - never a stack trace,
# file path or library version. Full detail is written to the audit log only.
# ---------------------------------------------------------------------------
@app.errorhandler(413)
def too_large(_e):
    audit_event("file_encrypt", "failure", logging.WARNING, reason="upload too large")
    return jsonify({"error": f"File too large (max {MAX_UPLOAD_MB} MB)",
                    "request_id": g.request_id}), 413


@app.errorhandler(HTTPException)
def http_error(e):
    return jsonify({"error": e.name, "request_id": getattr(g, "request_id", None)}), e.code


@app.errorhandler(Exception)
def unhandled_error(e):
    audit_event("unhandled_error", "failure", logging.ERROR,
                error_type=type(e).__name__, detail=str(e)[:300])
    return jsonify({"error": "Internal error - please quote the request ID to support",
                    "request_id": getattr(g, "request_id", None)}), 500


# ---------------------------------------------------------------------------
# STEP 5 CHANGE (ASD V-222468, Web SRG V-206356): startup and shutdown events
# ---------------------------------------------------------------------------
init_storage()
audit_event("app_start", version=APP_VERSION, uid=os.getuid(),
            max_upload_mb=MAX_UPLOAD_MB, log_level="INFO")
atexit.register(lambda: audit_event("app_stop", uid=os.getuid()))

if __name__ == "__main__":
    app.run(host='127.0.0.1')
