"""Company X - Secure File Encryption Service (final implementation).

Every security-relevant change is marked "STEP n CHANGE" with the finding (F-xx)
and the DISA STIG rule it addresses:
  ASD  = Application Security and Development STIG V6R5
  WSRG = Web Server Security Requirements Guide V4R5
"""
import os
import re
import sys
import hmac
import json
import time
import uuid
import atexit
import base64
import secrets
import sqlite3
import logging
from io import BytesIO
from datetime import datetime, timezone, timedelta
from functools import wraps

import click
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (Flask, render_template, request, send_file, jsonify, g,
                   session, redirect, url_for, flash, abort, make_response)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# STEP 1 CHANGE (F-03 / F-04, ASD V-222604, V-222511):
# Removed the hard-coded Fernet key and the start-up code that sourced
# ~/.bashrc, decrypted $API_CHECK and executed it with subprocess(shell=True).
# That payload exfiltrated encryption keys from the log to canarytokens.com.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_NAME = "file-encryption-service"
APP_VERSION = "3.0.0"
DATA_DIR = os.environ.get("DATA_DIR", "/data")          # STEP 2 (F-05): not /tmp
DB_PATH = os.path.join(DATA_DIR, "files.db")
SECRET_PATH = os.path.join(DATA_DIR, "session_secret.key")
LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
AUDIT_LOG = os.path.join(LOG_DIR, "audit.log")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
MAX_NAME_LEN = 200

# STEP 6 security parameters (values taken directly from the ASD STIG)
IDLE_TIMEOUT = timedelta(minutes=15)       # ASD V-222389: 15 min idle logoff
ABSOLUTE_TIMEOUT = timedelta(hours=8)      # forced re-authentication (V-222520)
MAX_FAILED_LOGINS = 3                      # ASD V-222432: 3 attempts ...
LOCKOUT_WINDOW = timedelta(minutes=15)     # ... within 15 minutes
LOCKOUT_DURATION = timedelta(minutes=15)
INACTIVE_ACCOUNT_DAYS = 35                 # ASD V-222411
MAX_SESSIONS_PER_USER = 3                  # ASD V-222387
MIN_PASSWORD_LEN = 15                      # ASD V-222536
MAX_PASSWORD_LEN = 128                     # avoids hashing-cost DoS
# PBKDF2-HMAC-SHA256 (NIST SP 800-132, FIPS-approved), 600,000 iterations
# (OWASP 2023 guidance). ASD V-222542: only hashes are stored.
# Reviewed Bandit B105 false positive: this is the hash ALGORITHM name, not a password.
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"  # nosec B105

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
UUID_RE = re.compile(r"^[0-9a-f]{32}$")

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,      # STEP 2 (F-13)
    # STEP 6 CHANGE - session cookie hardening
    SESSION_COOKIE_NAME="__Host-session",  # __Host- prefix: Secure, Path=/, no Domain
    SESSION_COOKIE_SECURE=True,            # ASD V-222576: HTTPS only
    SESSION_COOKIE_HTTPONLY=True,          # ASD V-222575: no JavaScript access
    SESSION_COOKIE_SAMESITE="Strict",      # ASD V-222603: CSRF defence in depth
    PERMANENT_SESSION_LIFETIME=IDLE_TIMEOUT,
)

# STEP 5 CHANGE (F-14): trust exactly one proxy hop (nginx). Flask is only
# reachable through nginx's Unix socket, so X-Forwarded-For cannot be spoofed.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# ---------------------------------------------------------------------------
# STEP 5 CHANGE (F-14): STIG-compliant audit logging
# ---------------------------------------------------------------------------
# One JSON object per line:
#   ts (UTC, ms)          ASD V-222473, V-222498, V-222499
#   event / path          ASD V-222474 (which function triggered it)
#   outcome               ASD V-222476
#   user                  ASD V-222477 (identity)
#   src_ip / dst          ASD V-222470 (destination IP) + source
#   app                   ASD V-222475 (identifier for centralised logging)
#   request_id            correlates with the nginx access log
# JSON encoding escapes control characters, so crafted filenames or
# User-Agents cannot forge log lines. Keys/passwords/contents are NEVER logged.
class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc)
                          .isoformat(timespec="milliseconds"),
            "app": APP_NAME,
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
            "outcome": getattr(record, "outcome", None),
            "pid": record.process,
        }
        entry.update(getattr(record, "fields", {}))
        return json.dumps({k: v for k, v in entry.items() if v is not None})


def setup_audit_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    # ASD V-222500/V-222501/V-222502: audit log owner-only (0600)
    if not os.path.exists(AUDIT_LOG):
        os.close(os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    os.chmod(AUDIT_LOG, 0o600)
    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        for handler in (logging.FileHandler(AUDIT_LOG), logging.StreamHandler(sys.stdout)):
            handler.setFormatter(JsonFormatter())
            logger.addHandler(handler)
    return logger


audit = setup_audit_logger()


def audit_event(event, outcome="success", level=logging.INFO, **fields):
    try:
        ctx = {
            "user": getattr(g, "username", None) or "anonymous",
            "src_ip": request.remote_addr,
            "dst": request.headers.get("X-Server-Addr"),
            "method": request.method,
            "path": request.path,
            "request_id": getattr(g, "request_id", None),
        }
    except RuntimeError:          # outside a request (startup / shutdown / CLI)
        ctx = {}
    ctx.update(fields)
    audit.log(level, event, extra={"event": event, "outcome": outcome, "fields": ctx})


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def init_storage():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    with get_db() as conn:
        # ASD V-222607: every query in this file is parameterised (no SQL built
        # from strings), so user input can never change the query structure.
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash   TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                last_login      TEXT,
                prev_login      TEXT,
                prev_login_ip   TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                first_failed_at TEXT,
                locked_until    TEXT,
                disabled        INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                sid         TEXT PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                src_ip      TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
                id            TEXT PRIMARY KEY,
                owner_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                size_bytes    INTEGER NOT NULL,
                created_at    TEXT NOT NULL
            );
        """)
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(files)")]
        if "owner_id" not in cols:     # migrate a Step 2-5 database
            conn.execute("ALTER TABLE files ADD COLUMN owner_id INTEGER")
    os.chmod(DB_PATH, 0o600)           # STEP 4 (ASD V-222430/V-222587)


def load_secret_key():
    """Signing key for the session cookie, shared by all gunicorn workers.

    Generated once from the OS CSPRNG and kept in the private data volume
    (0600). Accepted risk: production would use a secrets manager / Docker
    secret with rotation - see POA&M.
    """
    try:
        fd = os.open(SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    for _ in range(50):                # another worker may be mid-write
        with open(SECRET_PATH, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
        time.sleep(0.05)
    raise RuntimeError("session secret unavailable")


def blob_path(file_id):
    # file_id is always a validated, server-generated UUID (STEP 2, F-06)
    return os.path.join(DATA_DIR, f"{file_id}.enc")


def clean_filename(name):
    # STEP 2 CHANGE (F-06 / F-12, ASD V-222606, V-222609)
    name = secure_filename(name or "") or "file"
    if len(name) > MAX_NAME_LEN:
        root, ext = os.path.splitext(name)
        name = root[:MAX_NAME_LEN - len(ext)] + ext
    return name


# ---------------------------------------------------------------------------
# Encryption - STEP 2 CHANGE (F-01, ASD V-222587/V-222588): AES-256-GCM
# ---------------------------------------------------------------------------
# Fresh random 256-bit key and 96-bit nonce per file; the file ID is bound as
# associated data. The key is shown to the user once and never stored or
# logged (F-02). Accepted risk: FIPS-approved algorithm, but not a
# FIPS-validated module (POA&M).
def encrypt_bytes(plaintext, file_id):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return key, nonce + AESGCM(key).encrypt(nonce, plaintext, file_id.encode())


def decrypt_bytes(blob, key, file_id):
    return AESGCM(key).decrypt(blob[:12], blob[12:], file_id.encode())


def encode_key(key):
    return base64.urlsafe_b64encode(key).decode()


def decode_key(text):
    try:
        key = base64.urlsafe_b64decode(text.strip().encode())
    except Exception:
        return None
    return key if len(key) == 32 else None


# ---------------------------------------------------------------------------
# STEP 6 CHANGE (F-11): authentication helpers
# ---------------------------------------------------------------------------
# Used to keep failed-login timing identical whether or not the user exists,
# so response time cannot be used to discover valid usernames.
DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method=PASSWORD_HASH_METHOD)


def password_problems(password, username):
    """ASD V-222536 to V-222540 password rules."""
    problems = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        problems.append(f"no more than {MAX_PASSWORD_LEN} characters")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[0-9]", password):
        problems.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a special character")
    if username and username.lower() in password.lower():
        problems.append("not containing your username")
    return problems


def wants_json():
    return "application/json" in request.headers.get("Accept", "")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if wants_json():
                return error_response("Authentication required", 401)
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def start_session(user):
    """New server-side session after login (ASD V-222579 session fixation)."""
    session.clear()                                   # discard pre-login session
    sid = secrets.token_hex(32)                       # 256-bit, OS CSPRNG (V-222583)
    ts = iso(now())
    with get_db() as conn:
        conn.execute("INSERT INTO sessions (sid, user_id, created_at, last_seen, src_ip) "
                     "VALUES (?, ?, ?, ?, ?)", (sid, user["id"], ts, ts, request.remote_addr))
        # ASD V-222387: limit concurrent sessions - drop the oldest extras
        # never evict the session just created; keep the newest others
        # (rowid breaks ties when several logins happen in the same second)
        extra = conn.execute(
            "SELECT sid FROM sessions WHERE user_id = ? AND sid != ? "
            "ORDER BY last_seen DESC, rowid DESC LIMIT -1 OFFSET ?",
            (user["id"], sid, MAX_SESSIONS_PER_USER - 1)).fetchall()
        for row in extra:
            conn.execute("DELETE FROM sessions WHERE sid = ?", (row["sid"],))
    session.permanent = True
    session["sid"] = sid
    session["csrf"] = secrets.token_urlsafe(32)
    g.user, g.username = user, user["username"]
    audit_event("session_created", session_ref=sid[:8], evicted_sessions=len(extra))  # V-222441


def end_session(reason):
    sid = session.get("sid")
    if sid:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE sid = ?", (sid,))   # V-222578
        audit_event("session_destroyed", session_ref=sid[:8], reason=reason)  # V-222442
    session.clear()


# ---------------------------------------------------------------------------
# Request lifecycle
# ---------------------------------------------------------------------------
@app.before_request
def start_request():
    g.start = time.perf_counter()
    rid = request.headers.get("X-Request-ID", "")
    g.request_id = rid if re.fullmatch(r"[0-9a-f]{32}", rid) else uuid.uuid4().hex
    g.user, g.username = None, None

    # STEP 6: validate the server-side session on every request (ASD V-222580)
    sid = session.get("sid")
    if sid:
        with get_db() as conn:
            row = conn.execute(
                "SELECT u.*, s.sid, s.created_at AS s_created, s.last_seen AS s_seen FROM sessions s "
                "JOIN users u ON u.id = s.user_id WHERE s.sid = ?", (sid,)).fetchone()
        if row is None:
            session.clear()                     # unknown / revoked session ID
        else:
            g.username = row["username"]
            idle = now() - datetime.fromisoformat(row["s_seen"])
            age = now() - datetime.fromisoformat(row["s_created"])
            if idle > IDLE_TIMEOUT or age > ABSOLUTE_TIMEOUT or row["disabled"]:
                reason = "idle timeout" if idle > IDLE_TIMEOUT else (
                    "absolute timeout" if age > ABSOLUTE_TIMEOUT else "account disabled")
                audit_event("session_timeout", "failure", logging.INFO, reason=reason)  # V-222445
                end_session(reason)
                g.username = None
                flash("Your session expired - please sign in again.", "info")
                if request.method == "POST" and request.endpoint != "login":
                    return redirect(url_for("login"))
            else:
                g.user = row
                with get_db() as conn:
                    conn.execute("UPDATE sessions SET last_seen = ? WHERE sid = ?",
                                 (iso(now()), sid))

    # STEP 6 (F-11): anonymous requests to protected actions get a clear
    # "authentication required" before any other processing
    if g.user is None and request.endpoint in ("upload_file", "decrypt", "delete_file"):
        audit_event("access_denied", "failure", logging.WARNING, reason="not authenticated")
        if wants_json() or request.method != "GET":
            if wants_json():
                return error_response("Authentication required", 401)
            flash("Please sign in first.", "info")
        return redirect(url_for("login"))

    # STEP 6: CSRF protection for every state-changing request (ASD V-222603)
    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(token, expected):
            audit_event("csrf_check", "failure", logging.WARNING)
            abort(400, description="Invalid or missing CSRF token - reload the page and try again.")


@app.template_filter("filesize")
def filesize(n):
    for unit in ("bytes", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


@app.template_filter("when")
def when(ts):
    if not ts:
        return ""
    return datetime.fromisoformat(ts).strftime("%d %b %Y, %H:%M UTC")


@app.context_processor
def template_globals():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf"], "current_user": g.user,
            "idle_minutes": int(IDLE_TIMEOUT.total_seconds() // 60),
            "max_upload_mb": MAX_UPLOAD_MB, "min_password_len": MIN_PASSWORD_LEN}


@app.after_request
def finish_request(response):
    response.headers["X-Request-ID"] = g.request_id
    # pages for signed-in users must not be cached by the browser
    if g.user is not None or request.endpoint in ("upload_file", "decrypt"):
        response.headers["Cache-Control"] = "no-store"
    if request.endpoint != "static":
        audit_event("http_request",
                    outcome="success" if response.status_code < 400 else "failure",
                    status=response.status_code,
                    duration_ms=round((time.perf_counter() - g.start) * 1000, 1),
                    user_agent=(request.headers.get("User-Agent") or "")[:200],
                    # ASD V-222447: HTTP headers incl. User-Agent and Referer
                    referer=(request.headers.get("Referer") or "")[:200] or None)
    return response


def error_response(message, status):
    """Generic error + reference ID, never internals (ASD V-222610)."""
    if wants_json():
        return jsonify({"error": message, "request_id": getattr(g, "request_id", None)}), status
    return render_template("error.html", message=message, status=status,
                           request_id=getattr(g, "request_id", None)), status


# ---------------------------------------------------------------------------
# STEP 6: account routes
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""

    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-32 characters: letters, numbers, . _ -")
    problems = password_problems(password, username)
    if problems:
        errors.append("Password must have " + ", ".join(problems) + ".")
    if password != confirm:
        errors.append("Passwords do not match.")
    if not errors:
        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                             (username, generate_password_hash(password, method=PASSWORD_HASH_METHOD),
                              iso(now())))
        except sqlite3.IntegrityError:
            errors.append("That username is not available.")
    if errors:
        audit_event("account_create", "failure", logging.WARNING, target_user=username[:32],
                    reason="validation failed")
        for e in errors:
            flash(e, "error")
        return render_template("register.html", username=username), 400

    audit_event("account_create", target_user=username)          # ASD V-222467
    flash("Account created - please sign in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    generic = "Invalid username or password, or the account is temporarily locked."

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def fail(reason, log_user):
        audit_event("login", "failure", logging.WARNING, target_user=log_user, reason=reason)  # V-222462
        if wants_json():
            return error_response(generic, 401)
        flash(generic, "error")
        return render_template("login.html", username=username), 401

    if user is None or len(password) > MAX_PASSWORD_LEN:
        check_password_hash(DUMMY_HASH, password[:MAX_PASSWORD_LEN])  # equal timing
        return fail("unknown user" if user is None else "oversized password", username[:32])

    t = now()
    if user["disabled"]:
        return fail("account disabled", user["username"])
    if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > t:
        check_password_hash(DUMMY_HASH, password)
        return fail("account locked", user["username"])
    # ASD V-222411: disable accounts unused for 35 days
    last = user["last_login"] or user["created_at"]
    if t - datetime.fromisoformat(last) > timedelta(days=INACTIVE_ACCOUNT_DAYS):
        with get_db() as conn:
            conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user["id"],))
        audit_event("account_disable", target_user=user["username"], reason="35 days inactive")
        return fail("account inactive > 35 days", user["username"])

    if not check_password_hash(user["password_hash"], password):
        # ASD V-222432: lock after 3 failures within 15 minutes
        first = user["first_failed_at"]
        in_window = first and t - datetime.fromisoformat(first) <= LOCKOUT_WINDOW
        attempts = (user["failed_attempts"] + 1) if in_window else 1
        first = first if in_window else iso(t)
        locked = iso(t + LOCKOUT_DURATION) if attempts >= MAX_FAILED_LOGINS else None
        with get_db() as conn:
            conn.execute("UPDATE users SET failed_attempts = ?, first_failed_at = ?, locked_until = ? "
                         "WHERE id = ?", (attempts, first, locked, user["id"]))
        if locked:
            audit_event("account_lock", "success", logging.WARNING, target_user=user["username"],
                        attempts=attempts, locked_until=locked)
        return fail(f"bad password (attempt {attempts}/{MAX_FAILED_LOGINS})", user["username"])

    # success: reset counters, record previous login for display (ASD V-222437)
    with get_db() as conn:
        conn.execute("UPDATE users SET failed_attempts = 0, first_failed_at = NULL, locked_until = NULL, "
                     "prev_login = last_login, prev_login_ip = ?, last_login = ? WHERE id = ?",
                     (request.remote_addr, iso(t), user["id"]))
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    g.username = user["username"]
    audit_event("login")                                       # ASD V-222462 / V-222464
    start_session(user)
    if wants_json():
        return jsonify({"message": "Signed in", "csrf_token": session["csrf"]})
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    was_signed_in = g.user is not None
    if was_signed_in:
        audit_event("logout")                                  # ASD V-222464
    end_session("user logout")
    resp = make_response(render_template("logged_out.html", was_signed_in=was_signed_in))
    # ASD V-222388: tell the browser to clear cookies and storage for this site
    resp.headers["Clear-Site-Data"] = '"cookies", "storage"'
    return resp


# ---------------------------------------------------------------------------
# File routes (STEP 6: every file belongs to exactly one user)
# ---------------------------------------------------------------------------
def owned_file(file_id):
    """Return the file row only if it belongs to the signed-in user.

    ASD V-222425: users can only reach their own files. A file that exists but
    belongs to someone else returns the same 404 as a missing file, so its
    existence is not revealed.
    """
    if not UUID_RE.match(file_id or ""):
        return None
    with get_db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        return None
    if row["owner_id"] != g.user["id"]:
        audit_event("access_denied", "failure", logging.WARNING, file_id=file_id,
                    reason="file owned by another user")          # ASD V-222465
        return None
    return row


@app.route("/")
@login_required
def index():
    with get_db() as conn:
        files = conn.execute(
            "SELECT id, original_name, size_bytes, created_at FROM files "
            "WHERE owner_id = ? ORDER BY created_at DESC", (g.user["id"],)).fetchall()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    file = request.files.get("file")
    if file is None or not file.filename:
        audit_event("file_encrypt", "failure", logging.WARNING, reason="no file selected")
        if wants_json():
            return error_response("No file provided", 400)
        flash("Choose a file to encrypt first.", "error")
        return redirect(url_for("index"))

    display_name = clean_filename(file.filename)
    data = file.read()
    file_id = uuid.uuid4().hex
    key, blob = encrypt_bytes(data, file_id)

    fd = os.open(blob_path(file_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    with get_db() as conn:
        conn.execute("INSERT INTO files (id, owner_id, original_name, size_bytes, created_at) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (file_id, g.user["id"], display_name, len(data), iso(now())))

    audit_event("file_encrypt", file_id=file_id, filename=display_name, size_bytes=len(data))  # V-222472

    if wants_json():
        return jsonify({"message": "File encrypted and stored. Save this key - it cannot be recovered.",
                        "file_id": file_id, "filename": display_name,
                        "encryption_key": encode_key(key)})
    return render_template("key.html", filename=display_name, key=encode_key(key),
                           size=len(data))


@app.route("/decrypt", methods=["GET"])
@login_required
def decrypt_form():
    return redirect(url_for("index"))


@app.route("/decrypt", methods=["POST"])
@login_required
def decrypt():
    file_id = (request.form.get("file_id") or "").strip()
    key = decode_key(request.form.get("key") or "")

    def fail(message, status, **why):
        audit_event("file_decrypt", "failure", logging.WARNING, file_id=file_id[:32] or None, **why)
        if wants_json():
            return error_response(message, status)
        flash(message, "error")
        return redirect(url_for("index"))

    if not UUID_RE.match(file_id) or key is None:
        return fail("That key is not valid - it should be the 44-character key you were given.",
                    400, reason="invalid input format")
    row = owned_file(file_id)
    if row is None or not os.path.exists(blob_path(file_id)):
        return fail("File not found.", 404, reason="not found or not owner")

    with open(blob_path(file_id), "rb") as f:
        blob = f.read()
    try:
        plaintext = decrypt_bytes(blob, key, file_id)
    except InvalidTag:
        return fail("Decryption failed: wrong key, or the stored file has been tampered with.",
                    400, reason="authentication tag mismatch")

    audit_event("file_decrypt", file_id=file_id, filename=row["original_name"])   # V-222471
    return send_file(BytesIO(plaintext), as_attachment=True, download_name=row["original_name"])


@app.route("/delete", methods=["POST"])
@login_required
def delete_file():
    file_id = (request.form.get("file_id") or "").strip()
    row = owned_file(file_id)
    if row is None:
        audit_event("file_delete", "failure", logging.WARNING, file_id=file_id[:32] or None)
        if wants_json():
            return error_response("File not found.", 404)
        flash("File not found.", "error")
        return redirect(url_for("index"))
    try:
        os.remove(blob_path(file_id))
    except FileNotFoundError:
        pass
    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    audit_event("file_delete", file_id=file_id, filename=row["original_name"])    # V-222472
    if wants_json():
        return jsonify({"message": "File deleted", "file_id": file_id})
    flash(f"Deleted {row['original_name']}.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Error handling - STEP 5 CHANGE (ASD V-222610 / V-222611)
# ---------------------------------------------------------------------------
@app.errorhandler(413)
def too_large(_e):
    audit_event("file_encrypt", "failure", logging.WARNING, reason="upload too large")
    return error_response(f"File too large (maximum {MAX_UPLOAD_MB} MB).", 413)


@app.errorhandler(HTTPException)
def http_error(e):
    message = e.description if e.code == 400 and "CSRF" in (e.description or "") else e.name
    return error_response(message, e.code)


@app.errorhandler(Exception)
def unhandled_error(e):
    audit_event("unhandled_error", "failure", logging.ERROR,
                error_type=type(e).__name__, detail=str(e)[:300])
    return error_response("Something went wrong. Please quote the reference below to support.", 500)


# ---------------------------------------------------------------------------
# STEP 6: administrator commands (ASD V-222433 approved unlock process)
#   docker compose exec flask flask --app app unlock-user <name>
#   docker compose exec flask flask --app app list-users
# ---------------------------------------------------------------------------
@app.cli.command("unlock-user")
@click.argument("username")
def unlock_user(username):
    with get_db() as conn:
        n = conn.execute("UPDATE users SET failed_attempts = 0, first_failed_at = NULL, "
                         "locked_until = NULL, disabled = 0, last_login = ? WHERE username = ?",
                         (iso(now()), username)).rowcount
    audit_event("account_unlock", "success" if n else "failure", target_user=username,
                actor="administrator (CLI)")
    click.echo(f"{'Unlocked' if n else 'No such user:'} {username}")


@app.cli.command("list-users")
def list_users():
    with get_db() as conn:
        for u in conn.execute("SELECT username, created_at, last_login, failed_attempts, "
                              "locked_until, disabled FROM users ORDER BY id"):
            click.echo(dict(u))


# ---------------------------------------------------------------------------
# Startup / shutdown (ASD V-222468 / V-222469, WSRG V-206356)
# ---------------------------------------------------------------------------
init_storage()
app.secret_key = load_secret_key()
audit_event("app_start", version=APP_VERSION, uid=os.getuid(),
            max_upload_mb=MAX_UPLOAD_MB, idle_timeout_min=15, log_level="INFO")
atexit.register(lambda: audit_event("app_stop", uid=os.getuid()))

if __name__ == "__main__":
    app.run(host="127.0.0.1")
