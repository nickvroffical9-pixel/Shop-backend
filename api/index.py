import base64
import os
import random
import string
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode

import bcrypt
import jwt
import psycopg2
import psycopg2.extras
import requests
from flask import Flask, jsonify, redirect, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[os.environ.get("FRONTEND_ORIGIN", "*")], supports_credentials=True)

# ---------- Config (all from environment variables, never hardcoded) ----------
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-vercel-env-vars")
SETUP_SECRET = os.environ.get("SETUP_SECRET", "change-me-too")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")  # optional, signup notices only
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM = os.environ.get("RESEND_FROM", "no-reply@yourdomain.com")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")  # e.g. https://your-backend.vercel.app/api/auth/google/callback
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5500")
REQUIRE_EXTRA_CODE_AFTER_GOOGLE = os.environ.get("REQUIRE_EXTRA_CODE_AFTER_GOOGLE", "false").lower() == "true"
MAX_AUDIO_BYTES = 3 * 1024 * 1024  # 3 MB cap for profile background audio


def db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


# ---------- Helpers ----------
def make_token(user):
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "is_owner": user["is_owner"],
        "exp": datetime.now(timezone.utc) + timedelta(days=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "invalid or expired token"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper


def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.user.get("is_owner"):
            return jsonify({"error": "owner access required"}), 403
        return f(*args, **kwargs)
    return wrapper


def gen_code():
    return "".join(random.choices(string.digits, k=6))


def send_email(to_email, subject, text):
    if not RESEND_API_KEY:
        # No email provider configured yet -- log instead of failing, so local testing still works.
        print(f"[DEV EMAIL] to={to_email} subject={subject} body={text}")
        return True
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
        json={"from": RESEND_FROM, "to": [to_email], "subject": subject, "text": text},
        timeout=10,
    )
    return resp.ok


def notify_discord(message):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message}, timeout=5)
    except requests.RequestException:
        pass


def store_code(conn, email, purpose, minutes_valid=15):
    code = gen_code()
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes_valid)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO email_verifications (email, code, purpose, expires_at) VALUES (%s,%s,%s,%s)",
            (email, code, purpose, expires),
        )
    conn.commit()
    return code


def check_code(conn, email, purpose, code):
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id FROM email_verifications
               WHERE email=%s AND purpose=%s AND code=%s AND used=FALSE AND expires_at > now()
               ORDER BY id DESC LIMIT 1""",
            (email, purpose, code),
        )
        row = cur.fetchone()
        if not row:
            return False
        cur.execute("UPDATE email_verifications SET used=TRUE WHERE id=%s", (row["id"],))
    conn.commit()
    return True


# ---------- Signup / login / email verification ----------
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not username or not email or len(password) < 6:
        return jsonify({"error": "username, email, and a password of 6+ chars are required"}), 400

    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
        if cur.fetchone():
            return jsonify({"error": "username or email already taken"}), 409

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s,%s,%s) RETURNING id",
            (username, email, pw_hash),
        )
        conn.commit()

    code = store_code(conn, email, "signup")
    send_email(email, "Your verification code", f"Your verification code is {code}. It expires in 15 minutes.")
    notify_discord(f"\U0001F7E2 New signup: **{username}** ({email})")
    conn.close()
    return jsonify({"message": "account created, verification code sent to email"}), 201


@app.route("/api/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    conn = db()
    if not check_code(conn, email, "signup", code) and not check_code(conn, email, "google_extra", code):
        conn.close()
        return jsonify({"error": "invalid or expired code"}), 400

    with conn.cursor() as cur:
        cur.execute("UPDATE users SET email_verified=TRUE WHERE email=%s RETURNING *", (email,))
        user = cur.fetchone()
    conn.commit()
    conn.close()
    if not user:
        return jsonify({"error": "no account with that email"}), 404
    return jsonify({"token": make_token(user), "user": public_user(user)})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    identifier = (data.get("username_or_email") or "").strip().lower()
    password = data.get("password") or ""

    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE lower(username)=%s OR lower(email)=%s", (identifier, identifier))
        user = cur.fetchone()
    conn.close()

    if not user or not user["password_hash"] or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "invalid credentials"}), 401
    if not user["email_verified"]:
        return jsonify({"error": "email not verified yet"}), 403

    return jsonify({"token": make_token(user), "user": public_user(user)})


def public_user(user):
    return {
        "username": user["username"],
        "email": user["email"],
        "is_owner": user["is_owner"],
        "bio": user.get("bio", ""),
    }


# ---------- Google OAuth (real OAuth, no password collection) ----------
@app.route("/api/auth/google/start")
def google_start():
    if not GOOGLE_CLIENT_ID or not GOOGLE_REDIRECT_URI:
        return jsonify({"error": "Google OAuth not configured yet"}), 500
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))


@app.route("/api/auth/google/callback")
def google_callback():
    code = request.args.get("code")
    if not code:
        return redirect(f"{FRONTEND_URL}/login?error=google_denied")

    token_resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=10,
    ).json()
    access_token = token_resp.get("access_token")
    if not access_token:
        return redirect(f"{FRONTEND_URL}/login?error=google_token_failed")

    profile = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()
    google_id = profile.get("id")
    email = (profile.get("email") or "").lower()

    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE google_id=%s OR email=%s", (google_id, email))
        user = cur.fetchone()

        if user:
            if not user["google_id"]:
                cur.execute("UPDATE users SET google_id=%s WHERE id=%s", (google_id, user["id"]))
                conn.commit()
            if REQUIRE_EXTRA_CODE_AFTER_GOOGLE and not user["email_verified"]:
                store_code(conn, email, "google_extra")
                send_email(email, "Confirm it's you", "Enter the code we just emailed you to finish logging in.")
                conn.close()
                return redirect(f"{FRONTEND_URL}/verify?email={email}")
            conn.close()
            notify_discord(f"\U0001F7E2 Google login: **{user['username']}** ({email})")
            return redirect(f"{FRONTEND_URL}/oauth-complete?token={make_token(user)}")

        # No account yet -- hand the frontend a short-lived signup ticket, no password involved.
        ticket = jwt.encode(
            {"email": email, "google_id": google_id, "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
            JWT_SECRET,
            algorithm="HS256",
        )
        conn.close()
        return redirect(f"{FRONTEND_URL}/choose-username?ticket={ticket}&email={email}")


@app.route("/api/signup/google-complete", methods=["POST"])
def google_complete():
    data = request.get_json(force=True)
    ticket = data.get("ticket")
    username = (data.get("username") or "").strip()
    try:
        payload = jwt.decode(ticket, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return jsonify({"error": "signup link expired, please try Google sign-in again"}), 400

    email = payload["email"]
    google_id = payload["google_id"]

    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            return jsonify({"error": "username already taken"}), 409
        cur.execute(
            """INSERT INTO users (username, email, google_id, email_verified)
               VALUES (%s,%s,%s, TRUE) RETURNING *""",
            (username, email, google_id),
        )
        user = cur.fetchone()
    conn.commit()

    extra_required = False
    if REQUIRE_EXTRA_CODE_AFTER_GOOGLE:
        store_code(conn, email, "google_extra")
        send_email(email, "Confirm your account", "Enter the code we just emailed you to finish setting up.")
        extra_required = True

    notify_discord(f"\U0001F7E2 New signup via Google: **{username}** ({email})")
    conn.close()

    if extra_required:
        return jsonify({"message": "check your email for a final code", "email": email})
    return jsonify({"token": make_token(user), "user": public_user(user)})


# ---------- Users / profiles ----------
@app.route("/api/users")
@auth_required
def list_users():
    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT username, is_owner FROM users ORDER BY username")
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@app.route("/api/users/<username>")
@auth_required
def get_profile(username):
    conn = db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT username, bio, is_owner, (audio_data IS NOT NULL) AS has_audio FROM users WHERE username=%s",
            (username,),
        )
        user = cur.fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@app.route("/api/profile/bio", methods=["POST"])
@auth_required
def set_bio():
    bio = (request.get_json(force=True).get("bio") or "")[:1000]
    conn = db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET bio=%s WHERE id=%s", (bio, request.user["sub"]))
    conn.commit()
    conn.close()
    return jsonify({"message": "bio updated"})


@app.route("/api/profile/audio", methods=["POST"])
@auth_required
def upload_audio():
    data = request.get_json(force=True)
    b64 = data.get("audio_base64") or ""
    mime = data.get("mime") or "audio/mpeg"
    raw = base64.b64decode(b64.split(",")[-1])
    if len(raw) > MAX_AUDIO_BYTES:
        return jsonify({"error": "audio file too large (3MB max)"}), 400
    conn = db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET audio_data=%s, audio_mime=%s WHERE id=%s",
            (psycopg2.Binary(raw), mime, request.user["sub"]),
        )
    conn.commit()
    conn.close()
    return jsonify({"message": "audio uploaded"})


@app.route("/api/profile/audio/<username>")
def get_audio(username):
    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT audio_data, audio_mime FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
    conn.close()
    if not row or not row["audio_data"]:
        return jsonify({"error": "no audio set"}), 404
    return app.response_class(bytes(row["audio_data"]), mimetype=row["audio_mime"] or "audio/mpeg")


# ---------- Direct messages ----------
@app.route("/api/messages", methods=["POST"])
@auth_required
def send_message():
    data = request.get_json(force=True)
    to_username = (data.get("to_username") or "").strip()
    content = (data.get("content") or "").strip()
    if not to_username or not content:
        return jsonify({"error": "to_username and content are required"}), 400

    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s", (to_username,))
        recipient = cur.fetchone()
        if not recipient:
            conn.close()
            return jsonify({"error": "user not found"}), 404
        cur.execute(
            "INSERT INTO messages (sender_id, recipient_id, content) VALUES (%s,%s,%s)",
            (request.user["sub"], recipient["id"], content),
        )
    conn.commit()
    conn.close()
    return jsonify({"message": "sent"})


@app.route("/api/messages/<username>")
@auth_required
def get_conversation(username):
    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        other = cur.fetchone()
        if not other:
            conn.close()
            return jsonify({"error": "user not found"}), 404
        cur.execute(
            """SELECT m.content, m.created_at, u.username AS sender
               FROM messages m JOIN users u ON u.id = m.sender_id
               WHERE (m.sender_id=%s AND m.recipient_id=%s) OR (m.sender_id=%s AND m.recipient_id=%s)
               ORDER BY m.created_at ASC""",
            (request.user["sub"], other["id"], other["id"], request.user["sub"]),
        )
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


# ---------- Site settings (Discord link etc.), owner-managed ----------
@app.route("/api/settings/public")
def public_settings():
    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT key, value FROM settings")
        rows = {r["key"]: r["value"] for r in cur.fetchall()}
    conn.close()
    return jsonify(rows)


@app.route("/api/owner/settings", methods=["POST"])
@auth_required
@owner_required
def update_settings():
    data = request.get_json(force=True)
    conn = db()
    with conn.cursor() as cur:
        for key, value in data.items():
            cur.execute(
                """INSERT INTO settings (key, value) VALUES (%s,%s)
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()""",
                (key, str(value)),
            )
    conn.commit()
    conn.close()
    return jsonify({"message": "settings updated"})


# ---------- One-time owner account setup ----------
@app.route("/api/setup/seed-owner-form")
def seed_owner_form():
    return """
    <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{font-family:sans-serif;max-width:420px;margin:40px auto;padding:0 16px}
    input{width:100%;padding:10px;margin:6px 0 14px;box-sizing:border-box;font-size:16px}
    button{padding:10px 18px;font-size:16px}#msg{margin-top:14px;font-weight:bold}</style></head>
    <body>
    <h2>One-time owner setup</h2>
    <p>This makes one account the permanent site owner. You only need to do this once.</p>
    <label>Setup secret (from your SETUP_SECRET env var)</label><input id="secret" type="password">
    <label>Username (must already exist &mdash; sign up on the site first)</label><input id="username">
    <label>Email (the one used to sign up)</label><input id="email" type="email">
    <label>Password (can be the same one you already use to log in)</label><input id="password" type="password">
    <button onclick="go()">Make this account the owner</button>
    <div id="msg"></div>
    <script>
    function go(){
      var msg = document.getElementById('msg'); msg.textContent = 'Working...';
      fetch('/api/setup/seed-owner', {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-Setup-Secret': document.getElementById('secret').value},
        body: JSON.stringify({
          username: document.getElementById('username').value,
          email: document.getElementById('email').value,
          password: document.getElementById('password').value
        })
      }).then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
        .then(function(res){ msg.textContent = res.ok ? 'Success! That account is now the owner.' : ('Error: ' + (res.d.error || 'something went wrong')); })
        .catch(function(){ msg.textContent = 'Network error. Try again.'; });
    }
    </script>
    </body></html>
    """


@app.route("/api/setup/seed-owner", methods=["POST"])
def seed_owner():
    """
    Call this ONCE after deploying, with your own chosen username/email/password,
    using a header 'X-Setup-Secret' matching the SETUP_SECRET env var you set in Vercel.
    This avoids ever hardcoding real credentials into source code.
    """
    if request.headers.get("X-Setup-Secret") != SETUP_SECRET:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(force=True)
    username = data["username"]
    email = data["email"].lower()
    password = data["password"]
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = db()
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users (username, email, password_hash, is_owner, email_verified)
               VALUES (%s,%s,%s, TRUE, TRUE)
               ON CONFLICT (username) DO UPDATE SET is_owner=TRUE, email_verified=TRUE, password_hash=EXCLUDED.password_hash
               RETURNING *""",
            (username, email, pw_hash),
        )
        user = cur.fetchone()
    conn.commit()
    conn.close()
    return jsonify({"message": "owner account ready", "user": public_user(user)})


@app.route("/api/reviews")
def list_reviews():
    conn = db()
    with conn.cursor() as cur:
        cur.execute(
            """SELECT r.id, u.username, r.rating, r.text, r.created_at
               FROM reviews r JOIN users u ON u.id = r.user_id
               ORDER BY r.created_at DESC LIMIT 300"""
        )
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)


@app.route("/api/reviews", methods=["POST"])
@auth_required
def upsert_review():
    data = request.get_json(force=True)
    try:
        rating = int(data.get("rating") or 0)
    except (TypeError, ValueError):
        rating = 0
    text = (data.get("text") or "").strip()[:400]
    if rating < 1 or rating > 5 or len(text) < 5:
        return jsonify({"error": "Give a star rating and write at least a few words."}), 400
    conn = db()
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO reviews (user_id, rating, text) VALUES (%s,%s,%s)
               ON CONFLICT (user_id) DO UPDATE SET rating=EXCLUDED.rating, text=EXCLUDED.text, created_at=now()""",
            (request.user["sub"], rating, text),
        )
    conn.commit()
    conn.close()
    return jsonify({"message": "saved"})


@app.route("/api/reviews/<int:review_id>", methods=["DELETE"])
@auth_required
def delete_review(review_id):
    conn = db()
    with conn.cursor() as cur:
        cur.execute("SELECT user_id FROM reviews WHERE id=%s", (review_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not found"}), 404
        if row["user_id"] != request.user["sub"] and not request.user.get("is_owner"):
            conn.close()
            return jsonify({"error": "you can only delete your own review"}), 403
        cur.execute("DELETE FROM reviews WHERE id=%s", (review_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "deleted"})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": time.time()})
