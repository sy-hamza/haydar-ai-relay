"""
database.py — HAYDAR AI Relay Server
SQLite schema with display_name, OTP email verification support.
"""
import sqlite3
import os
import random
import string
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "haydar_relay.db")

# ── SMTP (optional) ───────────────────────────────────────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_ENABLED = bool(SMTP_USER and SMTP_PASS)

def get_smtp_config():
    load_dotenv(override=True)
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    return host, port, user, password, bool(user and password)

# ── In-memory OTP store ───────────────────────────────────────────────────────
_otp_store: dict = {}

# ── DB Init ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name  TEXT    NOT NULL DEFAULT 'مستخدم',
            email         TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migration: add display_name to old schema
    try:
        c.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT 'مستخدم'")
        conn.commit()
    except Exception:
        pass
    conn.commit()
    conn.close()

init_db()

# ── Password hashing ──────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    import bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def check_password(password: str, hashed_pw: str) -> bool:
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_pw.encode("utf-8"))
    except Exception:
        return False

# ── User operations ───────────────────────────────────────────────────────────
def email_exists(email: str) -> bool:
    email = email.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def register_user(display_name: str, email: str, password: str) -> Optional[dict]:
    email = email.strip().lower()
    pw_hash = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (display_name, email, password_hash) VALUES (?, ?, ?)",
            (display_name.strip(), email, pw_hash),
        )
        conn.commit()
        user_id = c.lastrowid
        return {"id": user_id, "email": email, "display_name": display_name.strip()}
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def authenticate_user(email: str, password: str) -> Optional[dict]:
    email = email.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, display_name, email, password_hash FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    if row and check_password(password, row[3]):
        return {"id": row[0], "display_name": row[1], "email": row[2]}
    return None

# ── OTP ───────────────────────────────────────────────────────────────────────
def create_otp(email: str, name: str = "") -> str:
    otp = "".join(random.choices(string.digits, k=6))
    _otp_store[email.strip().lower()] = {
        "otp": otp,
        "name": name,
        "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
    }
    return otp

def verify_otp(email: str, otp: str) -> bool:
    email = email.strip().lower()
    entry = _otp_store.get(email)
    if not entry:
        return False
    if datetime.datetime.utcnow() > entry["expires"]:
        _otp_store.pop(email, None)
        return False
    if entry["otp"] != otp.strip():
        return False
    _otp_store.pop(email, None)
    return True

# ── Email sending ─────────────────────────────────────────────────────────────
def send_otp_email(to_email: str, otp: str, display_name: str = "") -> bool:
    smtp_host, smtp_port, smtp_user, smtp_pass, smtp_enabled = get_smtp_config()
    if not smtp_enabled:
        print(f"\n{'='*50}")
        print(f"[RELAY OTP - DEV MODE] Email: {to_email}")
        print(f"[RELAY OTP - DEV MODE] Code : {otp}")
        print(f"{'='*50}\n")
        return False

    try:
        greeting = f"مرحباً {display_name}!" if display_name else "مرحباً!"
        html = f"""<!DOCTYPE html>
<html dir="rtl">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#060612;font-family:Arial,sans-serif;">
  <table width="100%" bgcolor="#060612" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="520" style="background:#0A0A1A;border-radius:20px;border:1px solid #00E5FF33;">
        <tr><td style="padding:30px 40px;text-align:center;background:linear-gradient(135deg,#00E5FF11,#7C3AED11);">
          <span style="font-size:28px;font-weight:bold;color:#00E5FF;">HAYDAR AI 🤖</span>
        </td></tr>
        <tr><td style="padding:32px 40px;color:#ccc;">
          <p style="font-size:18px;color:#fff;margin:0 0 8px;">{greeting}</p>
          <p style="margin:0 0 24px;color:#999;">رمز التحقق الخاص بك:</p>
          <div style="background:#12122A;border:1px solid #00E5FF44;border-radius:14px;padding:28px;text-align:center;">
            <span style="font-size:48px;font-weight:900;letter-spacing:14px;color:#00E5FF;font-family:monospace;">{otp}</span>
          </div>
          <p style="color:#666;font-size:13px;margin:16px 0 0;">⏱ صالح لمدة 10 دقائق فقط.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"HAYDAR AI — رمز التحقق: {otp}"
        msg["From"] = f"HAYDAR AI <{smtp_user}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html, "html", "utf-8"))
        print(f"[SMTP] Sending relay OTP email to {to_email} via {smtp_user}")
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.ehlo(); s.starttls(); s.login(smtp_user, smtp_pass)
            refused = s.sendmail(smtp_user, to_email, msg.as_string())
            if refused:
                print(f"[SMTP] Refused recipients: {list(refused.keys())}")
                return False
        return True
    except Exception as e:
        print(f"[SMTP Error] {e}")
        return False

def update_user_password(email: str, password: str) -> bool:
    email = email.strip().lower()
    pw_hash = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        print(f"[DB Error] {e}")
        return False
    finally:
        conn.close()

def get_user_id_by_email(email: str) -> Optional[int]:
    email = email.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        if row:
            return row[0]
        return None
    except Exception as e:
        print(f"[DB Error] {e}")
        return None
    finally:
        conn.close()
