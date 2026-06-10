from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
import database
import auth
import json
import asyncio
import time

# ── Rate limiting (OTP) ───────────────────────────────────────────────────────
_otp_rate: dict = {}  # { email: last_request_timestamp }
OTP_RATE_LIMIT_SEC = 60  # 1 request per minute per email

# Pending email relay responses: { email: asyncio.Future }
pending_emails: dict = {}

app = FastAPI()

class AuthModel(BaseModel):
    display_name: str = ""
    email: str
    password: str

class OtpRequestModel(BaseModel):
    email: str
    name: str = ""
    mode: str = "register"   # "register" | "login"

class OtpVerifyModel(BaseModel):
    email: str
    otp: str

@app.get("/")
async def index():
    return {"status": "HAYDAR AI Relay Server is running!"}

# /api/debug removed — was exposing SMTP credentials publicly

# ── Send OTP ───────────────────────────────────────────────────────────────────
@app.post("/api/auth/send-otp")
async def send_otp(body: OtpRequestModel):
    email = body.email.strip()
    name  = body.name.strip()
    mode  = body.mode

    if not email or "@" not in email:
        raise HTTPException(400, detail="صيغة البريد الإلكتروني غير صحيحة")

    if mode == "register" and database.email_exists(email):
        raise HTTPException(400, detail="هذا البريد مسجل بالفعل. جرب تسجيل الدخول.")

    if mode in ("login", "reset") and not database.email_exists(email):
        raise HTTPException(400, detail="لا يوجد حساب بهذا البريد. أنشئ حساباً جديداً.")

    # Rate limiting: max 1 OTP per email per 60 seconds
    now = time.time()
    last = _otp_rate.get(email, 0)
    if now - last < OTP_RATE_LIMIT_SEC:
        wait = int(OTP_RATE_LIMIT_SEC - (now - last))
        raise HTTPException(429, detail=f"انتظر {wait} ثانية قبل الإعادة")
    _otp_rate[email] = now

    otp = database.create_otp(email, name)

    # WebSocket SMTP Relay Check
    email_key = email.strip().lower()
    pc_ws = None
    if email_key in rooms and rooms[email_key]["pc"]:
        pc_ws = rooms[email_key]["pc"]

    if not pc_ws:
        for uid, room in rooms.items():
            if room.get("pc"):
                pc_ws = room["pc"]
                print(f"[Relay] Fallback: Using active PC connection for user_id {uid} to send email to {email}")
                break

    if pc_ws:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        pending_emails[email.lower()] = fut
        try:
            print(f"[Relay] Relaying OTP email to PC for {email}")
            await pc_ws.send_text(json.dumps({
                "type": "system",
                "action": "send_email",
                "to_email": email,
                "otp": otp,
                "display_name": name
            }))
            success = await asyncio.wait_for(fut, timeout=5.0)
            if success:
                return {"status": "success", "message": f"تم إرسال رمز التحقق إلى {email} (تأكد من مجلد الرسائل غير المرغوب فيها Spam)", "email_sent": True}
        except Exception as err:
            print(f"[Relay] Failed to relay email via PC: {err}")
        finally:
            pending_emails.pop(email.lower(), None)

    # Fallback to direct SMTP
    email_sent = await asyncio.to_thread(database.send_otp_email, email, otp, name)

    if email_sent:
        return {"status": "success", "message": f"تم إرسال رمز التحقق إلى {email} (تأكد من مجلد الرسائل غير المرغوب فيها Spam)", "email_sent": True}
    else:
        # Fallback: Render free tier blocks outgoing SMTP ports (25/465/587).
        # Return the generated OTP directly in the response so the user can register/login.
        return {
            "status": "success",
            "message": f"تخطي البريد (Render Free) - الرمز: {otp}",
            "email_sent": False,
            "dev_otp": otp
        }

# ── Register ───────────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(data: dict):
    email    = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    name     = (data.get("display_name") or data.get("name") or "مستخدم").strip()
    otp_val  = (data.get("otp") or "").strip()
    system_token = (data.get("system_token") or "").strip()

    if not email or not password:
        raise HTTPException(400, detail="يرجى تعبئة جميع الحقول")
    if len(password) < 6:
        raise HTTPException(400, detail="يجب أن تكون كلمة المرور 6 خانات على الأقل")

    # Verify if it's a trusted system request (e.g. from the PC server)
    is_system = False
    if system_token:
        decoded = auth.verify_token(system_token)
        if decoded and decoded.get("email") == "system@haydar.ai":
            is_system = True

    if not is_system:
        # OTP is MANDATORY for registration
        if not otp_val:
            raise HTTPException(400, detail="رمز التحقق مطلوب")
        if not database.verify_otp(email, otp_val):
            raise HTTPException(400, detail="رمز التحقق غير صحيح أو منتهي الصلاحية")

    user = await asyncio.to_thread(database.register_user, name, email, password)
    if not user:
        if is_system:
            # If system request and user exists, update password and return token
            await asyncio.to_thread(database.update_user_password, email, password)
            uid = database.get_user_id_by_email(email) or -1
            token = auth.generate_token(uid, email, name)
            return {"token": token, "email": email, "display_name": name}
        raise HTTPException(400, detail="البريد الإلكتروني مسجل بالفعل")

    token = auth.generate_token(user["id"], user["email"], user.get("display_name", ""))
    return {"token": token, "email": user["email"], "display_name": user.get("display_name", "")}

# ── Login ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(data: dict):
    email    = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    otp_val  = (data.get("otp") or "").strip()
    system_token = (data.get("system_token") or "").strip()

    if not email or not password:
        raise HTTPException(400, detail="يرجى تعبئة جميع الحقول")

    is_system = False
    if system_token:
        decoded = auth.verify_token(system_token)
        if decoded and decoded.get("email") == "system@haydar.ai":
            is_system = True

    if not is_system:
        # OTP is MANDATORY for login
        if not otp_val:
            raise HTTPException(400, detail="رمز التحقق مطلوب")
        if not database.verify_otp(email, otp_val):
            raise HTTPException(400, detail="رمز التحقق غير صحيح أو منتهي الصلاحية")

    user = await asyncio.to_thread(database.authenticate_user, email, password)
    if not user:
        raise HTTPException(401, detail="البريد الإلكتروني أو كلمة المرور غير صحيحة")

    token = auth.generate_token(user["id"], user["email"], user.get("display_name", ""))
    return {"token": token, "email": user["email"], "display_name": user.get("display_name", "")}

# ── Reset Password ─────────────────────────────────────────────────────────────
@app.post("/api/auth/reset-password")
async def reset_password(data: dict):
    email    = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    otp_val  = (data.get("otp") or "").strip()

    if not email or not password or not otp_val:
        raise HTTPException(400, detail="يرجى تعبئة جميع الحقول")

    if len(password) < 6:
        raise HTTPException(400, detail="يجب أن تكون كلمة المرور 6 خانات على الأقل")

    if not database.email_exists(email):
        raise HTTPException(400, detail="البريد الإلكتروني غير مسجل")

    if not database.verify_otp(email, otp_val):
        raise HTTPException(400, detail="رمز التحقق غير صحيح أو منتهي الصلاحية")

    success = await asyncio.to_thread(database.update_user_password, email, password)
    if not success:
        raise HTTPException(500, detail="فشل تحديث كلمة المرور")

    return {"status": "success", "message": "تم تحديث كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن."}

# ── WebSocket Rooms ────────────────────────────────────────────────────────────
# rooms: { user_id (str): { "pc": ws|None, "mobile": ws|None } }
rooms: dict = {}

@app.websocket("/ws/{client_type}/{token}")
async def websocket_endpoint(websocket: WebSocket, client_type: str, token: str):
    if client_type not in ("pc", "mobile"):
        await websocket.close(code=4000, reason="Invalid client type")
        return

    user_info = auth.verify_token(token)
    if not user_info:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    user_id = user_info["email"].strip().lower()
    await websocket.accept()

    if user_id not in rooms:
        rooms[user_id] = {"pc": None, "mobile": None}
    rooms[user_id][client_type] = websocket
    print(f"{client_type.upper()} connected — account: {user_id}")

    other = "mobile" if client_type == "pc" else "pc"
    if rooms[user_id][other]:
        try:
            await websocket.send_json({"status": "info", "message": "تم الاقتران بالطرف الآخر ✅"})
            await rooms[user_id][other].send_json({"status": "info", "message": "تم الاقتران بالطرف الآخر ✅"})
        except Exception:
            pass

    try:
        while True:
            message = await websocket.receive_text()
            
            # Check for system messages / responses from PC
            if client_type == "pc":
                try:
                    parsed = json.loads(message)
                    if isinstance(parsed, dict):
                        mtype = parsed.get("type")
                        action = parsed.get("action")
                        
                        if mtype == "system" and action == "sync_account":
                            sync_email = (parsed.get("email") or "").strip().lower()
                            sync_name = (parsed.get("display_name") or "مستخدم").strip()
                            sync_pwhash = (parsed.get("password_hash") or "").strip()
                            
                            if sync_email and sync_pwhash:
                                print(f"[Relay Sync] Syncing account for {sync_email} from PC")
                                conn = database.sqlite3.connect(database.DB_PATH)
                                c = conn.cursor()
                                try:
                                    c.execute("INSERT OR REPLACE INTO users (display_name, email, password_hash) VALUES (?, ?, ?)",
                                              (sync_name, sync_email, sync_pwhash))
                                    conn.commit()
                                    print(f"[Relay Sync] Account {sync_email} synced successfully.")
                                except Exception as sync_err:
                                    print(f"[Relay Sync Error] Failed to sync: {sync_err}")
                                finally:
                                    conn.close()
                            continue
                            
                        elif mtype == "system_response" and action == "send_email":
                            to_email = parsed.get("to_email")
                            success = parsed.get("success", False)
                            email_key = (to_email or "").strip().lower()
                            if email_key in pending_emails:
                                pending_emails[email_key].set_result(success)
                            continue
                except Exception as parse_err:
                    print(f"[Relay System Parser Error] {parse_err}")
            
            target_ws = rooms[user_id][other]
            if target_ws:
                await target_ws.send_text(message)
            else:
                await websocket.send_json({"status": "error", "message": "الطرف الآخر غير متصل حالياً"})
    except WebSocketDisconnect:
        rooms[user_id][client_type] = None
        other_ws = rooms[user_id][other]
        if other_ws:
            try:
                await other_ws.send_json({"status": "info", "message": "انقطع اتصال الطرف الآخر"})
            except Exception:
                pass
        if rooms[user_id]["pc"] is None and rooms[user_id]["mobile"] is None:
            del rooms[user_id]
