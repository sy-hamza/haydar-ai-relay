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

    if mode == "login" and not database.email_exists(email):
        raise HTTPException(400, detail="لا يوجد حساب بهذا البريد. أنشئ حساباً جديداً.")

    # Rate limiting: max 1 OTP per email per 60 seconds
    now = time.time()
    last = _otp_rate.get(email, 0)
    if now - last < OTP_RATE_LIMIT_SEC:
        wait = int(OTP_RATE_LIMIT_SEC - (now - last))
        raise HTTPException(429, detail=f"انتظر {wait} ثانية قبل الإعادة")
    _otp_rate[email] = now

    otp = database.create_otp(email, name)
    email_sent = await asyncio.to_thread(database.send_otp_email, email, otp, name)

    if email_sent:
        return {"status": "success", "message": f"تم إرسال رمز التحقق إلى {email}", "email_sent": True}
    else:
        return {"status": "success", "message": "لم يتم تكوين البريد — الرمز: " + otp, "email_sent": False, "dev_otp": otp}

# ── Register ───────────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(data: dict):
    email    = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    name     = (data.get("display_name") or data.get("name") or "مستخدم").strip()
    otp_val  = (data.get("otp") or "").strip()

    if not email or not password:
        raise HTTPException(400, detail="يرجى تعبئة جميع الحقول")
    if len(password) < 6:
        raise HTTPException(400, detail="يجب أن تكون كلمة المرور 6 خانات على الأقل")

    # OTP is MANDATORY for registration
    if not otp_val:
        raise HTTPException(400, detail="رمز التحقق مطلوب")
    if not database.verify_otp(email, otp_val):
        raise HTTPException(400, detail="رمز التحقق غير صحيح أو منتهي الصلاحية")

    user = await asyncio.to_thread(database.register_user, name, email, password)
    if not user:
        raise HTTPException(400, detail="البريد الإلكتروني مسجل بالفعل")

    token = auth.generate_token(user["id"], user["email"], user.get("display_name", ""))
    return {"token": token, "email": user["email"], "display_name": user.get("display_name", "")}

# ── Login ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(data: dict):
    email    = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    otp_val  = (data.get("otp") or "").strip()

    if not email or not password:
        raise HTTPException(400, detail="يرجى تعبئة جميع الحقول")

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

    user_id = str(user_info["user_id"])
    await websocket.accept()

    if user_id not in rooms:
        rooms[user_id] = {"pc": None, "mobile": None}
    rooms[user_id][client_type] = websocket
    print(f"{client_type.upper()} connected — account: {user_id} ({user_info.get('email','')})")

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
