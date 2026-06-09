import jwt
import datetime
import os

JWT_SECRET = os.getenv("JWT_SECRET", "haydar-ai-jwt-super-secret-key-123456")
ALGORITHM = "HS256"

def generate_token(user_id: int, email: str, display_name: str = "") -> str:
    """Generate JWT token valid for 90 days."""
    payload = {
        "user_id": user_id,
        "email": email,
        "display_name": display_name,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=90)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def verify_token(token: str) -> dict | None:
    """Verify JWT token. Returns payload dict on success, None on failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return {
            "user_id": payload.get("user_id"),
            "email": payload.get("email"),
            "display_name": payload.get("display_name", ""),
        }
    except jwt.PyJWTError:
        return None
