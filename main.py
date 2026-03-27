from pathlib import Path
import random

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    UploadFile,
    File,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from db import init_db, get_connection


# ---------------- APP & SETUP ---------------- #

app = FastAPI(
    title="Secure File Manager API",
    description="Secure upload, download and sharing with 2FA and basic threat detection.",
    version="1.0.0",
)

init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

pending_otp = {}

security = HTTPBearer()


# --------------- AUTH HELPERS --------------- #

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials

    if not token.startswith("token-"):
        raise HTTPException(status_code=401, detail="Invalid token")

    username = token.replace("token-", "", 1)
    return {"username": username}


def log_security_event(username: str, event_type: str, details: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO security_events (username, event_type, details) "
        "VALUES (?, ?, ?)",
        (username, event_type, details),
    )
    conn.commit()
    conn.close()


# --------------- AUTH ENDPOINTS --------------- #

@app.post("/register")
def register(username: str, password: str):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="User already exists")
    conn.close()
    return {"message": "User registered"}


@app.post("/login-step1")
def login_step1(username: str, password: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()

    if not row or row["password_hash"] != password:
        log_security_event(username, "login_failed", "Invalid credentials in step1")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    otp = f"{random.randint(100000, 999999)}"
    pending_otp[username] = otp

    return {"message": "OTP generated (demo only)", "otp": otp}


@app.post("/login-step2")
def login_step2(username: str, otp: str):
    expected = pending_otp.get(username)
    if not expected or expected != otp:
        log_security_event(username, "otp_failed", "Wrong OTP in step2")
        raise HTTPException(status_code=400, detail="Invalid OTP")

    pending_otp.pop(username, None)
    token = f"token-{username}"
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def read_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}


# --------------- FILE ENDPOINTS --------------- #

@app.post("/files/upload")
def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    username = current_user["username"]

    dangerous_ext = {".exe", ".bat", ".sh"}
    ext = Path(file.filename).suffix.lower()
    if ext in dangerous_ext:
        log_security_event(username, "blocked_upload", file.filename)
        raise HTTPException(status_code=400, detail="Potential malware file blocked")

    data = file.file.read()
    if len(data) > 10 * 1024 * 1024:
        log_security_event(username, "blocked_upload", "File too large")
        raise HTTPException(status_code=400, detail="File too large")

    user_dir = UPLOAD_DIR / username
    user_dir.mkdir(exist_ok=True)
    destination = user_dir / file.filename
    with destination.open("wb") as f:
        f.write(data)

    size = destination.stat().st_size

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO files (owner, filename, path, size, shared_with) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, file.filename, str(destination), size, None),
    )
    conn.commit()
    file_id = cur.lastrowid
    conn.close()

    return {
        "id": file_id,
        "owner": username,
        "filename": file.filename,
        "size": size,
    }


@app.get("/files")
def list_my_files(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, filename, size, shared_with "
        "FROM files "
        "WHERE owner = ? OR instr(ifnull(shared_with,''), ?) > 0",
        (username, username),
    )
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "filename": row["filename"],
            "size": row["size"],
            "shared_with": row["shared_with"],
        }
        for row in rows
    ]


@app.get("/files/{file_id}")
def download_file(
    file_id: int,
    current_user: dict = Depends(get_current_user),
):
    username = current_user["username"]
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT owner, path, filename, shared_with FROM files WHERE id = ?",
        (file_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="File not found")

    shared = row["shared_with"] or ""
    allowed = row["owner"] == username or username in shared.split(",")

    if not allowed:
        raise HTTPException(status_code=403, detail="Not allowed")

    return FileResponse(
        path=row["path"],
        filename=row["filename"],
        media_type="application/octet-stream",
    )


@app.post("/files/{file_id}/share")
def share_file(
    file_id: int,
    target_username: str,
    current_user: dict = Depends(get_current_user),
):
    username = current_user["username"]
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT owner, shared_with FROM files WHERE id = ?",
        (file_id,),
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")

    if row["owner"] != username:
        conn.close()
        raise HTTPException(status_code=403, detail="Not allowed")

    users = set((row["shared_with"] or "").split(","))
    users.discard("")
    users.add(target_username)

    cur.execute(
        "UPDATE files SET shared_with = ? WHERE id = ?",
        (",".join(users), file_id),
    )
    conn.commit()
    conn.close()

    return {"message": "File shared", "shared_with": list(users)}


# --------------- CUSTOM SWAGGER UI --------------- #

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title="Secure File Manager API - Docs",
        swagger_css_url="/static/custom.css",
    )
