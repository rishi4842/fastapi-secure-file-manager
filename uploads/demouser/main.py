from pathlib import Path

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Header,
    UploadFile,
    File,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html

from db import init_db, get_connection

app = FastAPI()
init_db()

# serve static files for custom CSS
app.mount("/static", StaticFiles(directory="static"), name="static")

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# in-memory store for OTPs
pending_otp = {}  # username -> otp string


# --------------- AUTH HELPERS --------------- #

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.replace("Bearer ", "", 1)
    if not token.startswith("token-"):
        raise HTTPException(status_code=401, detail="Invalid token")
    username = token.replace("token-", "", 1)
    return {"username": username}


def log_security_event(username: str, event_type: str, details: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO security_events (username, event_type, details) VALUES (?, ?, ?)",
        (username, event_type, details),
    )
    conn.commit()
    conn.close()


# --------------- AUTH ENDPOINTS --------------- #

@app.post("/register")
def register(username: str, password: str):
    """
    Register user; password stored in clear text for demo.
    """
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
    """
    Step 1 of 2FA: username + password.
    """
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

    # generate 6-digit OTP
    import random

    otp = f"{random.randint(100000, 999999)}"
    pending_otp[username] = otp

    # in real system, OTP is sent via email/SMS
    return {"message": "OTP generated (demo only)", "otp": otp}


@app.post("/login-step2")
def login_step2(username: str, otp: str):
    """
    Step 2 of 2FA: OTP.
    """
    expected = pending_otp.get(username)
    if not expected or expected != otp:
        log_security_event(username, "otp_failed", "Wrong or missing OTP in step2")
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

    # basic threat detection: extensions & size
    dangerous_ext = {".exe", ".bat", ".sh"}
    ext = Path(file.filename).suffix.lower()
    if ext in dangerous_ext:
        log_security_event(
            username,
            "blocked_upload",
            f"Blocked dangerous extension: {file.filename}",
        )
        raise HTTPException(
            status_code=400,
            detail="Potential malware file blocked",
        )

    data = file.file.read()
    max_size = 10 * 1024 * 1024  # 10 MB
    if len(data) > max_size:
        log_security_event(
            username,
            "blocked_upload",
            f"File too large: {file.filename} size={len(data)}",
        )
        raise HTTPException(
            status_code=400,
            detail="File too large; possible DoS / overflow attempt",
        )

    # save to disk
    user_dir = UPLOAD_DIR / username
    user_dir.mkdir(exist_ok=True)
    destination = user_dir / file.filename
    with destination.open("wb") as out_file:
        out_file.write(data)

    size = destination.stat().st_size

    # store metadata
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO files (owner, filename, path, size, shared_with) VALUES (?, ?, ?, ?, ?)",
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
        "SELECT id, filename, size, shared_with FROM files WHERE owner = ? OR instr(ifnull(shared_with,''), ?) > 0",
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
def download_file(file_id: int, current_user: dict = Depends(get_current_user)):
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

    shared_with = row["shared_with"] or ""
    allowed = (
        row["owner"] == username
        or username in [u for u in shared_with.split(",") if u]
    )
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

    current = row["shared_with"] or ""
    users = {u for u in current.split(",") if u}
    users.add(target_username)
    new_value = ",".join(users)

    cur.execute(
        "UPDATE files SET shared_with = ? WHERE id = ?",
        (new_value, file_id),
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


