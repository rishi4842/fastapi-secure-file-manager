# 🔐 Secure File Manager API

A secure backend system built using **FastAPI** that allows users to upload, download, and share files with authentication and basic threat protection.

---

## 🚀 Live Demo
👉 https://fastapi-secure-file-manager.onrender.com/docs

---

## 🧠 Features

- 🔐 JWT Authentication (Login system)
- 👤 User Registration & Login (2-step login)
- 📁 File Upload & Download
- 📤 File Sharing
- 🛡️ Basic Security & Validation
- 📄 Swagger UI for API testing

---

## 🛠️ Tech Stack

- **Backend:** FastAPI (Python)
- **Auth:** JWT (python-jose)
- **Server:** Uvicorn
- **Deployment:** Render
- **Storage:** Local file system

---

## 📌 API Endpoints

| Method | Endpoint | Description |
|--------|--------|-------------|
| POST | /register | Register user |
| POST | /login-step1 | Login step 1 |
| POST | /login-step2 | Login step 2 |
| GET | /me | Get user details |
| POST | /files/upload | Upload file |
| GET | /files | List files |
| GET | /files/{file_id} | Download file |
| POST | /files/{file_id}/share | Share file |

---

## ⚙️ Installation (Local Setup)

```bash
git clone https://github.com/rishi4842/fastapi-secure-file-manager.git
cd fastapi-secure-file-manager

pip install -r requirements.txt
uvicorn main:app --reload
