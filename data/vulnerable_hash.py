import hashlib
import sqlite3

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Account Registration API")

DATABASE = ":memory:"

# Demo database for this benchmark fixture.
conn = sqlite3.connect(DATABASE, check_same_thread=False)
conn.execute(
    """
    CREATE TABLE accounts (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )
    """
)
conn.commit()


class RegistrationRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=1, max_length=128)


def hash_password(password: str) -> str:
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-328: Use of Weak Hash.

    MD5 is fast and unsuitable for password storage.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


@app.post("/api/accounts/register")
def register_account(request: RegistrationRequest):
    password_hash = hash_password(request.password)

    try:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (request.username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")

    return {
        "username": request.username,
        "password_hash": password_hash,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
