import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from pwdlib import PasswordHash

app = FastAPI(title="Secure Authentication API")

DATABASE_PATH = Path(__file__).with_name("users.db")
password_hash = PasswordHash.recommended()


def initialize_database():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
            """
        )


initialize_database()


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=80)
    password: str = Field(..., min_length=1, max_length=128)


@app.post("/api/login")
def login(request: LoginRequest):
    with sqlite3.connect(DATABASE_PATH) as connection:
        row = connection.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (request.username,),
        ).fetchone()

    if row is None or not password_hash.verify(request.password, row[1]):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    return {"message": "Login successful", "username": row[0]}


@app.get("/health")
def health():
    return {"status": "ok"}
