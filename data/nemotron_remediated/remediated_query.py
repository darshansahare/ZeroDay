import sqlite3
from fastapi import FastAPI, HTTPException

app = FastAPI()


def run_query_secure(username: str):
    """Execute a safe in‑memory SQLite query for the given username."""
    with sqlite3.connect(":memory:") as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (username TEXT, role TEXT)")
        cur.executemany(
            "INSERT INTO users VALUES (?, ?)",
            [("darshan", "user"), ("admin", "admin")],
        )
        cur.execute(
            "SELECT username, role FROM users WHERE username = ?",
            (username,),
        )
        return cur.fetchall()


@app.get("/query")
def query_endpoint(username: str):
    """FastAPI endpoint that returns user data for the supplied username."""
    results = run_query_secure(username)
    if not results:
        raise HTTPException(status_code=404, detail="User not found")
    return results