from fastapi import FastAPI, Response, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Customer Portal Authentication")

# Demo credentials for this isolated benchmark fixture.
USERS = {
    "darshan": "demo-password-123",
}


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


@app.post("/api/login")
def login(request: LoginRequest, response: Response):
    """
    Fixed session cookie configuration:
    - Secure flag set to True (sent only over HTTPS)
    - HttpOnly flag set to True (not accessible via JavaScript)
    - SameSite set to "lax" to mitigate CSRF while allowing safe cross‑site navigation
    """
    if USERS.get(request.username) != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    response.set_cookie(
        key="session_id",
        value="demo-session-token-9f82",
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    return {"message": "Login successful"}


@app.get("/health")
def health():
    return {"status": "ok"}