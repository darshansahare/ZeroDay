from fastapi import FastAPI, Response
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
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE

    CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute.
    CWE-1004: Sensitive Cookie Without HttpOnly Attribute.
    """
    if USERS.get(request.username) != request.password:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # VULNERABILITY: session cookie omits Secure and HttpOnly.
    # SameSite is also omitted.
    response.set_cookie(
        key="session_id",
        value="demo-session-token-9f82",
        httponly=False,
        secure=False,
        samesite=None,
        path="/",
    )

    return {"message": "Login successful"}


@app.get("/health")
def health():
    return {"status": "ok"}
