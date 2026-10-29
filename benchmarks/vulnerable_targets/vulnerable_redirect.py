from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse

app = FastAPI(title="Authentication Redirect Service")


@app.get("/login/callback")
def login_callback(
    next: str = Query(default="/dashboard", max_length=2048),
):
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-601: URL Redirection to Untrusted Site.

    The application redirects to a user-controlled URL without
    validating the destination.
    """
    # VULNERABILITY: untrusted redirect destination.
    return RedirectResponse(
        url=next,
        status_code=302,
    )


@app.get("/dashboard")
def dashboard():
    return {"message": "Welcome to your dashboard"}


@app.get("/health")
def health():
    return {"status": "ok"}
