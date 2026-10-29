from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse

app = FastAPI(title="Authentication Redirect Service")

# Define allowed internal redirect paths
ALLOWED_REDIRECT_PATHS = {"/dashboard", "/health"}

@app.get("/login/callback")
def login_callback(
    next: str = Query(default="/dashboard", max_length=2048),
):
    """
    Fixed: Only allow redirects to known internal paths.
    """
    # Ensure the redirect target is a safe internal path
    if next not in ALLOWED_REDIRECT_PATHS:
        next = "/dashboard"
    return RedirectResponse(url=next, status_code=302)


@app.get("/dashboard")
def dashboard():
    return {"message": "Welcome to your dashboard"}


@app.get("/health")
def health():
    return {"status": "ok"}