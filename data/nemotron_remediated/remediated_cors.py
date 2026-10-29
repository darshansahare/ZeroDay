from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Customer Account API")

# Explicitly define allowed origins – no wildcard.
ALLOWED_ORIGINS = [
    "https://example.com",
    "https://frontend.example.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,          # Disallow credentials with any origin
    allow_methods=["GET"],            # Restrict to methods actually used
    allow_headers=["Content-Type"],   # Restrict to necessary headers
)


@app.get("/api/account")
def get_account():
    return {
        "account_id": "ACC-1001",
        "customer_name": "Demo Customer",
        "plan": "premium",
    }


@app.get("/health")
def health():
    return {"status": "ok"}