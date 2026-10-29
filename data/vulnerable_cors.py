from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Customer Account API")

# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
# Reflects arbitrary request origins and allows credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
