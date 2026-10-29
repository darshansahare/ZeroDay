from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Invoice Management API")

# Demo data for a local security benchmark.
USERS = {
    "token-darshan": {"id": 1, "name": "Darshan"},
    "token-priya": {"id": 2, "name": "Priya"},
}

INVOICES = {
    101: {
        "id": 101,
        "owner_id": 1,
        "description": "Laptop repair",
        "amount": 2500,
    },
    102: {
        "id": 102,
        "owner_id": 2,
        "description": "Consulting services",
        "amount": 8500,
    },
}


class InvoiceResponse(BaseModel):
    id: int
    owner_id: int
    description: str
    amount: int


def get_current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = authorization.removeprefix("Bearer ")
    user = USERS.get(token)

    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user


@app.get("/api/invoices/{invoice_id}", response_model=InvoiceResponse)
def get_invoice(
    invoice_id: int,
    authorization: str | None = Header(default=None),
):
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-639: Authorization Bypass Through User-Controlled Key.

    Authentication is performed, but invoice ownership is not checked.
    """
    current_user = get_current_user(authorization)

    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=404, detail="Invoice not found")

    # VULNERABILITY: current_user is never checked against owner_id.
    return invoice


@app.get("/health")
def health():
    return {"status": "ok"}
