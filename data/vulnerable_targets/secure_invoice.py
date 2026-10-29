from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Secure Invoice API")

# Demo-only data. In production, use a database and verified authentication.
USERS = {
    "token-darshan": "user-1",
    "token-priya": "user-2",
}

INVOICES = {
    "INV-101": {"owner_id": "user-1", "amount": 1200},
    "INV-202": {"owner_id": "user-2", "amount": 2500},
}


def authenticate(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = authorization.removeprefix("Bearer ")
    user_id = USERS.get(token)

    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return user_id


@app.get("/invoices/{invoice_id}")
def get_invoice(
    invoice_id: str,
    authorization: str | None = Header(default=None),
):
    user_id = authenticate(authorization)

    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=404, detail="Invoice not found")

    # Authorization must be checked for every requested object.
    if invoice["owner_id"] != user_id:
        # Return 404 to avoid revealing another user's invoice existence.
        raise HTTPException(status_code=404, detail="Invoice not found")

    return {
        "invoice_id": invoice_id,
        "amount": invoice["amount"],
    }
