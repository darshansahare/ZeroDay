import os
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Payment Gateway Integration")

# Load credentials from secure environment configuration
PAYMENT_API_KEY = os.getenv("PAYMENT_API_KEY")
PAYMENT_MERCHANT_ID = os.getenv("PAYMENT_MERCHANT_ID")
if not PAYMENT_API_KEY or not PAYMENT_MERCHANT_ID:
    raise RuntimeError("PAYMENT_API_KEY and PAYMENT_MERCHANT_ID must be set in the environment")

class PaymentRequest(BaseModel):
    order_id: str = Field(..., min_length=1, max_length=64)
    amount: int = Field(..., gt=0, le=100000)

def create_payment_reference(order_id: str, amount: int) -> dict:
    reference_input = (
        f"{PAYMENT_API_KEY}:{PAYMENT_MERCHANT_ID}:"
        f"{order_id}:{amount}"
    )
    reference = hashlib.sha256(reference_input.encode("utf-8")).hexdigest()[:16]
    return {
        "order_id": order_id,
        "amount": amount,
        "merchant_id": PAYMENT_MERCHANT_ID,
        "payment_reference": reference,
    }

@app.post("/api/payments/prepare")
def prepare_payment(request: PaymentRequest):
    try:
        return create_payment_reference(request.order_id, request.amount)
    except ValueError:
        raise HTTPException(status_code=400, detail="Unable to prepare payment")

@app.get("/health")
def health():
    return {"status": "ok"}