import hashlib

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Payment Gateway Integration")

# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
# Fake, nonfunctional credential for testing only.
PAYMENT_API_KEY = "sk_test_ZERODAY_FAKE_CREDENTIAL_7f3a91c2"
PAYMENT_MERCHANT_ID = "merchant_demo_4821"


class PaymentRequest(BaseModel):
    order_id: str = Field(..., min_length=1, max_length=64)
    amount: int = Field(..., gt=0, le=100000)


def create_payment_reference(order_id: str, amount: int) -> dict:
    """
    CWE-798: Use of Hard-coded Credentials.

    The API credential is embedded in the source instead of
    being supplied through secure configuration.
    """
    # Demonstrates a credential being used in integration code.
    # This does not contact a real payment provider.
    reference_input = (
        f"{PAYMENT_API_KEY}:{PAYMENT_MERCHANT_ID}:"
        f"{order_id}:{amount}"
    )

    reference = hashlib.sha256(
        reference_input.encode("utf-8")
    ).hexdigest()[:16]

    return {
        "order_id": order_id,
        "amount": amount,
        "merchant_id": PAYMENT_MERCHANT_ID,
        "payment_reference": reference,
    }


@app.post("/api/payments/prepare")
def prepare_payment(request: PaymentRequest):
    try:
        return create_payment_reference(
            request.order_id,
            request.amount,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Unable to prepare payment",
        )


@app.get("/health")
def health():
    return {"status": "ok"}
