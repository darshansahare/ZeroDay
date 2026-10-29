from decimal import Decimal

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Shopping Cart API")

PRODUCTS = {
    "LAPTOP": Decimal("55000.00"),
    "MOUSE": Decimal("799.00"),
}


class CartRequest(BaseModel):
    product_code: str
    quantity: int


@app.post("/api/cart/total")
def calculate_cart_total(request: CartRequest):
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-20: Improper Input Validation.

    The API accepts a quantity without checking that it is positive
    or within the application's permitted order limits.
    """
    product_price = PRODUCTS.get(request.product_code)

    if product_price is None:
        return {
            "error": "Unknown product",
        }

    # VULNERABILITY: quantity has no business-rule validation.
    total = product_price * request.quantity

    return {
        "product_code": request.product_code,
        "quantity": request.quantity,
        "unit_price": str(product_price),
        "total": str(total),
    }


@app.get("/health")
def health():
    return {"status": "ok"}
