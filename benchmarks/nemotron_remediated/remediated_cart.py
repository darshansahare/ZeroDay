from decimal import Decimal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Shopping Cart API")

PRODUCTS = {
    "LAPTOP": Decimal("55000.00"),
    "MOUSE": Decimal("799.00"),
}

MAX_QUANTITY = 1000


class CartRequest(BaseModel):
    product_code: str
    quantity: int = Field(..., gt=0, le=MAX_QUANTITY)


@app.post("/api/cart/total")
def calculate_cart_total(request: CartRequest):
    product_price = PRODUCTS.get(request.product_code)
    if product_price is None:
        raise HTTPException(status_code=400, detail="Unknown product")
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