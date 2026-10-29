"""
Functional Regression Test Suite for Target Microservice
Ensures that standard business operations continue working as expected
before, during, and after autonomous security patch remediation.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from target_app.app import app, init_db

@pytest.fixture(autouse=True)
def setup_database():
    """Ensure clean test database state before each test run."""
    init_db()

@pytest.fixture
def client():
    return TestClient(app)

def test_health_check(client):
    """Verify microservice health check endpoint responds with 200 OK."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "orders-vulnerable-microservice" in data["service"]

def test_get_products(client):
    """Verify catalog retrieval returns valid items."""
    response = client.get("/api/products")
    assert response.status_code == 200
    products = response.json()
    assert isinstance(products, list)
    assert len(products) >= 3
    product_names = [p["name"] for p in products]
    assert "Quantum Encryption Key" in product_names

def test_create_order(client):
    """Verify order creation pipeline processes valid input and generates confirmation."""
    payload = {
        "user_id": "USR-101",
        "product_id": "PROD-01",
        "quantity": 2
    }
    response = client.post("/api/orders/create", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["user_id"] == "USR-101"
    assert data["total_amount"] == 2500.00
    assert data["status"] == "confirmed"

def test_legitimate_order_query(client):
    """Verify legitimate order retrieval for an authenticated customer returns their exact record."""
    response = client.get("/api/orders?user_id=USR-101")
    assert response.status_code == 200
    data = response.json()
    assert "records" in data
    assert data["count"] >= 1
    # Ensure Alice's record is found
    alice_orders = [r for r in data["records"] if r["order_id"] == "ORD-9021"]
    assert len(alice_orders) == 1
    assert alice_orders[0]["user_id"] == "USR-101"

def test_nonexistent_user_order_query(client):
    """Verify querying an unknown user returns an empty list with 0 records."""
    response = client.get("/api/orders?user_id=USR-DOES-NOT-EXIST")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert data["records"] == []
