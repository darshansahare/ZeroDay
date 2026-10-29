"""
Target Microservice: Clean Snapshot Copy for Deterministic Rollback
ZeroDay Arena Self-Healing Platform
"""

import sqlite3
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel

app = FastAPI(
    title="Financial Orders Sandbox Microservice",
    description="Vulnerable target app used for adversarial security benchmarks",
    version="1.0.4-dev"
)

import os

def get_db_connection() -> sqlite3.Connection:
    db_path = os.getenv("ZDA_TARGET_DB_PATH", "sandbox_orders.db")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DROP TABLE IF EXISTS orders")
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS products")
    
    cursor.execute("""
    CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        api_token TEXT NOT NULL
    )
    """)
    
    cursor.execute("""
    CREATE TABLE products (
        product_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        inventory INTEGER NOT NULL
    )
    """)
    
    cursor.execute("""
    CREATE TABLE orders (
        order_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        total_amount REAL NOT NULL,
        credit_card TEXT NOT NULL,
        ssn_last4 TEXT NOT NULL,
        secret_notes TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )
    """)
    
    cursor.execute("INSERT INTO users VALUES ('USR-101', 'Alice Vance', 'Customer', 'tok_live_alice_84920')")
    cursor.execute("INSERT INTO users VALUES ('USR-102', 'Bob Stone', 'Customer', 'tok_live_bob_99120')")
    cursor.execute("INSERT INTO users VALUES ('USR-103', 'Charlie Root', 'SuperAdmin', 'tok_root_master_00192')")
    
    cursor.execute("INSERT INTO products VALUES ('PROD-01', 'Quantum Encryption Key', 1250.00, 45)")
    cursor.execute("INSERT INTO products VALUES ('PROD-02', 'Neural Coprocessor Blade', 420.50, 120)")
    cursor.execute("INSERT INTO products VALUES ('PROD-03', 'Enterprise Zero-Trust Sentinel', 9900.00, 10)")
    
    cursor.execute("""
    INSERT INTO orders VALUES (
        'ORD-9021', 'USR-101', 1250.00, '4111-XXXX-XXXX-9912', '8492', 'Corporate procurement - expedited delivery'
    )
    """)
    cursor.execute("""
    INSERT INTO orders VALUES (
        'ORD-9022', 'USR-102', 420.50, '5500-XXXX-XXXX-1123', '3120', 'Consumer test purchase - cleared'
    )
    """)
    cursor.execute("""
    INSERT INTO orders VALUES (
        'ORD-9099', 'USR-103', 99000.00, '3782-XXXX-XXXX-0001', '0042', 'CLASSIFIED: ZeroDay bounty escrow vault allocation'
    )
    """)
    
    conn.commit()
    conn.close()

init_db()

class OrderCreateRequest(BaseModel):
    user_id: str
    product_id: str
    quantity: int

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "orders-vulnerable-microservice",
        "environment": "sandboxed-execution",
        "version": "1.0.4-dev"
    }

@app.get("/api/products")
async def get_products():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT product_id, name, price, inventory FROM products")
    rows = cursor.fetchall()
    conn.close()
    return [{"product_id": r["product_id"], "name": r["name"], "price": r["price"], "inventory": r["inventory"]} for r in rows]

@app.post("/api/orders/create", status_code=status.HTTP_201_CREATED)
async def create_order(payload: OrderCreateRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT price, inventory FROM products WHERE product_id = ?", (payload.product_id,))
    prod = cursor.fetchone()
    if not prod:
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")
        
    order_id = f"ORD-{len(payload.user_id)}890"
    total = prod["price"] * payload.quantity
    
    cursor.execute(
        "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
        (order_id, payload.user_id, total, "4000-XXXX-XXXX-0000", "9999", "Automated system generated order")
    )
    conn.commit()
    conn.close()
    return {"order_id": order_id, "user_id": payload.user_id, "total_amount": total, "status": "confirmed"}

@app.get("/api/orders")
async def get_orders(user_id: str = Query(..., description="Target User ID")):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # SINK: Vulnerable unparameterized string formatting
    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
    cursor.execute(query)
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "order_id": r["order_id"],
            "user_id": r["user_id"],
            "total_amount": r["total_amount"],
            "credit_card": r["credit_card"],
            "ssn_last4": r["ssn_last4"],
            "secret_notes": r["secret_notes"]
        })
    return {"count": len(results), "records": results}

@app.get("/api/user/{user_id}/profile")
async def get_user_profile(user_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, full_name, role, api_token FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user_id": user["user_id"],
        "full_name": user["full_name"],
        "role": user["role"],
        "api_token": user["api_token"]
    }
