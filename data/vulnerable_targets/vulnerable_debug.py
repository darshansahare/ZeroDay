import os

import uvicorn
from fastapi import FastAPI

# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
# Debug mode is enabled by default, including in production.
DEBUG = os.getenv("APP_DEBUG", "true").lower() == "true"

app = FastAPI(
    title="Customer Support API",
    debug=DEBUG,
)


@app.get("/api/support/ticket/{ticket_id}")
def get_ticket(ticket_id: int):
    # Simulated application logic for the benchmark.
    if ticket_id <= 0:
        raise ValueError("Ticket ID must be positive")

    return {
        "ticket_id": ticket_id,
        "status": "open",
        "subject": "Account access issue",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=DEBUG,
    )
