import ipaddress
import socket
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Link Preview API")


class PreviewRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


@app.post("/api/preview")
def preview_url(request: PreviewRequest):
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-918: Server-Side Request Forgery.

    The service fetches a client-provided URL without validating
    whether its destination is safe for the server to contact.
    """
    try:
        # VULNERABILITY: untrusted URL is fetched directly.
        response = requests.get(
            request.url,
            timeout=5,
            allow_redirects=True,
        )
        response.raise_for_status()
    except requests.RequestException:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve preview",
        )

    return {
        "requested_url": request.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "preview": response.text[:1000],
    }


@app.get("/health")
def health():
    return {"status": "ok"}
