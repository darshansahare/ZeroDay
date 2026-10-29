import ipaddress
import socket
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Link Preview API")


class PreviewRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


def _is_allowed_host(host: str) -> bool:
    """Return True if the host is a public, routable address."""
    try:
        ip = ipaddress.ip_address(host)
        # Private, reserved, loopback, link‑local, or multicast addresses are unsafe
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        # Not a valid IP address – treat as unsafe
        return False


@app.post("/api/preview")
def preview_url(request: PreviewRequest):
    """
    Secure implementation of the link‑preview endpoint.
    The URL is validated to prevent Server‑Side Request Forgery (SSRF).
    """
    parsed = urlparse(request.url)

    # Enforce a safe scheme
    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="Only http and https URLs are allowed",
        )

    # Validate the host is public and routable
    host = parsed.hostname or ""
    if not host or not _is_allowed_host(host):
        raise HTTPException(
            status_code=400,
            detail="Destination host is not allowed",
        )

    # Optional: reject URLs that contain credentials
    if "@" in request.url:
        raise HTTPException(
            status_code=400,
            detail="URLs with authentication are not allowed",
        )

    try:
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