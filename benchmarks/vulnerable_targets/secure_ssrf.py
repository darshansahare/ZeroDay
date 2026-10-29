from ipaddress import ip_address
from urllib.parse import urlparse
import socket

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

app = FastAPI(title="Secure URL Preview")

ALLOWED_PORTS = {80, 443}


class PreviewRequest(BaseModel):
    url: HttpUrl


def validate_public_destination(url: HttpUrl) -> str:
    parsed = urlparse(str(url))

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Unsupported URL scheme")

    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URL credentials are not allowed")

    if parsed.port and parsed.port not in ALLOWED_PORTS:
        raise HTTPException(status_code=400, detail="Port not allowed")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid hostname")

    try:
        results = socket.getaddrinfo(
            hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Hostname could not be resolved")

    if not results:
        raise HTTPException(status_code=400, detail="No destination addresses found")

    for result in results:
        address = ip_address(result[4][0])
        if not address.is_global:
            raise HTTPException(
                status_code=400,
                detail="Non-public destinations are not allowed"
            )

    return str(url)


@app.post("/api/preview")
async def preview_url(request: PreviewRequest):
    target = validate_public_destination(request.url)

    # Redirects are disabled so a public URL cannot redirect the client
    # to a private or otherwise forbidden destination.
    timeout = httpx.Timeout(5.0, connect=2.0)

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            trust_env=False
        ) as client:
            response = await client.get(target)
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Unable to fetch URL")

    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "preview": response.text[:500]
    }
