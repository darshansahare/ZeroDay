import urllib3
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Partner Integration API")

# Safe urllib3 version >= 2.0.7 / >= 1.26.18 pinned in requirements.txt
http = urllib3.PoolManager()

ALLOWED_PARTNER_HOSTS = {"partner.example.com", "api.trustedpartner.com"}


class PartnerRequest(BaseModel):
    partner_url: str = Field(..., min_length=1, max_length=2048)


@app.post("/api/partner/status")
def get_partner_status(request: PartnerRequest):
    """
    Patched partner status endpoint with URL validation and safe urllib3 dependency.
    """
    parsed = urlparse(request.partner_url)
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Only HTTPS partner URLs are supported",
        )

    if parsed.hostname not in ALLOWED_PARTNER_HOSTS:
        raise HTTPException(
            status_code=403,
            detail="Partner domain not in authorized allowlist",
        )

    try:
        response = http.request(
            "GET",
            request.partner_url,
            timeout=urllib3.Timeout(connect=2.0, read=3.0),
            retries=False,
        )
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Partner service unavailable",
        )

    return {
        "status_code": response.status,
        "response_bytes": len(response.data),
    }


@app.get("/health")
def health():
    return {"status": "ok"}
