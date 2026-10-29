import urllib3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Partner Integration API")

# The dependency version is intentionally pinned in requirements.txt.
http = urllib3.PoolManager()


class PartnerRequest(BaseModel):
    partner_url: str = Field(..., min_length=1, max_length=2048)


@app.post("/api/partner/status")
def get_partner_status(request: PartnerRequest):
    """
    Dependency benchmark fixture.

    The dependency scanner should inspect requirements.txt and
    resolve urllib3 against known vulnerability advisories.
    """
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
