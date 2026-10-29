import re
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Network Diagnostics API",
    description="Internal network connectivity diagnostic service",
)


class PingRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)


def _is_valid_hostname(hostname: str) -> bool:
    # Allow typical DNS hostnames (letters, digits, hyphens, dots)
    return bool(re.fullmatch(r"[a-zA-Z0-9.-]+", hostname))


@app.post("/api/diagnostics/ping")
def ping_host(request: PingRequest):
    """
    Secure implementation of the ping diagnostic endpoint.
    The hostname is validated and passed to subprocess without shell=True,
    eliminating OS command injection risks.
    """
    if not _is_valid_hostname(request.hostname):
        raise HTTPException(
            status_code=400,
            detail="Invalid hostname format",
        )

    command = ["ping", "-c", "1", "-W", "2", request.hostname]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Network diagnostic timed out",
        )

    return {
        "hostname": request.hostname,
        "return_code": result.returncode,
        "output": result.stdout[-3000:],
        "error": result.stderr[-1000:],
    }


@app.get("/health")
def health():
    return {"status": "ok"}