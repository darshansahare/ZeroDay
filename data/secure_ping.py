import ipaddress
import platform
import subprocess

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="Secure Network Diagnostics")


class PingRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        value = value.strip()

        # Accept IP addresses for this diagnostic endpoint.
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("A valid IP address is required")

        return value


@app.post("/api/diagnostics/ping")
def ping_host(request: PingRequest):
    """Run a ping command without shell interpretation."""
    count_flag = "-n" if platform.system() == "Windows" else "-c"

    command = [
        "ping",
        count_flag,
        "1",
        str(request.host),
    ]

    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Diagnostic timed out",
        )
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Diagnostic command unavailable",
        )

    return {
        "host": request.host,
        "reachable": result.returncode == 0,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
