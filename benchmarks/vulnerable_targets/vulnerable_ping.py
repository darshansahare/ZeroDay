import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="Network Diagnostics API",
    description="Internal network connectivity diagnostic service",
)


class PingRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)


@app.post("/api/diagnostics/ping")
def ping_host(request: PingRequest):
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-78: OS Command Injection

    The hostname comes from an HTTP request and is interpolated
    into a shell command. Input length validation does not make
    shell interpolation safe.
    """
    command = f"ping -c 1 -W 2 {request.hostname}"

    try:
        result = subprocess.run(
            command,
            shell=True,
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
