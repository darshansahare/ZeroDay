import base64
import pickle

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="User Preferences Import API")


class ImportRequest(BaseModel):
    serialized_data: str = Field(..., min_length=1, max_length=10000)


@app.post("/api/preferences/import")
def import_preferences(request: ImportRequest):
    """
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-502: Deserialization of Untrusted Data.

    The endpoint accepts a client-supplied serialized object
    and deserializes it with pickle.
    """
    try:
        raw_data = base64.b64decode(
            request.serialized_data,
            validate=True,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid Base64 data",
        )

    try:
        # VULNERABILITY: pickle can execute code while deserializing.
        preferences = pickle.loads(raw_data)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid serialized preferences",
        )

    if not isinstance(preferences, dict):
        raise HTTPException(
            status_code=400,
            detail="Preferences must be an object",
        )

    return {"preferences": preferences}


@app.get("/health")
def health():
    return {"status": "ok"}
