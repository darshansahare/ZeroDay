import base64
import json
import pickle

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="User Preferences Import API")


class ImportRequest(BaseModel):
    serialized_data: str = Field(..., min_length=1, max_length=10000)


@app.post("/api/preferences/import")
def import_preferences(request: ImportRequest):
    """
    SECURE REPLACEMENT FOR PICKLE DESERIALIZATION.
    CWE-502: Deserialization of Untrusted Data is eliminated by using JSON.
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
        # Use JSON for safe deserialization; no code execution possible.
        preferences = json.loads(raw_data)
    except json.JSONDecodeError:
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