from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Document Management API")

# Keep benchmark files isolated in this directory.
DOCUMENT_ROOT = Path(__file__).resolve().parent / "documents"


class DocumentRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)


@app.post("/api/documents/read", response_class=PlainTextResponse)
def read_document(request: DocumentRequest):
    """
    Secure implementation: ensure the resolved path is strictly within DOCUMENT_ROOT.
    """
    # Resolve the requested file path and normalize it.
    file_path = (DOCUMENT_ROOT / request.filename).resolve()

    # Verify that the resolved path is still inside DOCUMENT_ROOT.
    if not file_path.is_relative_to(DOCUMENT_ROOT):
        raise HTTPException(status_code=400, detail="Access to files outside the document root is prohibited")

    # Ensure the path points to a regular file (not a directory).
    if not file_path.is_file():
        raise HTTPException(status_code=400, detail="Expected a document")

    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Unsupported document format")


@app.get("/health")
def health():
    return {"status": "ok"}