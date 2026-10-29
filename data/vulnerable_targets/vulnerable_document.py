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
    INTENTIONALLY VULNERABLE BENCHMARK FIXTURE
    CWE-22: Path Traversal.

    User-controlled filename is joined to DOCUMENT_ROOT without
    checking whether the resolved path remains inside that directory.
    """
    file_path = DOCUMENT_ROOT / request.filename

    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found")
    except IsADirectoryError:
        raise HTTPException(status_code=400, detail="Expected a document")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Unsupported document format")


@app.get("/health")
def health():
    return {"status": "ok"}
