from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Secure Document Service")

DOCUMENT_ROOT = (Path(__file__).resolve().parent / "documents").resolve()


@app.get("/api/documents/{filename}", response_class=PlainTextResponse)
def download_document(filename: str):
    """Serve documents only from the permitted directory."""

    # Resolve the requested path, including any traversal components.
    requested_path = (DOCUMENT_ROOT / filename).resolve()

    # Reject paths that escape the document root.
    try:
        requested_path.relative_to(DOCUMENT_ROOT)
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail="Access to this document is not permitted",
        )

    if not requested_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    try:
        return requested_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise HTTPException(
            status_code=400,
            detail="Unable to read document",
        )


@app.get("/health")
def health():
    return {"status": "ok"}
