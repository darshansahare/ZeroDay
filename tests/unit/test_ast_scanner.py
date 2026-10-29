"""
Unit tests for app.analysis.ast_scanner.ASTReconScanner.
Verifies detection of vulnerable SQL patterns, exclusion of safe patterns,
error resilience on syntax failures, and route extraction.
"""

from pathlib import Path
import pytest

from app.config import AppConfig
from app.analysis.ast_scanner import ASTReconScanner
from app.analysis.findings import EvidenceStatus, Severity, VulnerabilityClass


@pytest.fixture
def scanner():
    root = Path(__file__).parent.parent.parent.resolve()
    config = AppConfig(workspace_root=root)
    return ASTReconScanner(config=config)


def test_detects_vulnerable_sql_patterns(scanner):
    """Verify all 4 vulnerable patterns are detected and safe queries are excluded."""
    fixture_path = "tests/fixtures/sample_code.py"
    report = scanner.scan_path(fixture_path)

    assert report.scanned_files_count == 1
    assert len(report.findings) == 4

    for finding in report.findings:
        assert finding.vulnerability_class == VulnerabilityClass.SQL_INJECTION
        assert finding.cwe == "CWE-89"
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence_status == EvidenceStatus.STATIC_SUSPICION
        assert "cursor.execute" in finding.code_snippet or "execute" in finding.metadata.get("sink_method", "")

    # Verify descriptions mention construction types
    descriptions = " ".join(f.description for f in report.findings)
    assert "JoinedStr" in descriptions or "f-string" in descriptions
    assert "Concatenation" in descriptions or "+" in descriptions
    assert "format()" in descriptions


def test_safe_queries_excluded(scanner, tmp_path):
    """Verify safe parameterized queries emit 0 findings."""
    safe_code = '''
def safe_func_1(cursor, uid):
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (uid,))

def safe_func_2(cursor):
    cursor.execute("SELECT COUNT(*) FROM items")
'''
    test_file = tmp_path / "safe.py"
    test_file.write_text(safe_code, encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = ASTReconScanner(config=custom_config)

    report = custom_scanner.scan_path(test_file)
    assert report.scanned_files_count == 1
    assert len(report.findings) == 0


def test_syntax_error_resilience(scanner):
    """Verify syntax errors emit a warning and do not crash the engine."""
    broken_path = "tests/fixtures/broken_syntax.py"
    report = scanner.scan_path(broken_path)

    assert len(report.findings) == 0
    assert len(report.syntax_warnings) == 1
    assert "Syntax error" in report.syntax_warnings[0]["warning"]


def test_oversized_file_skipped(tmp_path):
    """Verify files exceeding max_scan_file_size_bytes are safely skipped."""
    large_code = "# filler\n" * 5000
    large_file = tmp_path / "large.py"
    large_file.write_text(large_code, encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path, max_scan_file_size_bytes=500)
    custom_scanner = ASTReconScanner(config=custom_config)

    report = custom_scanner.scan_path(large_file)
    assert report.scanned_files_count == 0
    assert len(report.syntax_warnings) == 1
    assert "exceeds limit" in report.syntax_warnings[0]["warning"]


def test_route_extraction_on_target_app(scanner):
    """Verify route handlers are mapped from target FastAPI app."""
    target_app_path = "target_app/app.py"
    report = scanner.scan_path(target_app_path)

    route_paths = [r.path for r in report.routes]
    assert "/api/health" in route_paths
    assert "/api/products" in route_paths
    assert "/api/orders" in route_paths
    assert "/api/user/{user_id}/profile" in route_paths

    orders_route = next(r for r in report.routes if r.path == "/api/orders")
    assert orders_route.method == "GET"
    assert "user_id" in orders_route.parameters

    # Also verify CWE-89 finding in target_app/app.py
    assert len(report.findings) >= 1
    sqli_finding = next((f for f in report.findings if f.cwe == "CWE-89"), None)
    assert sqli_finding is not None
    assert sqli_finding.severity == Severity.CRITICAL


def test_detects_expanded_vulnerability_classes(scanner, tmp_path):
    """Verify AST scanner detects hardcoded secrets, weak crypto, open redirect, cors, and debug mode."""
    vuln_code = '''
import os, hashlib, uvicorn
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

app = FastAPI(debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)

AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
secret_token = "production_super_secret_jwt_key_9999"

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

@app.get("/login/redirect")
def redirect_handler(next: str):
    return RedirectResponse(next)

@app.get("/cookie")
def cookie_handler(response: Response):
    response.set_cookie(key="auth", value="token123", httponly=False)
'''
    vuln_file = tmp_path / "extended_vulns.py"
    vuln_file.write_text(vuln_code, encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = ASTReconScanner(config=custom_config)
    report = custom_scanner.scan_path(vuln_file)

    cwes = {f.cwe for f in report.findings}
    assert "CWE-798" in cwes  # Hardcoded secret
    assert "CWE-327" in cwes  # Weak crypto (MD5)
    assert "CWE-601" in cwes  # Open redirect
    assert "CWE-942" in cwes  # CORS misconfiguration
    assert "CWE-489" in cwes  # Debug mode
    assert "CWE-614" in cwes  # Insecure cookie

    # Verify executed rules metadata
    assert "AST-SECRET-01" in report.scanner_rules_executed
    assert "AST-CRYPTO-01" in report.scanner_rules_executed
    assert "AST-REDIRECT-01" in report.scanner_rules_executed
    assert "AST-CORS-01" in report.scanner_rules_executed
    assert "AST-DEBUG-01" in report.scanner_rules_executed
    assert "AST-COOKIE-01" in report.scanner_rules_executed


def test_detects_all_ast_vulnerability_classes_comprehensive(scanner, tmp_path):
    """Verify that every single AST vulnerability class is identified and categorized properly."""
    comprehensive_vuln_code = '''
import os, sys, subprocess, pickle, requests, hashlib, sqlite3
from pathlib import Path
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

app = FastAPI(debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)

AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"

def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()

@app.get("/login")
def login(username: str):
    conn = sqlite3.connect(":memory:")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.cursor().execute(query).fetchall()

@app.get("/exec")
def execute_cmd(user_cmd: str):
    return os.system(f"echo {user_cmd}")

@app.get("/files/{filename:path}")
def get_file(filename: str):
    file_path = Path("/tmp") / filename
    return file_path.read_text()

users_db = {1: "Alice", 2: "Bob"}
@app.get("/users/{user_id}")
def get_user_profile(user_id: int):
    return users_db.get(user_id)

@app.post("/load")
def parse_payload(raw_data: bytes):
    return pickle.loads(raw_data)

@app.get("/fetch")
def proxy_request(target_url: str):
    return requests.get(target_url).text

@app.get("/goto")
def redirect_to(dest_url: str):
    return RedirectResponse(dest_url)

@app.get("/session")
def set_auth(response: Response):
    response.set_cookie(key="session_token", value="secret_123", httponly=False)
'''
    vuln_file = tmp_path / "all_vulns_demo.py"
    vuln_file.write_text(comprehensive_vuln_code, encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = ASTReconScanner(config=custom_config)
    report = custom_scanner.scan_path(vuln_file)

    detected_cwes = {f.cwe for f in report.findings}
    expected_cwes = {
        "CWE-89",   # SQL Injection
        "CWE-78",   # OS Command Injection
        "CWE-22",   # Path Traversal
        "CWE-639",  # IDOR
        "CWE-502",  # Unsafe Deserialization
        "CWE-918",  # SSRF
        "CWE-798",  # Hardcoded Secret
        "CWE-327",  # Weak Cryptography
        "CWE-601",  # Open Redirect
        "CWE-942",  # CORS Misconfiguration
        "CWE-489",  # Debug Mode
        "CWE-614",  # Insecure Cookie
    }

    for expected in expected_cwes:
        assert expected in detected_cwes, f"Expected {expected} to be detected, found: {detected_cwes}"

