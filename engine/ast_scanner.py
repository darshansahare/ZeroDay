"""
ZeroDay Arena: AST Security Scanner
High-precision Abstract Syntax Tree static analysis engine for Python FastAPI microservices.
Detects CWE-89 (SQL Injection), CWE-639 (IDOR), and credential exposure vectors.
"""

import ast
import re
from typing import List, Dict, Any, Optional

class ASTSecurityScanner:
    """
    Abstract Syntax Tree static analysis scanner.
    Analyzes Python AST nodes to identify sinks, vulnerable string interpolations,
    insecure direct object references, and missing authentication boundaries.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.routes: List[Dict[str, Any]] = []
        self.source_lines: List[str] = []

    def scan_file(self, filepath: str) -> Dict[str, Any]:
        """Scan a Python file or directory from disk using ASTReconScanner."""
        try:
            from app.analysis.ast_scanner import ASTReconScanner
            recon = ASTReconScanner()
            rep = recon.scan_path(filepath)
            findings_dicts = []
            for f in rep.findings:
                findings_dicts.append({
                    "id": f.id,
                    "cwe": f.cwe,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "line_number": f.line_number,
                    "sink_line": f.sink_line,
                    "vulnerability_type": f.vulnerability_class.value,
                    "description": f.description,
                    "snippet": f.code_snippet,
                    "recommendation": f.remediation_guidance,
                    "file_path": f.file_path,
                })
            routes_dicts = []
            for r in rep.routes:
                routes_dicts.append({
                    "name": r.name,
                    "method": r.method,
                    "path": r.path,
                    "line_start": r.line_start,
                    "line_end": r.line_end,
                })
            return {
                "success": True,
                "filename": filepath,
                "loc": rep.total_loc,
                "routes_count": len(routes_dicts),
                "routes": routes_dicts,
                "findings_count": len(findings_dicts),
                "findings": findings_dicts,
                "summary": rep.summary,
            }
        except Exception:
            resolved_p = Path(filepath).resolve()
            code = resolved_p.read_text(encoding="utf-8", errors="replace")
            return self.scan_source(code, filename=str(resolved_p))

    def scan_source(self, code: str, filename: str = "app.py") -> Dict[str, Any]:
        """Parse source code string into AST and run vulnerability detection passes."""
        self.findings = []
        self.routes = []
        self.source_lines = code.splitlines()

        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            return {
                "success": False,
                "error": f"AST Syntax Error at line {e.lineno}: {e.msg}",
                "findings": [],
                "routes": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "total": 0}
            }

        # Pass 1: Extract API Routes & Function Definitions
        self._extract_routes(tree)

        # Pass 2: Detect CWE-89 SQL Injection Sinks
        self._detect_sql_injection(tree)

        # Pass 3: Detect CWE-639 IDOR Vulnerabilities
        self._detect_idor(tree)

        # Pass 4: Detect CWE-798 Hardcoded Secrets / Tokens
        self._detect_hardcoded_secrets(tree)

        # Generate summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            sev = finding.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "success": True,
            "filename": filename,
            "loc": len(self.source_lines),
            "routes_count": len(self.routes),
            "routes": self.routes,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "summary": {
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "total": len(self.findings)
            }
        }

    def _extract_routes(self, tree: ast.AST):
        """Find FastAPI route decorators like @app.get('/api/orders')."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    # Check for app.get, app.post, etc.
                    method = None
                    path = ""
                    if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                        if decorator.func.attr in ("get", "post", "put", "delete", "patch"):
                            method = decorator.func.attr.upper()
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                path = str(decorator.args[0].value)

                    if method and path:
                        self.routes.append({
                            "name": node.name,
                            "method": method,
                            "path": path,
                            "line_start": node.lineno,
                            "line_end": getattr(node, "end_lineno", node.lineno),
                            "args": [arg.arg for arg in node.args.args]
                        })

    def _get_snippet(self, start_line: int, end_line: Optional[int] = None, padding: int = 2) -> str:
        """Extract formatted source code snippet around line numbers."""
        if not self.source_lines:
            return ""
        s = max(1, start_line - padding)
        e = min(len(self.source_lines), (end_line or start_line) + padding)
        snippet_lines = []
        for i in range(s, e + 1):
            prefix = " > " if i == start_line else "   "
            snippet_lines.append(f"{i:4d}{prefix}{self.source_lines[i - 1]}")
        return "\n".join(snippet_lines)

    def _detect_sql_injection(self, tree: ast.AST):
        """
        Identify SQL execution calls where the query is constructed using
        f-strings (JoinedStr), string concatenation (BinOp +), or % format.
        """
        # Track assignments of query variables
        query_assignments: Dict[str, Dict[str, Any]] = {}

        for node in ast.walk(tree):
            # Check for query assignments: query = f"SELECT ... {param}"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        # Check if value is a JoinedStr (f-string)
                        if isinstance(node.value, ast.JoinedStr):
                            has_variables = any(isinstance(v, ast.FormattedValue) for v in node.value.values)
                            if has_variables:
                                raw_text = ""
                                for v in node.value.values:
                                    if isinstance(v, ast.Constant):
                                        raw_text += str(v.value)
                                    elif isinstance(v, ast.FormattedValue):
                                        raw_text += "{...}"
                                if any(kw in raw_text.upper() for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP")):
                                    query_assignments[var_name] = {
                                        "lineno": node.lineno,
                                        "end_lineno": getattr(node, "end_lineno", node.lineno),
                                        "type": "JoinedStr (f-string)",
                                        "node": node
                                    }
                        # Check if value is string concatenation (+)
                        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                            query_assignments[var_name] = {
                                "lineno": node.lineno,
                                "end_lineno": getattr(node, "end_lineno", node.lineno),
                                "type": "String Concatenation (+)",
                                "node": node
                            }

        # Check for cursor.execute calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("execute", "executemany"):
                    if node.args:
                        arg0 = node.args[0]
                        vuln_detail = None

                        # Case A: cursor.execute(f"SELECT ... {var}") directly
                        if isinstance(arg0, ast.JoinedStr):
                            has_vars = any(isinstance(v, ast.FormattedValue) for v in arg0.values)
                            if has_vars:
                                vuln_detail = {
                                    "type": "Direct f-string in cursor.execute",
                                    "lineno": node.lineno,
                                    "end_lineno": getattr(node, "end_lineno", node.lineno)
                                }

                        # Case B: cursor.execute(query) where query was f-string
                        elif isinstance(arg0, ast.Name) and arg0.id in query_assignments:
                            q_meta = query_assignments[arg0.id]
                            vuln_detail = {
                                "type": f"Variable '{arg0.id}' built via {q_meta['type']}",
                                "lineno": q_meta["lineno"],
                                "end_lineno": node.lineno
                            }

                        if vuln_detail:
                            snippet = self._get_snippet(vuln_detail["lineno"], node.lineno)
                            self.findings.append({
                                "id": f"AST-SQLI-{len(self.findings) + 1:02d}",
                                "cwe": "CWE-89",
                                "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                "severity": "CRITICAL",
                                "confidence": "CERTAIN",
                                "line_number": vuln_detail["lineno"],
                                "sink_line": node.lineno,
                                "vulnerability_type": "SQL Injection (Unparameterized Query)",
                                "description": (
                                    "Dynamic SQL query construction detected. User input is interpolated directly "
                                    "into a raw SQL command string using Python string formatting rather than parameterized placeholders (?). "
                                    "This enables arbitrary SQL execution and sensitive database exfiltration."
                                ),
                                "snippet": snippet,
                                "recommendation": (
                                    "Refactor the query to use parameterized bindings (e.g. `cursor.execute('SELECT ... WHERE user_id = ?', (user_id,))`) "
                                    "and enforce strict parameter validation with Pydantic."
                                )
                            })

    def _detect_idor(self, tree: ast.AST):
        """
        Identify endpoints accepting an entity ID in path parameters but directly querying
        database records without authorization/session dependency validation in function signature or decorators.
        """
        for route in self.routes:
            # Check if route has an object id like {user_id} or {id}
            if "{" in route["path"] and "}" in route["path"]:
                # Check function node corresponding to route
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == route["name"]:
                        # Check if function arguments contain security dependencies
                        arg_names = [a.arg for a in node.args.args]
                        # Check if decorators have security dependencies
                        dec_str = " ".join(ast.dump(d) for d in node.decorator_list)
                        has_auth_guard = any(
                            guard in arg.lower() for arg in arg_names for guard in ("auth", "current_user", "session", "token_payload")
                        ) or "security" in dec_str.lower() or "authorize" in dec_str.lower()

                        if not has_auth_guard:
                            endpoint_code = self._get_snippet(route["line_start"], route["line_end"], padding=1)
                            self.findings.append({
                                "id": f"AST-IDOR-{len(self.findings) + 1:02d}",
                                "cwe": "CWE-639",
                                "title": "Authorization Bypass Through User-Controlled Key (IDOR)",
                                "severity": "HIGH",
                                "confidence": "FIRM",
                                "line_number": route["line_start"],
                                "vulnerability_type": "Insecure Direct Object Reference (IDOR)",
                                "description": (
                                    f"Route '{route['path']}' accepts direct resource identifier in path parameter "
                                    "without verifying authenticated session claims or object ownership permissions."
                                ),
                                "snippet": endpoint_code,
                                "recommendation": "Enforce RBAC/ABAC authorization dependencies validating that caller identity owns or is permitted to access the requested ID."
                            })

    def _detect_hardcoded_secrets(self, tree: ast.AST):
        """Identify potential hardcoded keys, tokens, or plaintext secrets."""
        secret_patterns = re.compile(r"(api[_-]?key|secret|private[_-]?key|jwt[_-]?token|auth[_-]?token)", re.IGNORECASE)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and secret_patterns.search(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            if len(val) > 8 and not val.startswith("os.environ"):
                                self.findings.append({
                                    "id": f"AST-SEC-{len(self.findings) + 1:02d}",
                                    "cwe": "CWE-798",
                                    "title": "Use of Hard-coded Credentials",
                                    "severity": "MEDIUM",
                                    "confidence": "HIGH",
                                    "line_number": node.lineno,
                                    "vulnerability_type": "Hardcoded Secret",
                                    "description": f"Potential static credential assignment assigned to variable '{target.id}'.",
                                    "snippet": self._get_snippet(node.lineno),
                                    "recommendation": "Migrate secrets to environment variables, Azure Key Vault, or AWS Secrets Manager."
                                })
