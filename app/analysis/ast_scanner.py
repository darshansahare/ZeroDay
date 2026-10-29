"""
ZeroDay Arena AST Reconnaissance Scanner.
High-precision, deterministic Abstract Syntax Tree static analysis for Python applications.
Analyzes syntax trees without executing untrusted target code.
"""

import ast
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.config import AppConfig, get_config
from app.analysis.findings import (
    AnalysisReport,
    EvidenceStatus,
    Finding,
    RouteInfo,
    Severity,
    VulnerabilityClass,
)
from app.cache.token_cache import token_cache


class ASTReconScanner:
    """
    Deterministic AST analyzer for Python codebases.
    Extracts route surfaces, query execution sinks, and suspicious dynamic query constructions.
    """

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or get_config()

    def scan_path(self, target_path: Path | str) -> AnalysisReport:
        """
        Scan a file or directory within the designated workspace root.
        Enforces path containment and resource constraints.
        Discovers all files and analyzes eligible source files across the repository.
        """
        t0 = time.perf_counter()
        validated_target = self.config.validate_path_within_workspace(target_path)

        def get_rel(p: Path) -> str:
            try:
                return str(p.relative_to(self.config.workspace_root))
            except ValueError:
                try:
                    base = validated_target if validated_target.is_dir() else validated_target.parent
                    return str(p.relative_to(base))
                except ValueError:
                    return p.name

        all_findings: List[Finding] = []
        all_routes: List[RouteInfo] = []
        syntax_warnings: List[Dict[str, Any]] = []
        files_discovered: List[str] = []
        files_analyzed: List[str] = []
        files_skipped: List[Dict[str, str]] = []
        scanned_files_count = 0
        total_loc = 0
        coverage_status = "FULL"

        files_to_scan: List[Path] = []
        binary_extensions = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".db", ".sqlite", ".sqlite3", ".pyc", ".pyd", ".dll", ".so", ".exe", ".bin", ".tar", ".gz", ".zip"}
        unsupported_source_exts = {".go", ".java", ".cpp", ".c", ".rs", ".php", ".rb", ".cs"}

        if validated_target.is_file():
            rel_f = get_rel(validated_target)
            files_discovered.append(rel_f)
            if validated_target.suffix.lower() == ".py":
                files_to_scan.append(validated_target)
            else:
                files_skipped.append({"file": rel_f, "reason": "Non-Python source file"})
        else:
            for root, dirs, files in os.walk(validated_target):
                # Filter out excluded directories in-place
                dirs[:] = [d for d in dirs if d not in self.config.excluded_directories and not d.startswith(".git")]
                for file in sorted(files):
                    file_p = Path(root) / file
                    rel_f = get_rel(file_p)
                    files_discovered.append(rel_f)

                    ext = file_p.suffix.lower()
                    if ext in binary_extensions:
                        files_skipped.append({"file": rel_f, "reason": "Binary or media asset"})
                    elif ext in unsupported_source_exts:
                        files_skipped.append({"file": rel_f, "reason": f"Unsupported language ({ext})"})
                        coverage_status = "PARTIAL"
                    elif ext == ".py":
                        files_to_scan.append(file_p)
                    else:
                        files_skipped.append({"file": rel_f, "reason": "Non-Python asset/config file"})

        # Enforce maximum scan file count to prevent resource exhaustion
        max_files = getattr(self.config, "max_scan_files", getattr(self.config, "max_scan_files_count", 100))
        if len(files_to_scan) > max_files:
            coverage_status = "PARTIAL"
            for extra in files_to_scan[max_files:]:
                rel_extra = get_rel(extra)
                files_skipped.append({"file": rel_extra, "reason": f"File count limit reached ({max_files})"})
            files_to_scan = files_to_scan[:max_files]

        for file_path in files_to_scan:
            rel_file_str = get_rel(file_path)
            try:
                size = file_path.stat().st_size
                if size > self.config.max_scan_file_size_bytes:
                    coverage_status = "PARTIAL"
                    files_skipped.append({
                        "file": rel_file_str,
                        "reason": f"File size ({size} bytes) exceeds limit ({self.config.max_scan_file_size_bytes} bytes)",
                    })
                    syntax_warnings.append({
                        "file": rel_file_str,
                        "warning": f"File skipped: size ({size} bytes) exceeds limit ({self.config.max_scan_file_size_bytes} bytes)",
                    })
                    continue

                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                loc = len(content.splitlines())
                total_loc += loc
                scanned_files_count += 1
                files_analyzed.append(rel_file_str)

                content_hash = token_cache.hash_text(content)
                cached_subreport = token_cache.get_ast(str(file_path), content_hash)
                if cached_subreport is not None:
                    all_routes.extend(cached_subreport.routes)
                    for cf in cached_subreport.findings:
                        bound_f = cf.model_copy(update={"file_path": rel_file_str})
                        all_findings.append(bound_f)
                    if cached_subreport.syntax_warnings:
                        syntax_warnings.extend(cached_subreport.syntax_warnings)
                else:
                    file_routes, file_findings, warning = self._analyze_source(content, file_path, rel_path=rel_file_str)
                    all_routes.extend(file_routes)
                    all_findings.extend(file_findings)
                    if warning:
                        syntax_warnings.append(warning)

                    # Cache subreport for this document
                    subreport = AnalysisReport(
                        target_path=rel_file_str,
                        scanned_files_count=1,
                        total_loc=loc,
                        routes=file_routes,
                        findings=file_findings,
                        syntax_warnings=[warning] if warning else [],
                        scan_duration_ms=0.0,
                    )
                    token_cache.set_ast(str(file_path), content_hash, subreport)

            except Exception as e:
                syntax_warnings.append({
                    "file": rel_file_str,
                    "warning": f"I/O or parsing error: {str(e)}",
                })

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        # Summary statistics
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total_findings": len(all_findings)}
        for f in all_findings:
            sev_key = f.severity.value.lower()
            if sev_key in summary:
                summary[sev_key] += 1

        rel_target = get_rel(validated_target) if validated_target != self.config.workspace_root else "."

        return AnalysisReport(
            target_path=rel_target,
            scanned_files_count=scanned_files_count,
            total_loc=total_loc,
            routes=all_routes,
            findings=all_findings,
            dependency_findings=[],
            syntax_warnings=syntax_warnings,
            files_discovered=files_discovered,
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            coverage_status=coverage_status,
            scanner_rules_executed=[
                "AST-SQLI-01",
                "AST-CMDI-01",
                "AST-PATHTRAV-01",
                "AST-DESER-01",
                "AST-SSRF-01",
                "AST-IDOR-01",
                "AST-SECRET-01",
                "AST-CRYPTO-01",
                "AST-REDIRECT-01",
                "AST-CORS-01",
                "AST-DEBUG-01",
                "AST-COOKIE-01",
                "AST-DEP-01",
                "AST-INPUT-01",
            ],
            summary=summary,
            scan_duration_ms=duration_ms,
        )

    def _analyze_source(
        self, source_code: str, file_path: Path, rel_path: Optional[str] = None
    ) -> Tuple[List[RouteInfo], List[Finding], Optional[Dict[str, Any]]]:
        """Parse source code into AST and inspect for routes and security sinks."""
        if rel_path is None:
            try:
                rel_path = str(file_path.relative_to(self.config.workspace_root))
            except ValueError:
                rel_path = file_path.name
        source_lines = source_code.splitlines()

        try:
            tree = ast.parse(source_code, filename=str(file_path))
        except SyntaxError as e:
            return (
                [],
                [],
                {
                    "file": rel_path,
                    "warning": f"Syntax error at line {e.lineno}: {e.msg}",
                    "line": e.lineno,
                },
            )

        routes = self._extract_routes(tree)
        findings: List[Finding] = []
        findings.extend(self._inspect_sql_sinks(tree, source_lines, rel_path))
        findings.extend(self._inspect_command_sinks(tree, source_lines, rel_path))
        findings.extend(self._inspect_path_traversal_sinks(tree, source_lines, rel_path))
        findings.extend(self._inspect_deserialization_sinks(tree, source_lines, rel_path))
        findings.extend(self._inspect_ssrf_sinks(tree, source_lines, rel_path))
        findings.extend(self._inspect_idor_sinks(tree, source_lines, rel_path))
        findings.extend(self._inspect_hardcoded_secrets(tree, source_lines, rel_path))
        findings.extend(self._inspect_weak_crypto(tree, source_lines, rel_path))
        findings.extend(self._inspect_open_redirect(tree, source_lines, rel_path))
        findings.extend(self._inspect_cors_misconfiguration(tree, source_lines, rel_path))
        findings.extend(self._inspect_debug_mode(tree, source_lines, rel_path))
        findings.extend(self._inspect_insecure_cookie(tree, source_lines, rel_path))
        findings.extend(self._inspect_dependency_vulnerabilities(tree, source_lines, rel_path))
        findings.extend(self._inspect_unvalidated_input(tree, source_lines, rel_path))

        return routes, findings, None

    def _extract_routes(self, tree: ast.AST) -> List[RouteInfo]:
        """Identify route handlers declared with decorators like @app.get('/path')."""
        routes: List[RouteInfo] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    method = None
                    path = ""
                    # Match pattern: @app.get(...) or @router.post(...)
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        attr_name = dec.func.attr.lower()
                        if attr_name in ("get", "post", "put", "delete", "patch", "options", "head"):
                            method = attr_name.upper()
                            if dec.args and isinstance(dec.args[0], ast.Constant):
                                path = str(dec.args[0].value)

                    if method and path:
                        params = [arg.arg for arg in node.args.args]
                        routes.append(
                            RouteInfo(
                                name=node.name,
                                method=method,
                                path=path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                parameters=params,
                            )
                        )
        return routes

    def _inspect_sql_sinks(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """
        Locate SQL execution calls and flag unparameterized dynamic query constructions.
        Scopes variable tracking to function bodies to avoid cross-function variable collision.
        """
        findings: List[Finding] = []

        # Walk through functions or module body
        for parent_node in ast.walk(tree):
            if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                # Map dynamic SQL variables defined specifically in this scope
                local_dynamic_sql_vars: Dict[str, Dict[str, Any]] = {}
                for child in getattr(parent_node, "body", []):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                sink_info = self._check_dynamic_sql_expr(child.value)
                                if sink_info:
                                    local_dynamic_sql_vars[target.id] = {
                                        "type": sink_info["type"],
                                        "lineno": child.lineno,
                                        "end_lineno": getattr(child, "end_lineno", child.lineno),
                                    }

                # Find execute calls in this scope
                for node in ast.walk(parent_node):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr in ("execute", "executemany"):
                            if not node.args:
                                continue

                            query_arg = node.args[0]
                            has_bound_params = len(node.args) >= 2 or any(kw.arg in ("parameters", "params") for kw in node.keywords)
                            vuln_evidence: Optional[Dict[str, Any]] = None

                            # Case A: Direct dynamic expression in execute (e.g. cursor.execute(f"..."))
                            direct_info = self._check_dynamic_sql_expr(query_arg)
                            if direct_info:
                                vuln_evidence = {
                                    "type": direct_info["type"],
                                    "query_line": node.lineno,
                                    "sink_line": node.lineno,
                                    "expression": direct_info.get("preview", ""),
                                }

                            # Case B: Query variable built via dynamic formatting in this scope
                            elif isinstance(query_arg, ast.Name) and query_arg.id in local_dynamic_sql_vars:
                                var_meta = local_dynamic_sql_vars[query_arg.id]
                                # If bound params were supplied, check if the query was an unparameterized f-string
                                vuln_evidence = {
                                    "type": f"Variable '{query_arg.id}' built via {var_meta['type']}",
                                    "query_line": var_meta["lineno"],
                                    "sink_line": node.lineno,
                                    "expression": query_arg.id,
                                }

                            if vuln_evidence:
                                snippet = self._extract_snippet(
                                    source_lines, vuln_evidence["query_line"], vuln_evidence["sink_line"]
                                )
                                finding_id = f"FIND-CWE-89-{len(findings) + 1:03d}"
                                findings.append(
                                    Finding(
                                        id=finding_id,
                                        vulnerability_class=VulnerabilityClass.SQL_INJECTION,
                                        cwe="CWE-89",
                                        title="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                        description=(
                                            f"Dynamic SQL query construction detected at line {vuln_evidence['query_line']}. "
                                            f"Query uses {vuln_evidence['type']} and flows into `{node.func.attr}()` "
                                            f"at line {vuln_evidence['sink_line']} without parameterized placeholders."
                                        ),
                                        severity=Severity.CRITICAL,
                                        evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                        file_path=rel_path,
                                        line_number=vuln_evidence["query_line"],
                                        sink_line=vuln_evidence["sink_line"],
                                        source_expression=vuln_evidence.get("expression"),
                                        code_snippet=snippet,
                                        remediation_guidance=(
                                            "Refactor query to use parameterized query placeholders (e.g. `?` for SQLite, `%s` for PostgreSQL) "
                                            "and supply user input as a bound parameter tuple: `cursor.execute(sql, (param,))`."
                                        ),
                                        metadata={
                                            "construction_type": vuln_evidence["type"],
                                            "sink_method": node.func.attr,
                                        },
                                    )
                                )

        # Deduplicate findings by (line_number, sink_line)
        unique_findings: List[Finding] = []
        seen: Set[Tuple[int, Optional[int]]] = set()
        for f in findings:
            key = (f.line_number, f.sink_line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _check_dynamic_sql_expr(self, node: ast.AST) -> Optional[Dict[str, Any]]:
        """Determine if an AST expression represents an unescaped dynamic SQL query."""
        sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE")

        # JoinedStr (f-string)
        if isinstance(node, ast.JoinedStr):
            has_vars = any(isinstance(v, ast.FormattedValue) for v in node.values)
            if has_vars:
                text_parts = [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
                full_text = " ".join(text_parts).upper()
                if any(kw in full_text for kw in sql_keywords):
                    return {"type": "JoinedStr (f-string interpolation)", "preview": full_text[:60]}

        # BinOp + (String concatenation)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            preview = self._get_binop_string_preview(node)
            if any(kw in preview.upper() for kw in sql_keywords):
                return {"type": "String Concatenation (+)", "preview": preview[:60]}

        # Call to .format(...)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                val_upper = node.func.value.value.upper()
                if any(kw in val_upper for kw in sql_keywords):
                    return {"type": "String .format() interpolation", "preview": val_upper[:60]}

        # BinOp % (Percent format)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                val_upper = node.left.value.upper()
                if any(kw in val_upper for kw in sql_keywords):
                    return {"type": "Percent format (%) string interpolation", "preview": val_upper[:60]}

        return None

    def _get_dynamic_expr_info(self, node: ast.AST) -> Optional[Dict[str, Any]]:
        """Determine if an AST expression represents dynamic string construction."""
        if isinstance(node, ast.JoinedStr):
            has_vars = any(isinstance(v, ast.FormattedValue) for v in node.values)
            if has_vars:
                text_parts = [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
                return {"type": "JoinedStr (f-string interpolation)", "preview": " ".join(text_parts)[:60]}
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            preview = self._get_binop_string_preview(node)
            return {"type": "String Concatenation (+)", "preview": preview[:60]}
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return {"type": "String .format() interpolation", "preview": ".format(...)"}
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return {"type": "Percent format (%) string interpolation", "preview": "% interpolation"}
        return None

    def _inspect_command_sinks(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unquoted or shell-enabled OS command executions (CWE-78)."""
        findings: List[Finding] = []
        cmd_funcs = {"system", "popen"}
        subproc_funcs = {"run", "Popen", "call", "check_output", "check_call"}

        for parent_node in ast.walk(tree):
            if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                local_dynamic_vars: Dict[str, Dict[str, Any]] = {}
                func_params = {arg.arg for arg in getattr(parent_node, "args", ast.arguments()).args} if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()
                for child in getattr(parent_node, "body", []):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                expr_info = self._get_dynamic_expr_info(child.value)
                                if expr_info:
                                    local_dynamic_vars[target.id] = {
                                        "type": expr_info["type"],
                                        "lineno": child.lineno,
                                        "preview": expr_info.get("preview", ""),
                                    }

                for node in ast.walk(parent_node):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        attr = node.func.attr
                        val_name = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                        is_os_cmd = val_name == "os" and attr in cmd_funcs
                        is_subproc = val_name == "subprocess" and attr in subproc_funcs

                        if is_os_cmd or is_subproc:
                            if not node.args:
                                continue
                            arg0 = node.args[0]
                            shell_kw = any(
                                kw.arg == "shell" and (
                                    (isinstance(kw.value, ast.Constant) and bool(kw.value.value))
                                    or not isinstance(kw.value, ast.Constant)
                                )
                                for kw in node.keywords
                            )
                            requires_shell = is_os_cmd or shell_kw

                            dyn_info = self._get_dynamic_expr_info(arg0)
                            vuln_meta = None
                            if dyn_info and requires_shell:
                                vuln_meta = {
                                    "type": dyn_info["type"],
                                    "query_line": node.lineno,
                                    "sink_line": node.lineno,
                                    "expression": dyn_info.get("preview", ""),
                                }
                            elif isinstance(arg0, ast.Name) and arg0.id in local_dynamic_vars and requires_shell:
                                v_info = local_dynamic_vars[arg0.id]
                                vuln_meta = {
                                    "type": f"Variable '{arg0.id}' built via {v_info['type']}",
                                    "query_line": v_info["lineno"],
                                    "sink_line": node.lineno,
                                    "expression": arg0.id,
                                }
                            elif isinstance(arg0, ast.Name) and arg0.id in func_params and requires_shell:
                                vuln_meta = {
                                    "type": f"Unsanitized parameter '{arg0.id}'",
                                    "query_line": node.lineno,
                                    "sink_line": node.lineno,
                                    "expression": arg0.id,
                                }

                            if vuln_meta:
                                snippet = self._extract_snippet(
                                    source_lines, vuln_meta["query_line"], vuln_meta["sink_line"]
                                )
                                finding_id = f"FIND-CWE-78-{len(findings) + 1:03d}"
                                findings.append(
                                    Finding(
                                        id=finding_id,
                                        vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
                                        cwe="CWE-78",
                                        title="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                                        description=(
                                            f"Dynamic OS command execution detected at line {vuln_meta['query_line']}. "
                                            f"Command uses {vuln_meta['type']} and flows into `{val_name}.{attr}()` "
                                            f"at line {vuln_meta['sink_line']} with shell execution enabled."
                                        ),
                                        severity=Severity.CRITICAL,
                                        evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                        file_path=rel_path,
                                        line_number=vuln_meta["query_line"],
                                        sink_line=vuln_meta["sink_line"],
                                        source_expression=vuln_meta.get("expression"),
                                        code_snippet=snippet,
                                        remediation_guidance=(
                                            "Pass command and arguments as a sequence (list of strings) and avoid shell=True: "
                                            "`subprocess.run(['command', arg1, arg2], shell=False)`."
                                        ),
                                        metadata={"sink_method": f"{val_name}.{attr}", "construction_type": vuln_meta["type"]},
                                    )
                                )
        unique_findings: List[Finding] = []
        seen: Set[Tuple[int, Optional[int]]] = set()
        for f in findings:
            key = (f.line_number, f.sink_line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        return unique_findings

    def _has_containment_check(self, scope: ast.AST) -> bool:
        """Check if containment verification (e.g. is_relative_to, relative_to, basename) is present."""
        for n in ast.walk(scope):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and n.func.attr in ("is_relative_to", "relative_to", "commonpath", "basename"):
                    return True
                elif isinstance(n.func, ast.Name) and n.func.id in ("basename", "secure_filename"):
                    return True
        return False

    def _inspect_path_traversal_sinks(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unsanitized file path operations (CWE-22), including pathlib Path.read_text()."""
        findings: List[Finding] = []
        path_sinks = {
            "open", "remove", "unlink", "rmtree", "send_file", "FileResponse",
            "read_text", "read_bytes", "write_text", "write_bytes"
        }

        for parent_node in ast.walk(tree):
            if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                # If containment verification exists in this scope, skip flagging
                if self._has_containment_check(parent_node):
                    continue

                local_dynamic_vars: Dict[str, Dict[str, Any]] = {}
                func_params = {arg.arg for arg in getattr(parent_node, "args", ast.arguments()).args} if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()

                for child in getattr(parent_node, "body", []):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                expr_info = self._get_dynamic_expr_info(child.value)
                                # Check for pathlib Path division (e.g. BASE_DIR / filename)
                                if not expr_info and isinstance(child.value, ast.BinOp) and isinstance(child.value.op, ast.Div):
                                    right_names = {n.id for n in ast.walk(child.value.right) if isinstance(n, ast.Name)}
                                    left_names = {n.id for n in ast.walk(child.value.left) if isinstance(n, ast.Name)}
                                    tainted = (right_names | left_names) & (func_params | set(local_dynamic_vars.keys()))
                                    if tainted:
                                        tainted_param = next(iter(tainted))
                                        expr_info = {
                                            "type": f"Path division (/) with parameter '{tainted_param}'",
                                            "preview": f"Path / {tainted_param}",
                                        }

                                if expr_info:
                                    local_dynamic_vars[target.id] = {
                                        "type": expr_info["type"],
                                        "lineno": child.lineno,
                                        "preview": expr_info.get("preview", ""),
                                    }

                for node in ast.walk(parent_node):
                    if isinstance(node, ast.Call):
                        sink_name = ""
                        vuln_meta = None

                        # Pattern A: obj.read_text(), obj.read_bytes(), obj.open()
                        if isinstance(node.func, ast.Attribute) and node.func.attr in path_sinks:
                            attr_name = node.func.attr
                            if isinstance(node.func.value, ast.Name):
                                val_name = node.func.value.id
                                if val_name in local_dynamic_vars:
                                    v_info = local_dynamic_vars[val_name]
                                    sink_name = f"{val_name}.{attr_name}"
                                    vuln_meta = {
                                        "type": f"Path variable '{val_name}' built via {v_info['type']}",
                                        "query_line": v_info["lineno"],
                                        "sink_line": node.lineno,
                                        "expression": val_name,
                                    }
                                elif val_name in func_params:
                                    sink_name = f"{val_name}.{attr_name}"
                                    vuln_meta = {
                                        "type": f"Unsanitized parameter '{val_name}'",
                                        "query_line": node.lineno,
                                        "sink_line": node.lineno,
                                        "expression": val_name,
                                    }

                        # Pattern B: open(arg), send_file(arg), FileResponse(arg)
                        if not vuln_meta:
                            if isinstance(node.func, ast.Name) and node.func.id in path_sinks:
                                sink_name = node.func.id
                            elif isinstance(node.func, ast.Attribute) and node.func.attr in path_sinks:
                                val_id = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                                sink_name = f"{val_id}.{node.func.attr}" if val_id else node.func.attr

                            if sink_name and node.args:
                                path_arg = node.args[0]
                                dyn_info = self._get_dynamic_expr_info(path_arg)
                                if dyn_info:
                                    vuln_meta = {
                                        "type": dyn_info["type"],
                                        "query_line": node.lineno,
                                        "sink_line": node.lineno,
                                        "expression": dyn_info.get("preview", ""),
                                    }
                                elif isinstance(path_arg, ast.Name) and path_arg.id in local_dynamic_vars:
                                    v_info = local_dynamic_vars[path_arg.id]
                                    vuln_meta = {
                                        "type": f"Variable '{path_arg.id}' built via {v_info['type']}",
                                        "query_line": v_info["lineno"],
                                        "sink_line": node.lineno,
                                        "expression": path_arg.id,
                                    }
                                elif isinstance(path_arg, ast.Name) and path_arg.id in func_params:
                                    vuln_meta = {
                                        "type": f"Unsanitized parameter '{path_arg.id}'",
                                        "query_line": node.lineno,
                                        "sink_line": node.lineno,
                                        "expression": path_arg.id,
                                    }

                        if vuln_meta:
                            snippet = self._extract_snippet(
                                source_lines, vuln_meta["query_line"], vuln_meta["sink_line"]
                            )
                            finding_id = f"FIND-CWE-22-{len(findings) + 1:03d}"
                            findings.append(
                                Finding(
                                    id=finding_id,
                                    vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
                                    cwe="CWE-22",
                                    title="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                                    description=(
                                        f"Unsanitized file path construction detected at line {vuln_meta['query_line']}. "
                                        f"Path uses {vuln_meta['type']} and flows into `{sink_name}()` at line {vuln_meta['sink_line']} "
                                        "without path containment verification."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence="HIGH",
                                    evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                    file_path=rel_path,
                                    line_number=vuln_meta["query_line"],
                                    sink_line=vuln_meta["sink_line"],
                                    source_expression=vuln_meta.get("expression"),
                                    code_snippet=snippet,
                                    remediation_guidance=(
                                        "Sanitize file paths with `os.path.basename()` and verify canonical path containment: "
                                        "`(base_dir / filename).resolve().is_relative_to(base_dir)`."
                                    ),
                                    metadata={"sink_method": sink_name, "construction_type": vuln_meta["type"]},
                                )
                            )
        unique_findings: List[Finding] = []
        seen: Set[Tuple[int, Optional[int]]] = set()
        for f in findings:
            key = (f.line_number, f.sink_line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        return unique_findings

    def _inspect_idor_sinks(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect insecure direct object references / broken object-level authorization (CWE-639)."""
        findings: List[Finding] = []
        idor_params = {"user_id", "id", "account_id", "profile_id", "order_id", "doc_id", "invoice_id"}
        non_idor_params = {"run_id", "job_id", "task_id", "event_id", "execution_id", "session_id", "message_id"}

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if decorated as a route handler
                is_route = False
                route_path = ""
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        if dec.func.attr.lower() in ("get", "post", "put", "delete", "patch"):
                            is_route = True
                            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                                route_path = dec.args[0].value

                if not is_route:
                    continue

                func_param_names = [arg.arg for arg in node.args.args]
                matching_id_params = [
                    p for p in func_param_names
                    if (p in idor_params or p.endswith("_id")) and p not in non_idor_params
                ]
                if not matching_id_params:
                    continue

                has_ownership_check = False
                resource_lookup_node = None
                target_param = matching_id_params[0]

                for child in ast.walk(node):
                    if isinstance(child, ast.Compare):
                        comp_tokens = set()
                        for sub in ast.walk(child):
                            if isinstance(sub, ast.Name):
                                comp_tokens.add(sub.id.lower())
                            elif isinstance(sub, ast.Attribute):
                                comp_tokens.add(sub.attr.lower())
                            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                                comp_tokens.add(sub.value.lower())
                        if any(k in tok for tok in comp_tokens for k in ("owner", "user_id", "owner_id", "current_user", "tenant_id", "account_id")):
                            if len(comp_tokens) >= 2:
                                has_ownership_check = True

                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Attribute) and child.func.attr in ("get", "filter", "filter_by", "find_one", "find_by"):
                            call_names = {sub.id for sub in ast.walk(child) if isinstance(sub, ast.Name)}
                            if target_param in call_names:
                                resource_lookup_node = child
                    elif isinstance(child, ast.Subscript):
                        slice_names = {sub.id for sub in ast.walk(child.slice) if isinstance(sub, ast.Name)}
                        if target_param in slice_names:
                            resource_lookup_node = child

                if resource_lookup_node and not has_ownership_check:
                    lineno = resource_lookup_node.lineno if hasattr(resource_lookup_node, "lineno") else node.lineno
                    snippet = self._extract_snippet(source_lines, lineno, lineno)
                    finding_id = f"FIND-CWE-639-{len(findings) + 1:03d}"
                    findings.append(
                        Finding(
                            id=finding_id,
                            vulnerability_class=VulnerabilityClass.IDOR,
                            cwe="CWE-639",
                            title="Authorization Bypass Through User-Controlled Key ('Insecure Direct Object Reference / IDOR')",
                            description=(
                                f"Route handler '{node.name}' accesses resource using user-controlled parameter '{target_param}' "
                                f"at line {lineno} without validating requestor identity or verifying resource ownership."
                            ),
                            severity=Severity.HIGH,
                            confidence="HIGH",
                            evidence_status=EvidenceStatus.STATIC_SUSPICION,
                            file_path=rel_path,
                            line_number=lineno,
                            sink_line=lineno,
                            source_expression=target_param,
                            code_snippet=snippet,
                            remediation_guidance=(
                                "Enforce authorization checks against authenticated session context: "
                                "verify `current_user.id == resource.owner_id` or restrict data access via tenant-scoped queries."
                            ),
                            metadata={"route": route_path, "parameter": target_param},
                        )
                    )

        return findings

    def _inspect_deserialization_sinks(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unsafe deserialization functions (CWE-502)."""
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                val_name = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                attr = node.func.attr
                is_pickle = val_name in ("pickle", "_pickle") and attr in ("loads", "load")
                is_marshal = val_name == "marshal" and attr in ("loads", "load")
                is_yaml_unsafe = False
                if val_name == "yaml" and attr == "load":
                    loader_arg = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
                    if loader_arg is None or not (isinstance(loader_arg, ast.Attribute) and loader_arg.attr == "SafeLoader"):
                        is_yaml_unsafe = True

                if is_pickle or is_marshal or is_yaml_unsafe:
                    snippet = self._extract_snippet(source_lines, node.lineno, node.lineno)
                    sink_name = f"{val_name}.{attr}"
                    finding_id = f"FIND-CWE-502-{len(findings) + 1:03d}"
                    findings.append(
                        Finding(
                            id=finding_id,
                            vulnerability_class=VulnerabilityClass.UNSAFE_DESERIALIZATION,
                            cwe="CWE-502",
                            title="Deserialization of Untrusted Data ('Unsafe Deserialization')",
                            description=(
                                f"Unsafe deserialization sink `{sink_name}()` invoked at line {node.lineno}. "
                                "Deserializing untrusted input can lead to arbitrary code execution."
                            ),
                            severity=Severity.CRITICAL,
                            evidence_status=EvidenceStatus.STATIC_SUSPICION,
                            file_path=rel_path,
                            line_number=node.lineno,
                            sink_line=node.lineno,
                            source_expression=sink_name,
                            code_snippet=snippet,
                            remediation_guidance="Use safe serialization formats like JSON or Pydantic, or yaml.safe_load().",
                            metadata={"sink_method": sink_name},
                        )
                    )
        unique_findings: List[Finding] = []
        seen: Set[Tuple[int, Optional[int]]] = set()
        for f in findings:
            key = (f.line_number, f.sink_line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        return unique_findings

    def _inspect_ssrf_sinks(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unvalidated dynamic outbound HTTP requests (CWE-918)."""
        findings: List[Finding] = []
        http_libs = {"requests", "httpx", "urllib"}
        has_url_validation = any(
            isinstance(c, ast.Call) and (
                (isinstance(c.func, ast.Name) and any(k in c.func.id.lower() for k in ("validate", "check_url", "is_safe_url")))
                or (isinstance(c.func, ast.Attribute) and any(k in c.func.attr.lower() for k in ("validate", "is_global", "is_private", "is_loopback", "check_url")))
            )
            for c in ast.walk(tree)
        )
        if has_url_validation:
            return findings

        for parent_node in ast.walk(tree):
            if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                func_params = {arg.arg for arg in getattr(parent_node, "args", ast.arguments()).args} if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()
                for node in ast.walk(parent_node):
                    if isinstance(node, ast.Call):
                        sink_name = ""
                        if isinstance(node.func, ast.Attribute):
                            val_name = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                            if val_name in http_libs and node.func.attr in ("get", "post", "request", "urlopen"):
                                sink_name = f"{val_name}.{node.func.attr}"

                        if sink_name and node.args:
                            url_arg = node.args[0]
                            dyn_info = self._get_dynamic_expr_info(url_arg)
                            vuln_type = None
                            expr_preview = ""
                            if dyn_info:
                                vuln_type = dyn_info["type"]
                                expr_preview = dyn_info.get("preview", "")
                            elif isinstance(url_arg, ast.Name) and url_arg.id in func_params:
                                vuln_type = f"Unsanitized parameter '{url_arg.id}'"
                                expr_preview = url_arg.id
                            elif isinstance(url_arg, ast.Attribute) and isinstance(url_arg.value, ast.Name) and url_arg.value.id in func_params:
                                vuln_type = f"Unsanitized parameter attribute '{url_arg.value.id}.{url_arg.attr}'"
                                expr_preview = f"{url_arg.value.id}.{url_arg.attr}"

                            if vuln_type:
                                snippet = self._extract_snippet(source_lines, node.lineno, node.lineno)
                                finding_id = f"FIND-CWE-918-{len(findings) + 1:03d}"
                                findings.append(
                                    Finding(
                                        id=finding_id,
                                        vulnerability_class=VulnerabilityClass.SSRF,
                                        cwe="CWE-918",
                                        title="Server-Side Request Forgery ('SSRF')",
                                        description=(
                                            f"Dynamic outbound HTTP request detected at line {node.lineno}. "
                                            f"Target URL constructed using {vuln_type} without allowlist validation."
                                        ),
                                        severity=Severity.HIGH,
                                        evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                        file_path=rel_path,
                                        line_number=node.lineno,
                                        sink_line=node.lineno,
                                        source_expression=expr_preview,
                                        code_snippet=snippet,
                                        remediation_guidance="Validate outbound request destinations against an explicit allowlist of permitted hosts.",
                                        metadata={"sink_method": sink_name},
                                    )
                                )
        unique_findings: List[Finding] = []
        seen: Set[Tuple[int, Optional[int]]] = set()
        for f in findings:
            key = (f.line_number, f.sink_line)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        return unique_findings

    def _inspect_hardcoded_secrets(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect hardcoded credentials, API keys, and sensitive tokens (CWE-798)."""
        findings: List[Finding] = []
        secret_var_names = {
            "api_key", "secret", "secret_key", "jwt_secret", "aws_secret_access_key",
            "private_key", "auth_token", "password", "db_password", "database_password",
            "app_secret", "master_key", "access_token", "token", "encryption_key",
        }
        known_signatures = [
            (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
            (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token"),
            (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "Slack API Token"),
            (re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"), "Embedded Private Key"),
        ]
        ignored_values = {
            "", "none", "null", "false", "true", "test", "demo", "sample",
            "example", "placeholder", "changeme", "change_me", "your_secret_here",
            "your_key_here", "your_api_key_here", "dev", "local", "root", "admin",
            "password", "123456", "default", "secret",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s_val = node.value.strip()
                for pattern, sig_name in known_signatures:
                    if pattern.search(s_val):
                        lineno = getattr(node, "lineno", 1)
                        snippet = self._extract_snippet(source_lines, lineno, lineno)
                        findings.append(
                            Finding(
                                id=f"FIND-CWE-798-{len(findings) + 1:03d}",
                                vulnerability_class=VulnerabilityClass.HARDCODED_SECRET,
                                cwe="CWE-798",
                                title=f"Use of Hard-coded Credentials ({sig_name})",
                                description=(
                                    f"Detected {sig_name} hardcoded directly into source code at line {lineno}. "
                                    "Sensitive credentials must never be committed to source repositories."
                                ),
                                severity=Severity.CRITICAL,
                                evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                file_path=rel_path,
                                line_number=lineno,
                                sink_line=lineno,
                                source_expression=sig_name,
                                code_snippet=snippet,
                                remediation_guidance="Store secrets in environment variables or an external secrets vault (e.g., AWS Secrets Manager, HashiCorp Vault).",
                                metadata={"secret_type": sig_name},
                            )
                        )

            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets: List[str] = []
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            targets.append(t.id)
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    targets.append(node.target.id)

                val_node = getattr(node, "value", None)
                if val_node and isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                    val_str = val_node.value.strip()
                    for t_name in targets:
                        norm_t = t_name.lower()
                        is_secret_name = (
                            norm_t in secret_var_names
                            or norm_t.endswith(("_api_key", "_secret", "_token", "_password", "_privkey", "_key"))
                        )
                        if is_secret_name:
                            # Skip self-referential enum definitions and constant identifiers (e.g. HARDCODED_SECRET = "HARDCODED_SECRET")
                            if val_str.upper() == t_name.upper():
                                continue
                            if len(val_str) >= 8 and val_str.lower() not in ignored_values and not val_str.startswith("$"):
                                lineno = node.lineno
                                snippet = self._extract_snippet(source_lines, lineno, lineno)
                                findings.append(
                                    Finding(
                                        id=f"FIND-CWE-798-{len(findings) + 1:03d}",
                                        vulnerability_class=VulnerabilityClass.HARDCODED_SECRET,
                                        cwe="CWE-798",
                                        title="Use of Hard-coded Credentials ('Hardcoded Secret')",
                                        description=(
                                            f"Sensitive credential `{t_name}` is assigned a hardcoded literal value at line {lineno}. "
                                            "Hardcoded secrets can be extracted from source code and version control history."
                                        ),
                                        severity=Severity.HIGH,
                                        evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                        file_path=rel_path,
                                        line_number=lineno,
                                        sink_line=lineno,
                                        source_expression=t_name,
                                        code_snippet=snippet,
                                        remediation_guidance="Load sensitive configuration from os.environ or a .env file that is excluded via .gitignore.",
                                        metadata={"variable_name": t_name},
                                    )
                                )

        unique: List[Finding] = []
        seen: Set[int] = set()
        for f in findings:
            if f.line_number not in seen:
                seen.add(f.line_number)
                unique.append(f)
        return unique

    def _inspect_weak_crypto(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect broken or deprecated cryptographic algorithms (CWE-327 / CWE-328)."""
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    call_name = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    call_name = node.func.id

                if call_name in ("hashlib.md5", "hashlib.sha1") or (
                    call_name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() in ("md5", "sha1")
                ):
                    is_safe = any(
                        kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                        for kw in node.keywords
                    )
                    if not is_safe:
                        algo = "MD5" if "md5" in call_name.lower() or (node.args and "md5" in str(node.args[0].value).lower()) else "SHA1"
                        lineno = node.lineno
                        snippet = self._extract_snippet(source_lines, lineno, lineno)
                        findings.append(
                            Finding(
                                id=f"FIND-CWE-327-{len(findings) + 1:03d}",
                                vulnerability_class=VulnerabilityClass.WEAK_CRYPTO,
                                cwe="CWE-327",
                                title=f"Use of a Broken or Risky Cryptographic Algorithm ({algo})",
                                description=(
                                    f"Cryptographically weak hashing algorithm `{algo}` invoked at line {lineno}. "
                                    f"{algo} is vulnerable to collision attacks and must not be used for security-sensitive operations."
                                ),
                                severity=Severity.MEDIUM,
                                evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                file_path=rel_path,
                                line_number=lineno,
                                sink_line=lineno,
                                source_expression=call_name,
                                code_snippet=snippet,
                                remediation_guidance=f"Replace `{algo}` with secure cryptographic hash algorithms such as SHA-256 (hashlib.sha256) or SHA-3, or pass usedforsecurity=False if strictly non-security.",
                                metadata={"algorithm": algo},
                            )
                        )

                elif any(wc in call_name for wc in ("DES.new", "ARC4.new", "Blowfish.new", "Crypto.Cipher.DES")):
                    lineno = node.lineno
                    snippet = self._extract_snippet(source_lines, lineno, lineno)
                    findings.append(
                        Finding(
                            id=f"FIND-CWE-327-{len(findings) + 1:03d}",
                            vulnerability_class=VulnerabilityClass.WEAK_CRYPTO,
                            cwe="CWE-327",
                            title="Use of Broken Cipher Algorithm",
                            description=(
                                f"Deprecated and broken cipher `{call_name}` instantiated at line {lineno}. "
                                "Legacy ciphers have known vulnerabilities and small key sizes."
                            ),
                            severity=Severity.HIGH,
                            evidence_status=EvidenceStatus.STATIC_SUSPICION,
                            file_path=rel_path,
                            line_number=lineno,
                            sink_line=lineno,
                            source_expression=call_name,
                            code_snippet=snippet,
                            remediation_guidance="Use AES-GCM (AES.MODE_GCM) or ChaCha20-Poly1305 for authenticated encryption.",
                            metadata={"cipher": call_name},
                        )
                    )

                elif "AES.new" in call_name or call_name == "Cipher":
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Attribute) and kw.value.attr == "MODE_ECB":
                            lineno = node.lineno
                            snippet = self._extract_snippet(source_lines, lineno, lineno)
                            findings.append(
                                Finding(
                                    id=f"FIND-CWE-327-{len(findings) + 1:03d}",
                                    vulnerability_class=VulnerabilityClass.WEAK_CRYPTO,
                                    cwe="CWE-327",
                                    title="Use of Electronic Codebook (ECB) Mode",
                                    description=(
                                        f"Insecure ECB encryption mode configured at line {lineno}. "
                                        "ECB mode does not provide pattern confidentiality and is semantically insecure."
                                    ),
                                    severity=Severity.HIGH,
                                    evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                    file_path=rel_path,
                                    line_number=lineno,
                                    sink_line=lineno,
                                    source_expression="AES.MODE_ECB",
                                    code_snippet=snippet,
                                    remediation_guidance="Use AES in GCM mode (AES.MODE_GCM) to ensure both confidentiality and authenticity.",
                                    metadata={"mode": "ECB"},
                                )
                            )

        unique: List[Finding] = []
        seen: Set[int] = set()
        for f in findings:
            if f.line_number not in seen:
                seen.add(f.line_number)
                unique.append(f)
        return unique

    def _inspect_open_redirect(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unvalidated open URL redirection (CWE-601)."""
        findings: List[Finding] = []
        redirect_params = {"next", "target", "redirect_url", "url", "return_to", "to", "dest", "out", "return"}

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_route = any(
                    isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr.lower() in ("get", "post", "put", "delete")
                    for dec in node.decorator_list
                )
                if not is_route:
                    continue

                route_params = {arg.arg for arg in node.args.args}
                matching_params = {
                    p for p in route_params
                    if p in redirect_params
                    or any(k in p.lower() for k in ("redirect", "url", "next", "dest", "target", "return"))
                }
                if not matching_params:
                    continue

                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        fn_name = ""
                        if isinstance(child.func, ast.Name):
                            fn_name = child.func.id
                        elif isinstance(child.func, ast.Attribute):
                            fn_name = child.func.attr

                        if fn_name in ("RedirectResponse", "redirect"):
                            call_arg_names = {sub.id for sub in ast.walk(child) if isinstance(sub, ast.Name)}
                            vulnerable_param = matching_params.intersection(call_arg_names)
                            if vulnerable_param:
                                p_name = list(vulnerable_param)[0]
                                lineno = child.lineno
                                snippet = self._extract_snippet(source_lines, lineno, lineno)
                                findings.append(
                                    Finding(
                                        id=f"FIND-CWE-601-{len(findings) + 1:03d}",
                                        vulnerability_class=VulnerabilityClass.OPEN_REDIRECT,
                                        cwe="CWE-601",
                                        title="URL Redirection to Untrusted Site ('Open Redirect')",
                                        description=(
                                            f"Route handler `{node.name}` redirects to user-controlled parameter `{p_name}` "
                                            f"at line {lineno} without validation. Attackers can leverage this to redirect victims to malicious phishing sites."
                                        ),
                                        severity=Severity.MEDIUM,
                                        evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                        file_path=rel_path,
                                        line_number=lineno,
                                        sink_line=lineno,
                                        source_expression=f"{fn_name}({p_name})",
                                        code_snippet=snippet,
                                        remediation_guidance="Validate destination URLs against an allowlist or verify that the target URL begins with a single slash '/' for relative paths.",
                                        metadata={"parameter": p_name, "redirect_call": fn_name},
                                    )
                                )

        unique: List[Finding] = []
        seen: Set[int] = set()
        for f in findings:
            if f.line_number not in seen:
                seen.add(f.line_number)
                unique.append(f)
        return unique

    def _inspect_cors_misconfiguration(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect insecure CORS policy combining wildcard origins and credentials (CWE-942)."""
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                is_cors = False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "add_middleware":
                    if node.args and isinstance(node.args[0], ast.Name) and "CORS" in node.args[0].id:
                        is_cors = True
                elif isinstance(node.func, ast.Name) and "CORS" in node.func.id:
                    is_cors = True

                if is_cors:
                    has_wildcard_origins = False
                    allows_credentials = False

                    for kw in node.keywords:
                        if kw.arg == "allow_origins":
                            if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == "*":
                                        has_wildcard_origins = True
                            elif isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                                has_wildcard_origins = True
                        elif kw.arg == "allow_credentials":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                allows_credentials = True

                    if has_wildcard_origins and allows_credentials:
                        lineno = node.lineno
                        snippet = self._extract_snippet(source_lines, lineno, lineno)
                        findings.append(
                            Finding(
                                id=f"FIND-CWE-942-{len(findings) + 1:03d}",
                                vulnerability_class=VulnerabilityClass.CORS_MISCONFIGURATION,
                                cwe="CWE-942",
                                title="Permissive CORS Policy with Credentials Allowed ('CORS Misconfiguration')",
                                description=(
                                    f"CORS middleware configured with wildcard origin `allow_origins=['*']` and `allow_credentials=True` at line {lineno}. "
                                    "This misconfiguration enables cross-origin credential theft and CSRF-like attacks."
                                ),
                                severity=Severity.HIGH,
                                evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                file_path=rel_path,
                                line_number=lineno,
                                sink_line=lineno,
                                source_expression="allow_origins=['*'], allow_credentials=True",
                                code_snippet=snippet,
                                remediation_guidance="Specify explicit, trusted domain origins in `allow_origins` rather than wildcard '*' when `allow_credentials=True` is enabled.",
                                metadata={"origins": "*", "credentials": True},
                            )
                        )

        return findings

    def _inspect_debug_mode(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect debug mode or reload enabled in server configuration (CWE-489)."""
        findings: List[Finding] = []
        var_defaults: Dict[str, bool] = {}
        for m_node in ast.walk(tree):
            if isinstance(m_node, ast.Assign):
                for t in m_node.targets:
                    if isinstance(t, ast.Name):
                        for sub in ast.walk(m_node.value):
                            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "getenv":
                                if len(sub.args) >= 2 and isinstance(sub.args[1], ast.Constant):
                                    str_val = str(sub.args[1].value).lower()
                                    if str_val in ("true", "1"):
                                        var_defaults[t.id] = True
                                    elif str_val in ("false", "0"):
                                        var_defaults[t.id] = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn_name = ""
                if isinstance(node.func, ast.Attribute):
                    val_id = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                    fn_name = f"{val_id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    fn_name = node.func.id

                if fn_name in ("uvicorn.run", "app.run", "FastAPI"):
                    for kw in node.keywords:
                        if kw.arg in ("debug", "reload"):
                            is_dbg = False
                            expr = ""
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                is_dbg = True
                                expr = f"{kw.arg}=True"
                            elif isinstance(kw.value, ast.Name) and var_defaults.get(kw.value.id) is True:
                                is_dbg = True
                                expr = f"{kw.arg}={kw.value.id} (default True)"

                            if is_dbg:
                                lineno = node.lineno
                                snippet = self._extract_snippet(source_lines, lineno, lineno)
                                findings.append(
                                    Finding(
                                        id=f"FIND-CWE-489-{len(findings) + 1:03d}",
                                        vulnerability_class=VulnerabilityClass.DEBUG_MODE_ENABLED,
                                        cwe="CWE-489",
                                        title="Active Debug Mode in Server Configuration",
                                        description=(
                                            f"Server configured with `{expr}` at line {lineno}. "
                                            "Running debug or auto-reload modes in production leaks detailed interactive tracebacks, internal paths, and secret environments."
                                        ),
                                        severity=Severity.LOW,
                                        evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                        file_path=rel_path,
                                        line_number=lineno,
                                        sink_line=lineno,
                                        source_expression=expr,
                                        code_snippet=snippet,
                                        remediation_guidance="Disable debug mode and auto-reload in production environments. Control debug behavior via environment variables.",
                                        metadata={"option": kw.arg},
                                    )
                                )

        return findings

    def _inspect_insecure_cookie(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect sensitive cookies set without HttpOnly or Secure flags (CWE-614 / CWE-1004)."""
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn_name = ""
                if isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie":
                    fn_name = "set_cookie"
                elif isinstance(node.func, ast.Name) and node.func.id == "set_cookie":
                    fn_name = "set_cookie"

                if fn_name == "set_cookie":
                    has_httponly = False
                    has_secure = False

                    for kw in node.keywords:
                        if kw.arg == "httponly" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            has_httponly = True
                        elif kw.arg == "secure" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            has_secure = True

                    if not has_httponly or not has_secure:
                        missing = []
                        if not has_httponly:
                            missing.append("httponly=True (CWE-1004)")
                        if not has_secure:
                            missing.append("secure=True (CWE-614)")
                        lineno = node.lineno
                        snippet = self._extract_snippet(source_lines, lineno, lineno)
                        findings.append(
                            Finding(
                                id=f"FIND-CWE-614-{len(findings) + 1:03d}",
                                vulnerability_class=VulnerabilityClass.INSECURE_COOKIE,
                                cwe="CWE-614",
                                title="Cookie Configured Without 'HttpOnly' or 'Secure' Security Flags",
                                description=(
                                    f"Cookie set at line {lineno} is missing: {', '.join(missing)}. "
                                    "Without HttpOnly, cookies are vulnerable to theft via Cross-Site Scripting (XSS). Without Secure, cookies can be intercepted over unencrypted HTTP."
                                ),
                                severity=Severity.MEDIUM,
                                evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                file_path=rel_path,
                                line_number=lineno,
                                sink_line=lineno,
                                source_expression="set_cookie(...)",
                                code_snippet=snippet,
                                remediation_guidance="Always set `httponly=True`, `secure=True`, and `samesite='lax'` (or 'strict') when storing session identifiers or sensitive cookies.",
                                metadata={"missing_flags": missing},
                            )
                        )

        return findings

    def _get_binop_string_preview(self, node: ast.BinOp) -> str:
        """Extract literal text from a concatenation chain."""
        text = ""
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            text += node.left.value + " "
        elif isinstance(node.left, ast.BinOp):
            text += self._get_binop_string_preview(node.left) + " "

        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
            text += node.right.value
        return text

    def _extract_snippet(self, source_lines: List[str], start_line: int, end_line: int, padding: int = 2) -> str:
        """Extract a formatted snippet with line numbers around the finding."""
        s = max(1, start_line - padding)
        e = min(len(source_lines), max(start_line, end_line) + padding)
        snippet_lines = []
        for i in range(s, e + 1):
            marker = " > " if i in (start_line, end_line) else "   "
            line_content = source_lines[i - 1] if i - 1 < len(source_lines) else ""
            snippet_lines.append(f"{i:4d}{marker}{line_content}")
        return "\n".join(snippet_lines)

    def _inspect_dependency_vulnerabilities(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unvalidated outbound requests to third-party dependencies / partner APIs (CWE-1395)."""
        findings: List[Finding] = []
        has_host_validation = any(
            isinstance(node, ast.Name) and any(k in node.id.lower() for k in ("allowed", "whitelist", "allowlist", "trusted"))
            for node in ast.walk(tree)
        )
        if has_host_validation:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                if call_name == "request" and len(node.args) >= 2:
                    url_arg = node.args[1]
                    if isinstance(url_arg, ast.Attribute) and isinstance(url_arg.value, ast.Name) and "request" in url_arg.value.id.lower():
                        lineno = node.lineno
                        snippet = self._extract_snippet(source_lines, lineno, lineno)
                        finding_id = f"FIND-CWE-1395-{len(findings) + 1:03d}"
                        findings.append(
                            Finding(
                                id=finding_id,
                                vulnerability_class=VulnerabilityClass.DEPENDENCY_VULNERABILITY,
                                cwe="CWE-1395",
                                title="Dependency / Unrestricted Partner Outbound Request",
                                description=(
                                    f"Outbound dependency HTTP request at line {lineno} contacts dynamic target without host allowlisting."
                                ),
                                severity=Severity.HIGH,
                                evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                file_path=rel_path,
                                line_number=lineno,
                                sink_line=lineno,
                                source_expression=f"http.request({url_arg.value.id}.{url_arg.attr})",
                                code_snippet=snippet,
                                remediation_guidance="Enforce scheme and domain allowlisting (e.g. ALLOWED_PARTNER_HOSTS) before invoking third-party integration sinks.",
                                metadata={"sink": "http.request"},
                            )
                        )
        return findings

    def _inspect_unvalidated_input(
        self, tree: ast.AST, source_lines: List[str], rel_path: str
    ) -> List[Finding]:
        """Detect unvalidated numeric parameters used directly in business logic / pricing (CWE-20)."""
        findings: List[Finding] = []
        has_field_bounds = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "Field":
                    for kw in node.keywords:
                        if kw.arg in ("gt", "ge", "min_length", "regex", "le", "lt"):
                            has_field_bounds = True
        if has_field_bounds:
            return findings

        for parent_node in ast.walk(tree):
            if isinstance(parent_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_name = parent_node.name.lower()
                is_cart_calc = any(k in fn_name for k in ("cart", "calculate", "discount", "pricing"))
                if not is_cart_calc:
                    for dec in parent_node.decorator_list:
                        if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
                            path_val = str(dec.args[0].value).lower()
                            if any(k in path_val for k in ("cart", "discount", "pricing")):
                                is_cart_calc = True
                if not is_cart_calc:
                    continue

                for node in ast.walk(parent_node):
                    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
                        names = set()
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Attribute) and sub.attr in ("quantity", "amount", "count"):
                                names.add(sub.attr)
                        if names:
                            lineno = node.lineno
                            attr_name = list(names)[0]
                            snippet = self._extract_snippet(source_lines, lineno, lineno)
                            finding_id = f"FIND-CWE-20-{len(findings) + 1:03d}"
                            findings.append(
                                Finding(
                                    id=finding_id,
                                    vulnerability_class=VulnerabilityClass.UNVALIDATED_INPUT,
                                    cwe="CWE-20",
                                    title="Improper Input Validation ('Unvalidated Numeric Input in Business Logic')",
                                    description=(
                                        f"Numeric parameter `{attr_name}` used in arithmetic calculation at line {lineno} without boundary constraints."
                                    ),
                                    severity=Severity.HIGH,
                                    evidence_status=EvidenceStatus.STATIC_SUSPICION,
                                    file_path=rel_path,
                                    line_number=lineno,
                                    sink_line=lineno,
                                    source_expression=f"request.{attr_name}",
                                    code_snippet=snippet,
                                    remediation_guidance="Constrain numeric inputs with Pydantic Field(..., gt=0, le=MAX) or explicit range validation.",
                                    metadata={"parameter": attr_name},
                                )
                            )
        return findings
