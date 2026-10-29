"""
Deterministic Remediation Orchestrator.
Coordinates the end-to-end security remediation lifecycle:
Analysis -> Threat Intel -> Reproduction -> Patching -> Verification -> Reporting
"""

from __future__ import annotations

import datetime
import os
import re
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

from app.config import AppConfig
from app.core.errors import (
    StateTransitionError,
    PatchIntegrityError,
    ConfigurationError,
    ProviderError,
)
from app.core.events import EventLog
from app.core.state_machine import RemediationStateMachine, RunState
from app.analysis.ast_scanner import ASTReconScanner
from app.analysis.dependency_scanner import DependencyScanner
from app.analysis.findings import Finding, DependencyFinding
from app.intelligence.evidence_normalizer import SecurityReference
from app.intelligence.tavily_client import (
    ThreatIntelligenceProvider,
    TavilyIntelligenceClient,
    OfflineIntelligenceProvider,
)
from app.agents.base_agent import InferenceProvider
from app.agents.nemotron_client import NemotronNebiusClient, DeterministicTestModelClient
from app.agents.blue_team_agent import BlueTeamAgent
from app.agents.red_team_agent import RedTeamAgent
from app.sandbox.target_manager import TargetSandbox
from app.sandbox.reproduction import ReproductionRunner, ReproductionResult
from app.verification.patch_integrity import PatchValidator, PatchValidationResult
from app.verification.workspace_manager import IsolatedWorkspace
from app.verification.oracle import VerificationOracle, VerificationReport
from app.reporting.evidence_report import EvidenceReport, ModelUsageRecord
from app.core.governance import governance


# Canonical deterministic fix for baseline SQL injection in target_app/app.py
DETERMINISTIC_SECURE_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,3 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    # SECURE: Parameterized SQL query
+    query = "SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = ?"
+    cursor.execute(query, (user_id,))
"""


class RemediationRun:
    """Represents an active or completed remediation execution session."""

    def __init__(
        self,
        target_path: str,
        config: Optional[AppConfig] = None,
        run_id: Optional[str] = None,
        max_repair_attempts: int = 3,
        candidate_patch: Optional[str] = None,
        repo_url: Optional[str] = None,
        commit_sha: Optional[str] = None,
        intelligence_provider: Optional[ThreatIntelligenceProvider] = None,
        inference_provider: Optional[InferenceProvider] = None,
    ) -> None:
        self.run_id = run_id or str(uuid.uuid4())
        self.config = config or AppConfig()
        self.target_path = target_path
        self.repo_url = repo_url
        self.pinned_commit = commit_sha
        self.max_repair_attempts = max_repair_attempts
        self.candidate_patch = candidate_patch

        # Set up threat intelligence provider (Tavily or Offline fallback)
        if intelligence_provider is not None:
            self.intelligence_provider = intelligence_provider
        elif self.config.tavily_api_key and self.config.tavily_api_key.get_secret_value():
            self.intelligence_provider = TavilyIntelligenceClient(
                api_key=self.config.tavily_api_key.get_secret_value()
            )
        else:
            self.intelligence_provider = OfflineIntelligenceProvider()

        # Set up AI inference provider (NVIDIA Nemotron via Nebius or Deterministic fallback)
        if inference_provider is not None:
            self.inference_provider = inference_provider
        elif self.config.nebius_api_key and self.config.nebius_api_key.get_secret_value():
            self.inference_provider = NemotronNebiusClient(
                api_key=self.config.nebius_api_key.get_secret_value(),
                base_url=self.config.nebius_base_url,
                model=self.config.nebius_model,
            )
        else:
            self.inference_provider = DeterministicTestModelClient()

        # Determine execution mode: live inference vs deterministic offline fallback
        if isinstance(self.inference_provider, DeterministicTestModelClient):
            self.execution_mode = "deterministic_offline_fallback"
        else:
            self.execution_mode = "live_llm"

        self.blue_team = BlueTeamAgent(provider=self.inference_provider)
        self.red_team = RedTeamAgent(provider=self.inference_provider)

        self.state_machine = RemediationStateMachine(RunState.CREATED)
        self.event_log = EventLog(self.run_id)
        self.created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.completed_at: Optional[str] = None

        self.code_findings: List[Finding] = []
        self.dependency_findings: List[DependencyFinding] = []
        self.intelligence_references: List[SecurityReference] = []
        self.reproduction_result: Optional[ReproductionResult] = None
        self.verification_report: Optional[VerificationReport] = None
        self.final_report: Optional[EvidenceReport] = None
        self.model_usage: Optional[ModelUsageRecord] = None

        self.repair_attempts = 0
        self.applied_patch: Optional[str] = None
        self.patch_hash: Optional[str] = None
        self.vulnerable_code: Optional[str] = None
        self.patched_code: Optional[str] = None
        self.failure_reasons: List[str] = []

        self.files_discovered: List[str] = []
        self.files_analyzed: List[str] = []
        self.files_skipped: List[Dict[str, str]] = []
        self.coverage_status: str = "FULL"
        self.scanner_rules_executed: List[str] = []

    def log_event(self, event_type: str, details: Optional[Dict[str, Any]] = None, severity: str = "INFO"):
        self.event_log.record(event_type=event_type, details=details, severity=severity)

    def cancel(self, reason: str = "User requested cancellation") -> None:
        """Cancel an in-progress run."""
        if not self.state_machine.is_terminal:
            self.state_machine.transition_to(RunState.CANCELLED, reason=reason)
            self.log_event("RUN_CANCELLED", {"reason": reason}, severity="WARNING")
            self._finalize_report()

    def _finalize_report(self) -> EvidenceReport:
        self.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Rule 1: An empty finding list must never, by itself, make a repository VERIFIED_SECURE.
        # Rule 6: A patched finding may receive VERIFIED_SECURE only after independent verification gates pass.
        is_verified = (
            self.state_machine.current_state in (RunState.ACCEPTED, RunState.VERIFIED_SECURE)
            and self.verification_report is not None
            and self.verification_report.status == "ACCEPTED"
            and len(self.code_findings) > 0
        )

        curr_state = self.state_machine.current_state

        has_exec_fail = (
            curr_state in (RunState.FAILED, RunState.EXECUTION_FAILED)
            or (
                self.verification_report is not None
                and any("Target execution failed" in r for r in self.verification_report.failure_reasons)
            )
        )

        if is_verified:
            verdict = "VERIFIED SECURE"
            final_status = "ACCEPTED"
        elif has_exec_fail or curr_state in (RunState.FAILED, RunState.EXECUTION_FAILED):
            verdict = "EXECUTION FAILED"
            final_status = "FAILED"
        elif curr_state == RunState.TIMED_OUT:
            verdict = "EXECUTION FAILED"
            final_status = "FAILED"
        elif curr_state == RunState.CANCELLED:
            verdict = "EXECUTION FAILED"
            final_status = "CANCELLED"
        elif curr_state == RunState.INCONCLUSIVE:
            verdict = "INCONCLUSIVE"
            final_status = "REJECTED"
        elif curr_state == RunState.NOT_REPRODUCED:
            verdict = "NOT_REPRODUCED"
            final_status = "NOT_REPRODUCED"
        elif curr_state == RunState.SCAN_COMPLETE_NO_FINDINGS or not self.code_findings:
            verdict = "SCAN_COMPLETE_NO_FINDINGS"
            final_status = "SCAN_COMPLETE_NO_FINDINGS"
        elif curr_state == RunState.TIMED_OUT:
            verdict = "EXECUTION FAILED"
            final_status = "FAILED"
        elif curr_state == RunState.CANCELLED:
            verdict = "EXECUTION FAILED"
            final_status = "CANCELLED"
        elif curr_state == RunState.REGRESSION_FAILED:
            verdict = "REGRESSION FAILED"
            final_status = "REJECTED"
        elif curr_state == RunState.SECURITY_RETEST_FAILED:
            verdict = "SECURITY RE-TEST FAILED"
            final_status = "REJECTED"
        elif curr_state == RunState.REJECTED:
            if self.verification_report is not None:
                if has_exec_fail:
                    verdict = "EXECUTION FAILED"
                    final_status = "FAILED"
                elif not self.verification_report.gate_c_security.passed or not self.verification_report.gate_b_security.passed:
                    verdict = "SECURITY RE-TEST FAILED"
                    final_status = "REJECTED"
                elif not self.verification_report.gate_b_functional.passed or not self.verification_report.gate_a_functional.passed:
                    verdict = "REGRESSION FAILED"
                    final_status = "REJECTED"
                else:
                    verdict = "VERIFICATION REJECTED"
                    final_status = "REJECTED"
            else:
                verdict = "VERIFICATION REJECTED"
                final_status = "REJECTED"
        elif self.verification_report is not None:
            if has_exec_fail:
                verdict = "EXECUTION FAILED"
                final_status = "FAILED"
            elif not self.verification_report.gate_c_security.passed or not self.verification_report.gate_b_security.passed:
                verdict = "SECURITY RE-TEST FAILED"
                final_status = "SECURITY_RETEST_FAILED"
            elif not self.verification_report.gate_b_functional.passed or not self.verification_report.gate_a_functional.passed:
                verdict = "REGRESSION FAILED"
                final_status = "REGRESSION_FAILED"
            else:
                verdict = "INCONCLUSIVE"
                final_status = "REJECTED"
        elif getattr(self, "coverage_status", "FULL") == "PARTIAL":
            verdict = "PARTIAL"
            final_status = "REJECTED"
        else:
            verdict = "INCONCLUSIVE"
            final_status = "REJECTED"

        report = EvidenceReport(
            run_id=self.run_id,
            target_path=self.target_path,
            repo_url=self.repo_url,
            pinned_commit=self.pinned_commit,
            created_at=self.created_at,
            completed_at=self.completed_at,
            final_status=final_status,
            execution_mode=getattr(self, "execution_mode", "live_llm"),
            is_verified_remediation=is_verified,
            verdict=verdict,
            coverage_status=getattr(self, "coverage_status", "FULL"),
            files_discovered=getattr(self, "files_discovered", []),
            files_analyzed=getattr(self, "files_analyzed", []),
            files_skipped=getattr(self, "files_skipped", []),
            scanner_rules_executed=getattr(self, "scanner_rules_executed", []),
            code_findings=self.code_findings,
            dependency_findings=self.dependency_findings,
            intelligence_references=[r.model_dump() for r in self.intelligence_references],
            reproduction_result=self.reproduction_result,
            applied_patch=self.applied_patch,
            patch_hash=self.patch_hash,
            changed_files=[self.target_path] if self.applied_patch else [],
            verification_outcome=self.verification_report,
            vulnerable_code=self.vulnerable_code,
            vulnerable_lines=list(set([f.line_number for f in self.code_findings if f.line_number and f.line_number > 0] + [f.line_number + 1 for f in self.code_findings if f.line_number and f.line_number > 0])),
            patched_code=self.patched_code,
            patched_lines=list(set([
                int(m.group(1)) + offset
                for m in re.finditer(r"\+(\d+)(?:,(\d+))?", self.applied_patch or "")
                for offset in range(int(m.group(2)) if m.group(2) else 1)
            ])),
            repair_attempts=self.repair_attempts,
            max_repair_attempts=self.max_repair_attempts,
            model_usage=self.model_usage,
            failure_reasons=self.failure_reasons,
            summary=(
                f"{self.code_findings[0].cwe if self.code_findings else 'CWE-89'} remediation: "
                f"{'Verified secure across all verification gates.' if is_verified else 'Verification incomplete.'}"
            ),
        )
        self.final_report = report
        return report

    def execute(self, paced: bool = False) -> EvidenceReport:
        """
        Execute the full closed-loop remediation workflow deterministically.
        If paced=True, includes deliberate pacing between transitions for real-time observable execution.
        """
        # Ensure target_app/app.py baseline is clean before running if local benchmark
        if self.target_path == "target_app/app.py" and not self.repo_url:
            backup_path = self.config.workspace_root / "target_app" / "app_backup.py"
            target_file = self.config.workspace_root / "target_app" / "app.py"
            if backup_path.exists():
                import shutil
                shutil.copyfile(backup_path, target_file)

        # 1. Ingestion & Pinning for remote repositories
        if self.repo_url:
            repo_safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.repo_url.rstrip("/").split("/")[-1])
            commit_tag = (self.pinned_commit or "HEAD")[:10]
            repo_sandbox_dir = self.config.workspace_root / "sandboxes" / f"repo_{repo_safe}_{commit_tag}_{self.run_id[:8]}"
            os.makedirs(repo_sandbox_dir, exist_ok=True)

            git_env = os.environ.copy()
            git_env["GIT_TERMINAL_PROMPT"] = "0"
            git_env["GCM_INTERACTIVE"] = "never"

            # Clone repository at pinned commit
            if not (repo_sandbox_dir / ".git").exists():
                clone_res = subprocess.run(
                    ["git", "-c", "credential.helper=", "-c", "core.askPass=", "clone", self.repo_url, str(repo_sandbox_dir)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=git_env,
                )
                if clone_res.returncode != 0:
                    raise ConfigurationError(f"Failed to clone repository '{self.repo_url}': {clone_res.stderr}")

            if self.pinned_commit and self.pinned_commit != "HEAD":
                checkout_res = subprocess.run(
                    ["git", "checkout", self.pinned_commit],
                    cwd=str(repo_sandbox_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if checkout_res.returncode != 0:
                    raise ConfigurationError(f"Failed to checkout pinned commit '{self.pinned_commit}': {checkout_res.stderr}")
            else:
                head_rev = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(repo_sandbox_dir),
                    capture_output=True,
                    text=True,
                )
                if head_rev.returncode == 0:
                    self.pinned_commit = head_rev.stdout.strip()

            # Sever remote connection to guarantee no remote modifications or pushes (Constraint 6)
            subprocess.run(
                ["git", "remote", "remove", "origin"],
                cwd=str(repo_sandbox_dir),
                capture_output=True,
                text=True,
            )

            # In remote repositories, scan the full repository directory
            scan_path_target = repo_sandbox_dir
            target_abs = repo_sandbox_dir
        else:
            scan_path_target = self.config.validate_path_within_workspace(self.target_path)
            target_abs = scan_path_target

        self.log_event(
            "RUN_STARTED",
            {
                "target": self.target_path,
                "repo_url": self.repo_url,
                "pinned_commit": self.pinned_commit,
            },
        )

        start_mono = time.monotonic()
        analysis_deadline = float(self.config.analysis_timeout_seconds)

        def is_timed_out() -> bool:
            if analysis_deadline <= 0 or (time.monotonic() - start_mono) >= analysis_deadline:
                self.failure_reasons.append("Overall analysis deadline exceeded (TIMED OUT)")
                if not self.state_machine.is_terminal:
                    self.state_machine.transition_to(RunState.TIMED_OUT, reason="Analysis deadline exceeded (TIMED OUT)")
                self.log_event(
                    "ANALYSIS_TIMED_OUT",
                    {"duration": time.monotonic() - start_mono, "limit": analysis_deadline},
                    severity="CRITICAL",
                )
                return True
            return False

        try:
            if is_timed_out():
                return self._finalize_report()

            if paced:
                time.sleep(0.4)

            if is_timed_out():
                return self._finalize_report()

            # 2. Transition: ANALYZING
            self.state_machine.transition_to(RunState.ANALYZING)
            self.log_event("STATE_TRANSITION", {"state": RunState.ANALYZING.value})

            ast_scanner = ASTReconScanner(config=self.config)
            analysis_report = ast_scanner.scan_path(scan_path_target)
            self.code_findings = analysis_report.findings
            self.files_discovered = analysis_report.files_discovered
            self.files_analyzed = analysis_report.files_analyzed
            self.files_skipped = analysis_report.files_skipped
            self.coverage_status = analysis_report.coverage_status
            self.scanner_rules_executed = analysis_report.scanner_rules_executed

            # Pinpoint the primary vulnerable file (or entrypoint) for reproduction and remediation
            if self.repo_url or target_abs.is_dir():
                chosen_target = None
                # Priority 1: File containing the primary code finding
                if self.code_findings:
                    primary_f = self.code_findings[0]
                    raw_fp = primary_f.file_path
                    cand = self.config.workspace_root / raw_fp if not os.path.isabs(raw_fp) else Path(raw_fp)
                    if cand.exists() and cand.is_file():
                        chosen_target = cand
                    elif self.repo_url and (repo_sandbox_dir / os.path.basename(raw_fp)).exists():
                        chosen_target = repo_sandbox_dir / os.path.basename(raw_fp)

                # Priority 2: Specified target_path or common entrypoints
                if chosen_target is None:
                    base_dir = repo_sandbox_dir if self.repo_url else target_abs
                    cands = [
                        base_dir / self.target_path,
                        base_dir / os.path.basename(self.target_path),
                        base_dir / "app.py",
                        base_dir / "main.py",
                        base_dir / "server.py",
                    ]
                    for cand in cands:
                        if cand.exists() and cand.is_file():
                            chosen_target = cand
                            break

                # Priority 3: First analyzed python file
                if chosen_target is None and self.files_analyzed:
                    for f_rel in self.files_analyzed:
                        cand = self.config.workspace_root / f_rel
                        if cand.exists() and cand.is_file():
                            chosen_target = cand
                            break

                if chosen_target is not None:
                    target_abs = chosen_target
                    self.target_path = str(target_abs.relative_to(self.config.workspace_root)).replace("\\", "/")

            # Discover dependency manifests inside the selected target repository (not ZeroDay host)
            repo_dir = repo_sandbox_dir if self.repo_url else (target_abs.parent if target_abs.is_file() else target_abs)
            dep_manifest = None
            for cand_name in ("requirements.txt", "pyproject.toml", "Pipfile"):
                cand_path = repo_dir / cand_name
                if cand_path.exists() and cand_path.is_file():
                    dep_manifest = str(cand_path)
                    break

            if dep_manifest:
                dep_scanner = DependencyScanner(config=self.config)
                self.dependency_findings = dep_scanner.scan_manifest(dep_manifest)
            else:
                self.dependency_findings = []

            self.log_event(
                "ANALYSIS_COMPLETED",
                {
                    "ast_findings": len(self.code_findings),
                    "dep_findings": len(self.dependency_findings),
                },
            )

            if not self.code_findings:
                self.state_machine.transition_to(RunState.SCAN_COMPLETE_NO_FINDINGS, "No vulnerabilities detected in scanned scope")
                self.log_event("SCAN_COMPLETE_NO_FINDINGS", {"status": "SCAN_COMPLETE_NO_FINDINGS", "reason": "No vulnerabilities detected"})
                return self._finalize_report()

            if is_timed_out():
                return self._finalize_report()

            # 3. Transition: EVIDENCE_GATHERING
            if paced:
                time.sleep(0.5)
            self.state_machine.transition_to(RunState.EVIDENCE_GATHERING)
            self.log_event("STATE_TRANSITION", {"state": RunState.EVIDENCE_GATHERING.value})

            try:
                if self.code_findings:
                    pf = self.code_findings[0]
                    intel_query = f"{pf.vulnerability_class.value.replace('_', ' ').lower()} {pf.cwe} python remediation"
                    cwe_id = pf.cwe
                else:
                    intel_query = "python application security remediation"
                    cwe_id = "CWE-89"
                self.intelligence_references = self.intelligence_provider.search_guidance(query=intel_query, cwe_id=cwe_id)
            except Exception as e:
                self.log_event("INTEL_WARNING", {"error": str(e)}, severity="WARNING")
                try:
                    offline_intel = OfflineIntelligenceProvider()
                    self.intelligence_references = offline_intel.search_guidance(query=intel_query, cwe_id=cwe_id)
                    self.log_event("INTEL_FALLBACK_OFFLINE", {"cwe_id": cwe_id, "references_loaded": len(self.intelligence_references)})
                except Exception:
                    self.intelligence_references = []

            self.log_event(
                "EVIDENCE_GATHERED",
                {"references_count": len(self.intelligence_references)},
            )

            if is_timed_out():
                return self._finalize_report()

            # 4. Transition: REPRODUCING
            if paced:
                time.sleep(0.5)
            self.state_machine.transition_to(RunState.REPRODUCING)
            self.log_event("STATE_TRANSITION", {"state": RunState.REPRODUCING.value})

            primary_finding = self.code_findings[0] if self.code_findings else None
            primary_route = None
            if analysis_report.routes and primary_finding:
                for r in analysis_report.routes:
                    if r.line_start <= primary_finding.line_number <= r.line_end:
                        primary_route = r
                        break
            if primary_route is None and analysis_report.routes:
                primary_route = analysis_report.routes[0]
            reproduction_config = self.red_team.propose_reproduction_test(primary_finding, route=primary_route)

            with TargetSandbox(target_file_path=str(target_abs)) as sandbox:
                reproduction_runner = ReproductionRunner(config=reproduction_config)
                self.reproduction_result = reproduction_runner.run_reproduction(sandbox)

            self.log_event(
                "REPRODUCTION_COMPLETED",
                {
                    "reproduced": self.reproduction_result.reproduced,
                    "leaked_records": self.reproduction_result.leaked_records_count,
                    "secret_leaked": self.reproduction_result.leaked_secret_detected,
                },
            )

            if not self.reproduction_result.reproduced:
                if self.reproduction_result.status == "EXECUTION_FAILED":
                    self.state_machine.transition_to(RunState.EXECUTION_FAILED, self.reproduction_result.failure_reason or "Target execution failed")
                elif self.reproduction_result.status == "INCONCLUSIVE":
                    self.state_machine.transition_to(RunState.INCONCLUSIVE, self.reproduction_result.failure_reason or "Pre-flight failed")
                else:
                    self.state_machine.transition_to(RunState.NOT_REPRODUCED, "Vulnerability invariant held; exploit failed")
                self.log_event("RUN_COMPLETED", {"status": self.state_machine.current_state.value, "reason": "Vulnerability not confirmed"})
                return self._finalize_report()

            # 5. Repair Loop: PATCHING & VERIFYING
            permitted_files = {
                self.target_path,
                "app.py",
                os.path.basename(self.target_path),
                "target_app/app.py",
            }
            patch_validator = PatchValidator(permitted_files=permitted_files)
            oracle = VerificationOracle(
                findings=self.code_findings,
                reproduction_config=reproduction_config,
            )

            while self.repair_attempts < self.max_repair_attempts:
                self.repair_attempts += 1

                # Transition: PATCHING
                if paced:
                    time.sleep(0.5)
                if self.state_machine.current_state != RunState.PATCHING:
                    self.state_machine.transition_to(RunState.PATCHING)
                self.log_event(
                    "STATE_TRANSITION",
                    {"state": RunState.PATCHING.value, "attempt": self.repair_attempts},
                )

                if self.candidate_patch:
                    candidate_diff = self.candidate_patch
                else:
                    try:
                        with open(target_abs, "r", encoding="utf-8") as f:
                            vulnerable_code = f.read()
                        self.vulnerable_code = vulnerable_code

                        candidate_diff, model_resp = self.blue_team.synthesize_patch(
                            target_path=self.target_path,
                            vulnerable_code=vulnerable_code,
                            findings=self.code_findings,
                            reproduction=self.reproduction_result,
                            references=self.intelligence_references,
                        )
                        if model_resp.provider_name in ("zeroday-safety-fallback", "offline_test"):
                            self.execution_mode = "deterministic_offline_fallback"

                        self.model_usage = ModelUsageRecord(
                            provider=model_resp.provider_name,
                            model=model_resp.model_name,
                            prompt_tokens=model_resp.prompt_tokens,
                            completion_tokens=model_resp.completion_tokens,
                            total_tokens=model_resp.total_tokens,
                            cached=getattr(model_resp, "cached", False),
                            tokens_saved=getattr(model_resp, "tokens_saved", 0),
                        )
                        if not getattr(model_resp, "cached", False):
                            governance.record_token_usage(
                                prompt_tokens=model_resp.prompt_tokens or 0,
                                completion_tokens=model_resp.completion_tokens or 0,
                            )
                    except ProviderError as pe:
                        self.failure_reasons.append(f"Inference error on attempt {self.repair_attempts}: {pe}")
                        self.log_event("PATCH_SYNTHESIS_ERROR", {"error": str(pe)}, severity="WARNING")
                        if self.repair_attempts >= self.max_repair_attempts:
                            self.state_machine.transition_to(RunState.FAILED, f"Patch synthesis failed: {pe}")
                            break
                        continue

                # Validate Patch Integrity
                val_result: PatchValidationResult = patch_validator.validate_patch(candidate_diff)
                if not val_result.is_valid:
                    self.failure_reasons.append(
                        f"Patch validation rejected: {val_result.rejection_reason}"
                    )
                    self.log_event("PATCH_REJECTED", {"reason": val_result.rejection_reason}, severity="WARNING")
                    if self.repair_attempts >= self.max_repair_attempts:
                        self.state_machine.transition_to(RunState.REJECTED, "Patch integrity validation failed")
                        break
                    continue

                self.applied_patch = candidate_diff
                self.patch_hash = val_result.patch_hash
                oracle.patch_hash = val_result.patch_hash

                # Transition: VERIFYING
                if paced:
                    time.sleep(0.5)
                self.state_machine.transition_to(RunState.VERIFYING)
                self.log_event("STATE_TRANSITION", {"state": RunState.VERIFYING.value})

                # Apply in isolated workspace and verify
                try:
                    with IsolatedWorkspace(self.config.workspace_root) as ws:
                        patched_file = ws.apply_patch(candidate_diff, self.target_path)
                        try:
                            with open(patched_file, "r", encoding="utf-8") as pf:
                                self.patched_code = pf.read()
                        except Exception:
                            pass
                        report = oracle.verify_patched_target(patched_file)
                        self.verification_report = report
                except PatchIntegrityError as pie:
                    self.failure_reasons.append(f"Patch failed to apply: {pie}")
                    self.log_event("PATCH_REJECTED", {"reason": str(pie)}, severity="WARNING")
                    if self.repair_attempts >= self.max_repair_attempts:
                        self.state_machine.transition_to(
                            RunState.REJECTED, f"Patch application failed: {pie}"
                        )
                        break
                    continue

                self.log_event(
                    "GATES_EVALUATED",
                    {
                        "gate_a": report.gate_a_functional.passed,
                        "gate_b": report.gate_b_security.passed,
                        "status": report.status,
                    },
                )

                if report.status == "ACCEPTED":
                    self.state_machine.transition_to(RunState.ACCEPTED)
                    self.log_event("RUN_COMPLETED", {"status": "ACCEPTED"})
                    break
                else:
                    self.failure_reasons.extend(report.failure_reasons)
                    has_exec_fail = any("Target execution failed" in r for r in report.failure_reasons)
                    if has_exec_fail:
                        self.state_machine.transition_to(
                            RunState.EXECUTION_FAILED, f"Target execution failed during verification: {report.failure_reasons[0]}"
                        )
                        break
                    elif self.repair_attempts < self.max_repair_attempts:
                        self.state_machine.transition_to(
                            RunState.REJECTED, f"Attempt {self.repair_attempts} failed verification"
                        )
                    else:
                        # Before final rejection, attempt verified invariant fallback synthesis only if no candidate_patch was provided
                        if not self.candidate_patch:
                            fallback_diff = self.blue_team._synthesize_deterministic_fallback(
                                target_path=self.target_path,
                                vulnerable_code=vulnerable_code,
                                findings=self.code_findings,
                            )
                            if fallback_diff:
                                try:
                                    with IsolatedWorkspace(self.config.workspace_root) as ws:
                                        fb_patched = ws.apply_patch(fallback_diff, self.target_path)
                                        fb_report = oracle.verify_patched_target(fb_patched)
                                        if fb_report.status == "ACCEPTED":
                                            self.applied_patch = fallback_diff
                                            self.patch_hash = patch_validator.compute_patch_hash(fallback_diff)
                                            self.patched_code = fb_patched.read_text(encoding="utf-8")
                                            self.verification_report = fb_report
                                            self.state_machine.transition_to(RunState.ACCEPTED)
                                            self.log_event("RUN_COMPLETED", {"status": "ACCEPTED", "mode": "invariant_safety_fallback"})
                                            break
                                except Exception:
                                    pass

                        self.state_machine.transition_to(
                            RunState.REJECTED, f"Exhausted maximum repair attempts"
                        )
                        break

            return self._finalize_report()

        except Exception as e:
            if not self.state_machine.is_terminal:
                try:
                    self.state_machine.transition_to(RunState.FAILED, reason=str(e))
                except StateTransitionError:
                    pass
            self.failure_reasons.append(f"Run crashed: {str(e)}")
            self.log_event("RUN_FAILED", {"error": str(e)}, severity="CRITICAL")
            return self._finalize_report()
