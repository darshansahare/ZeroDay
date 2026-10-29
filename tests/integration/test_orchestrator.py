"""
Integration Tests for End-to-End Orchestrator Workflow.
"""

import os
import pytest
from app.config import AppConfig
from app.core.orchestrator import RemediationRun, DETERMINISTIC_SECURE_PATCH
from app.core.state_machine import RunState


# A bad patch that fails security verification
INSECURE_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,2 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
+    # Not secure: still vulnerable string formatting
+    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
"""


def test_orchestrator_successful_remediation():
    """Verify complete end-to-end remediation run reaches ACCEPTED with verified evidence."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config = AppConfig(workspace_root=workspace_root)

    run = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=DETERMINISTIC_SECURE_PATCH,
    )

    report = run.execute()

    assert run.state_machine.current_state == RunState.ACCEPTED
    assert report.is_verified_remediation is True
    assert report.final_status == "ACCEPTED"
    assert report.reproduction_result is not None
    assert report.reproduction_result.reproduced is True
    assert report.verification_outcome is not None
    assert report.verification_outcome.status == "ACCEPTED"
    assert len(report.code_findings) >= 1
    assert run.event_log.count() >= 5


def test_orchestrator_rejected_remediation():
    """Verify that when a proposed patch fails verification, the run terminates in REJECTED state."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config = AppConfig(workspace_root=workspace_root)

    run = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=INSECURE_PATCH,
        max_repair_attempts=2,
    )

    report = run.execute()

    assert run.state_machine.current_state == RunState.REJECTED
    assert report.is_verified_remediation is False
    assert report.final_status == "REJECTED"
    assert len(report.failure_reasons) >= 1


def test_orchestrator_repository_ingestion_and_login_remediation():
    """Verify repo ingestion of darshansahare/zeroday-test-1, actual AST findings, reproduction, and verification."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config = AppConfig(workspace_root=workspace_root)

    repo_url = "https://github.com/darshansahare/zeroday-test-1"
    commit = "2255ecc4a78dfe6c28ca1d863bccc2d2c79a6cf1"

    valid_login_patch = """--- a/app.py
+++ b/app.py
@@ -55,9 +55,12 @@
-  query = (
-      "SELECT id, username, role FROM users "
-      f"WHERE username = '{body.username}' "
-      f"AND password = '{body.password}' "
-  )
-
-  with connect() as conn:
-    row = conn.execute(query).fetchone()
+  with connect() as conn:
+    row = conn.execute(
+        "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
+        (body.username, body.password),
+    ).fetchone()
"""

    run = RemediationRun(
        target_path="app.py",
        config=config,
        repo_url=repo_url,
        commit_sha=commit,
        candidate_patch=valid_login_patch,
    )

    report = run.execute()

    assert run.state_machine.current_state == RunState.ACCEPTED
    assert report.is_verified_remediation is True
    assert report.final_status == "ACCEPTED"
    assert report.pinned_commit.startswith("2255ecc")
    assert len(report.code_findings) >= 1
    primary = report.code_findings[0]
    assert "body.username" in primary.code_snippet
    assert "user_id = '{" not in primary.code_snippet
    assert report.reproduction_result is not None
    assert report.reproduction_result.reproduced is True
    assert report.reproduction_result.unauthorized_data_accessed is True
    assert report.reproduction_result.leaked_secret_detected is False
    assert report.verification_outcome.status == "ACCEPTED"
