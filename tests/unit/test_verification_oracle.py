"""
Unit and Integration Tests for Independent Verification Oracle.
Verifies Gate A (functional integrity) and Gate B (security neutralization).
"""

import os
import pytest
from app.verification.workspace_manager import IsolatedWorkspace, apply_unified_diff
from app.verification.oracle import VerificationOracle, VerificationReport


VALID_SECURITY_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,3 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    # SECURE: Parameterized query
+    query = "SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = ?"
+    cursor.execute(query, (user_id,))
"""

REGRESSION_FAILURE_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    # Broken logic: always returns empty list, breaking legitimate customer queries
+    return {"count": 0, "records": []}
"""

SECURITY_FAILURE_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,2 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
+    # Fake fix: cosmetic comment change, query remains vulnerable
+    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
"""


def test_valid_patch_passes_both_gates():
    """Verify that a genuine parameterized SQL fix passes Gate A and Gate B and is ACCEPTED."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(VALID_SECURITY_PATCH, "target_app/app.py")
        assert os.path.exists(patched_file)

        oracle = VerificationOracle(patch_hash="abc123valid")
        report = oracle.verify_patched_target(patched_file)

        assert report.status == "ACCEPTED"
        assert report.gate_a_functional.passed is True
        assert report.gate_b_security.passed is True
        assert len(report.failure_reasons) == 0


def test_regression_patch_rejected_by_gate_a():
    """Verify that a patch breaking business functionality is REJECTED by Gate A."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(REGRESSION_FAILURE_PATCH, "target_app/app.py")

        oracle = VerificationOracle(patch_hash="def456regression")
        report = oracle.verify_patched_target(patched_file)

        assert report.status == "REJECTED"
        assert report.gate_a_functional.passed is False
        assert any("Alice's orders" in reason for reason in report.failure_reasons)


def test_unfixed_patch_rejected_by_gate_b():
    """Verify that a cosmetic patch that fails to neutralize the SQL injection is REJECTED by Gate B."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(SECURITY_FAILURE_PATCH, "target_app/app.py")

        oracle = VerificationOracle(patch_hash="ghi789insecure")
        report = oracle.verify_patched_target(patched_file)

        assert report.status == "REJECTED"
        assert report.gate_a_functional.passed is True
        assert report.gate_b_security.passed is False
        assert any("CRITICAL: Patch failed" in reason or "SQL injection active" in reason for reason in report.failure_reasons)
