"""
Unit Tests for Patch Integrity and Safety Validation.
"""

import pytest
from app.verification.patch_integrity import PatchValidator, PatchValidationResult


SAMPLE_VALID_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,3 @@
-    query = f"SELECT * FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    query = "SELECT * FROM orders WHERE user_id = ?"
+    cursor.execute(query, (user_id,))
"""


def test_valid_patch_accepted():
    validator = PatchValidator(permitted_files={"target_app/app.py"})
    result = validator.validate_patch(SAMPLE_VALID_PATCH)
    assert result.is_valid is True
    assert result.rejection_reason is None
    assert "target_app/app.py" in result.target_files
    assert len(result.patch_hash) == 64


def test_malformed_patch_rejected():
    validator = PatchValidator()
    result = validator.validate_patch("This is just some random text with no diff headers")
    assert result.is_valid is False
    assert "Malformed patch" in result.rejection_reason


def test_test_file_tampering_rejected():
    malicious_patch = """--- a/tests/test_functional.py
+++ b/tests/test_functional.py
@@ -20,2 +20,2 @@
-    assert response.status_code == 200
+    pass
"""
    validator = PatchValidator()
    result = validator.validate_patch(malicious_patch)
    assert result.is_valid is False
    assert "Tampering detected" in result.rejection_reason


def test_path_traversal_in_patch_rejected():
    traversal_patch = """--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1,1 +1,1 @@
-root
+pwned
"""
    validator = PatchValidator()
    result = validator.validate_patch(traversal_patch)
    assert result.is_valid is False
    assert "Path traversal detected" in result.rejection_reason


def test_non_whitelisted_file_rejected():
    validator = PatchValidator(permitted_files={"target_app/app.py"})
    patch_other = """--- a/main.py
+++ b/main.py
@@ -1,1 +1,1 @@
-# comment
+# changed
"""
    result = validator.validate_patch(patch_other)
    assert result.is_valid is False
    assert "not in the permitted remediation whitelist" in result.rejection_reason
