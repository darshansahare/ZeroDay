"""
ZeroDay Arena Exception Hierarchy.
Deterministic and structured error types for all stages of analysis,
sandboxing, patching, and verification.
"""

from typing import Any, Dict, Optional


class ZDAError(Exception):
    """Base exception for all ZeroDay Arena errors."""

    def __init__(
        self,
        message: str,
        code: str = "ZDA_GENERIC_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize error to structured dictionary for logging and reporting."""
        return {
            "error_code": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(ZDAError):
    """Raised when application or environment configuration is invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_CONFIG_ERROR", details=details)


class SecurityViolationError(ZDAError):
    """Raised when an action violates security policies (e.g. path traversal, unauthorized edits)."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_SECURITY_VIOLATION", details=details)


class AnalysisError(ZDAError):
    """Raised when code analysis fails unexpectedly."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_ANALYSIS_ERROR", details=details)


class DependencyAnalysisError(ZDAError):
    """Raised when dependency manifest parsing or correlation fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_DEPENDENCY_ERROR", details=details)


class SandboxError(ZDAError):
    """Raised when the target execution sandbox fails to start, execute, or clean up."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_SANDBOX_ERROR", details=details)


class ExecutionTimeoutError(SandboxError):
    """Raised when execution of a target or test exceeds its allotted time limit."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, details=details)
        self.code = "ZDA_EXECUTION_TIMEOUT"


class PatchIntegrityError(ZDAError):
    """Raised when a patch is malformed, modifies unauthorized files, or fails to apply cleanly."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_PATCH_INTEGRITY_ERROR", details=details)


class VerificationGateError(ZDAError):
    """Raised when a patch fails independent functional or security verification gates."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_VERIFICATION_FAILED", details=details)


class ProviderError(ZDAError):
    """Raised when an external inference (Nemotron) or intelligence (Tavily) provider fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_PROVIDER_ERROR", details=details)


class StateTransitionError(ZDAError):
    """Raised when an invalid or illegal state machine transition is attempted."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, code="ZDA_INVALID_STATE_TRANSITION", details=details)

