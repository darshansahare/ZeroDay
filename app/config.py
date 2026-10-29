"""
ZeroDay Arena Configuration Module.
Strict environment validation, secret masking, and filesystem workspace constraints.
"""

import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, SecretStr, field_validator

from app.core.errors import ConfigurationError, SecurityViolationError


def load_dotenv_file(filepath: Path | str = ".env") -> None:
    """Load key-value environment variables from local .env file without overriding existing env."""
    path = Path(filepath)
    if path.exists() and path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


# Automatically load workspace root .env if present
load_dotenv_file()

ADMIN_KEY_FILENAME = ".zd_admin_key"


def resolve_admin_key(workspace_root: Path) -> SecretStr:
    """
    Resolve or securely initialize administrator key without leaking it to logs or public endpoints.
    1. Checks environment variables ADMIN_API_KEY and ZERODAY_API_KEY.
    2. If absent, checks/initializes local protected key file (.zd_admin_key) with 0600 permissions.
    3. If secure file creation is impossible, fails safely by raising ConfigurationError.
    """
    for env_var in ("ADMIN_API_KEY", "ZERODAY_API_KEY"):
        val = os.getenv(env_var)
        if val and val.strip():
            return SecretStr(val.strip())

    key_file = workspace_root / ADMIN_KEY_FILENAME
    if key_file.exists() and key_file.is_file():
        try:
            content = key_file.read_text(encoding="utf-8").strip()
            if content:
                return SecretStr(content)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to read existing administrator key file at {key_file}: {e}"
            )

    # Secure initialization: write new random key with owner-only (0600) permissions
    try:
        new_key = secrets.token_urlsafe(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(str(key_file), flags, mode)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(new_key + "\n")
        try:
            os.chmod(str(key_file), 0o600)
        except Exception:
            pass
        return SecretStr(new_key)
    except Exception as e:
        raise ConfigurationError(
            f"Unable to securely initialize administrator key file at {key_file}: {e}. "
            "Please configure ADMIN_API_KEY in the environment or .env file."
        )


class AppConfig(BaseModel):
    """Immutable runtime configuration for ZeroDay Arena."""

    # Workspace & Environment
    workspace_root: Path = Field(
        default_factory=lambda: Path(os.getenv("ZDA_WORKSPACE_ROOT", os.getcwd())).resolve()
    )
    sandbox_enabled: bool = Field(
        default_factory=lambda: os.getenv("ZDA_SANDBOX_ENABLED", "false").lower() in ("true", "1", "yes")
    )
    max_repair_attempts: int = Field(
        default_factory=lambda: int(os.getenv("ZDA_MAX_REPAIR_ATTEMPTS", "3"))
    )
    execution_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("TEST_EXECUTION_TIMEOUT_SECONDS", os.getenv("ZDA_EXECUTION_TIMEOUT_SECONDS", "30")))
    )

    # Timeouts & Governance Limits
    analysis_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "600"))
    )
    test_execution_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("TEST_EXECUTION_TIMEOUT_SECONDS", "30"))
    )
    per_device_rate_limit: int = Field(
        default_factory=lambda: int(os.getenv("PER_DEVICE_RATE_LIMIT", "999999"))
    )
    per_device_rate_window_seconds: int = Field(
        default_factory=lambda: int(os.getenv("PER_DEVICE_RATE_WINDOW_SECONDS", "3600"))
    )
    global_rate_limit: int = Field(
        default_factory=lambda: int(os.getenv("GLOBAL_RATE_LIMIT", "999999"))
    )
    global_rate_window_seconds: int = Field(
        default_factory=lambda: int(os.getenv("GLOBAL_RATE_WINDOW_SECONDS", "3600"))
    )
    max_repository_size_mb: int = Field(
        default_factory=lambda: int(os.getenv("MAX_REPOSITORY_SIZE_MB", "10"))
    )
    max_scan_files: int = Field(
        default_factory=lambda: int(os.getenv("MAX_SCAN_FILES", "100"))
    )
    max_concurrent_analyses: int = Field(
        default_factory=lambda: int(os.getenv("MAX_CONCURRENT_ANALYSES", "999"))
    )
    nebius_budget_usd: float = Field(
        default_factory=lambda: float(os.getenv("NEBIUS_BUDGET_USD", "999999.00"))
    )
    nebius_budget_safety_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NEBIUS_BUDGET_SAFETY_THRESHOLD", "1.00"))
    )

    # Administrative & API Protection Secret
    admin_api_key: SecretStr = Field(
        default_factory=lambda: resolve_admin_key(
            Path(os.getenv("ZDA_WORKSPACE_ROOT", os.getcwd())).resolve()
        )
    )

    # LLM Provider Configuration: Nebius Token Factory (NVIDIA Nemotron)
    llm_provider: str = Field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "nebius").lower()
    )
    nebius_api_key: Optional[SecretStr] = Field(
        default_factory=lambda: SecretStr(os.environ["NEBIUS_API_KEY"]) if "NEBIUS_API_KEY" in os.environ and os.environ["NEBIUS_API_KEY"].strip() else None
    )
    nebius_base_url: str = Field(
        default_factory=lambda: os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
    )
    nebius_model: str = Field(
        default_factory=lambda: os.getenv("NEBIUS_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
    )
    nebius_benchmark_model: str = Field(
        default_factory=lambda: os.getenv("NEBIUS_BENCHMARK_MODEL", "nvidia/nemotron-3-super-120b-a12b")
    )

    # Search / Threat Intelligence Provider Configuration: Tavily
    search_provider: str = Field(
        default_factory=lambda: os.getenv("SEARCH_PROVIDER", "tavily").lower()
    )
    tavily_api_key: Optional[SecretStr] = Field(
        default_factory=lambda: SecretStr(os.environ["TAVILY_API_KEY"]) if "TAVILY_API_KEY" in os.environ and os.environ["TAVILY_API_KEY"].strip() else None
    )

    # Token Optimization & Caching
    cache_enabled: bool = Field(
        default_factory=lambda: os.getenv("CACHE_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    cache_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("CACHE_TTL_SECONDS", "86400"))
    )
    cache_dir: str = Field(
        default_factory=lambda: os.getenv("CACHE_DIR", ".cache")
    )

    # Execution Boundaries
    max_scan_file_size_bytes: int = 1_048_576  # 1 MB
    excluded_directories: set[str] = {
        ".git",
        ".cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "frontend",
        "static_dist",
        "venv",
        ".venv",
        "dist",
        "build",
        "sandboxes",
        ADMIN_KEY_FILENAME,
    }

    @field_validator("workspace_root", mode="before")
    @classmethod
    def validate_workspace_root(cls, v: Any) -> Path:
        resolved = Path(v).resolve()
        if not resolved.exists():
            raise ConfigurationError(
                f"Configured workspace_root does not exist: {resolved}",
                details={"provided_path": str(v), "resolved_path": str(resolved)},
            )
        if not resolved.is_dir():
            raise ConfigurationError(
                f"Configured workspace_root is not a directory: {resolved}",
                details={"resolved_path": str(resolved)},
            )
        return resolved

    @field_validator("max_repair_attempts")
    @classmethod
    def validate_repair_attempts(cls, v: int) -> int:
        if v < 1 or v > 10:
            raise ConfigurationError("max_repair_attempts must be between 1 and 10", details={"value": v})
        return v

    def validate_path_within_workspace(self, target_path: Path | str) -> Path:
        """
        Guarantees that a target path resides strictly inside workspace_root.
        Prevents directory traversal, symlink escapes, and unauthorized file access.
        """
        candidate = Path(target_path)
        if not candidate.is_absolute():
            candidate = (self.workspace_root / candidate).resolve()
        else:
            candidate = candidate.resolve()

        try:
            candidate.relative_to(self.workspace_root)
        except ValueError:
            raise SecurityViolationError(
                f"Path traversal detected: {target_path} is outside workspace root {self.workspace_root}",
                details={"target": str(target_path), "workspace_root": str(self.workspace_root)},
            )
        return candidate

    def to_safe_dict(self) -> Dict[str, Any]:
        """Serialize configuration with all credentials securely masked/redacted."""
        return {
            "workspace_root": str(self.workspace_root),
            "sandbox_enabled": self.sandbox_enabled,
            "max_repair_attempts": self.max_repair_attempts,
            "execution_timeout_seconds": self.execution_timeout_seconds,
            "analysis_timeout_seconds": self.analysis_timeout_seconds,
            "test_execution_timeout_seconds": self.test_execution_timeout_seconds,
            "per_device_rate_limit": self.per_device_rate_limit,
            "per_device_rate_window_seconds": self.per_device_rate_window_seconds,
            "global_rate_limit": self.global_rate_limit,
            "global_rate_window_seconds": self.global_rate_window_seconds,
            "max_repository_size_mb": self.max_repository_size_mb,
            "max_concurrent_analyses": self.max_concurrent_analyses,
            "nebius_budget_usd": self.nebius_budget_usd,
            "nebius_budget_safety_threshold": self.nebius_budget_safety_threshold,
            "admin_auth_configured": bool(
                os.getenv("ADMIN_API_KEY")
                or os.getenv("ZERODAY_API_KEY")
                or (self.workspace_root / ADMIN_KEY_FILENAME).exists()
            ),
            # Active provider selection & settings
            "llm_provider": self.llm_provider,
            "nebius_configured": self.nebius_api_key is not None,
            "nebius_base_url": self.nebius_base_url,
            "nebius_model": self.nebius_model,
            "nebius_benchmark_model": self.nebius_benchmark_model,
            "search_provider": self.search_provider,
            "tavily_configured": self.tavily_api_key is not None,
            "max_scan_file_size_bytes": self.max_scan_file_size_bytes,
        }


def get_config() -> AppConfig:
    """Helper to instantiate or retrieve runtime configuration."""
    return AppConfig()
