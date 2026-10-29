"""
Target Sandbox Manager - Disposable, isolated execution for target microservice.
Executes target code in an isolated subprocess with scrubbed environment credentials.
Never executes untrusted target code within the ZeroDay backend process.
"""

from __future__ import annotations

import os
import sys
import shutil
import socket
import tempfile
import time
import subprocess
from typing import Any, Dict, Optional, Set
from dataclasses import dataclass
import httpx

from app.core.errors import SandboxError, ExecutionTimeoutError

STRIP_ENV_VARS: Set[str] = {
    "NEBIUS_API_KEY",
    "TAVILY_API_KEY",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "SECRET_KEY",
    "API_KEY",
    "ADMIN_API_KEY",
    "ZERODAY_API_KEY",
    "PGPASSWORD",
    "MYSQL_PWD",
    "REDIS_URL",
    "MONGODB_URI",
    "JWT_SECRET",
    "COOKIE_SECRET",
    "AUTH_SECRET",
    "PRIVATE_KEY",
}

SAFE_ENV_PASSTHROUGH: Set[str] = {
    "PATH",
    "PATHEXT",
    "PYTHONPATH",
    "HOMEPATH",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "LOGONSERVER",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
}

SENSITIVE_ENV_SUBSTRINGS = (
    "KEY",
    "SECRET",
    "TOKEN",
    "PASS",
    "CREDENTIAL",
    "PRIVATE",
    "AUTH",
    "DSN",
)


def is_sensitive_env_variable(key: str) -> bool:
    """Return True if an environment variable represents a secret or credential."""
    if key in STRIP_ENV_VARS:
        return True
    k_upper = key.upper()
    if k_upper in SAFE_ENV_PASSTHROUGH:
        return False
    return any(marker in k_upper for marker in SENSITIVE_ENV_SUBSTRINGS)


@dataclass
class SandboxResponse:
    """Bounded, structured response from sandboxed target execution."""
    status_code: int
    headers: Dict[str, str]
    text: str
    json_data: Optional[Dict[str, Any]] = None
    elapsed_seconds: float = 0.0


class TargetSandbox:
    """
    Manages the lifecycle of an isolated, disposable target microservice sandbox.
    Runs the target in an isolated subprocess with scrubbed credentials and network containment.
    """

    def __init__(
        self,
        target_app_module: str = "target_app.app",
        target_file_path: Optional[str] = None,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        self.target_app_module = target_app_module
        self.target_file_path = target_file_path
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.temp_dir: Optional[str] = None
        self.db_path: Optional[str] = None
        self.port: Optional[int] = None
        self.process: Optional[subprocess.Popen] = None
        self.http_client: Optional[httpx.Client] = None
        self._is_active = False

    def start(self) -> TargetSandbox:
        """Initialize the disposable sandbox in an isolated child process."""
        if self._is_active:
            return self

        try:
            self.temp_dir = tempfile.mkdtemp(prefix="zda_sandbox_")
            self.db_path = os.path.join(self.temp_dir, "isolated_orders.db")
            # Touch database file so it exists initially
            with open(self.db_path, "a", encoding="utf-8") as f:
                pass

            # Allocate free ephemeral port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
            sock.close()

            # Create isolated runner script
            runner_script = os.path.join(self.temp_dir, "_isolated_runner.py")
            with open(runner_script, "w", encoding="utf-8") as f:
                f.write(
                    "import sys, os, importlib\n"
                    "from pathlib import Path\n"
                    "_orig_mkdir = Path.mkdir\n"
                    "def _patched_mkdir(self, *args, **kwargs):\n"
                    "    if 'exists_ok' in kwargs:\n"
                    "        kwargs['exist_ok'] = kwargs.pop('exists_ok')\n"
                    "    return _orig_mkdir(self, *args, **kwargs)\n"
                    "Path.mkdir = _patched_mkdir\n"
                    "target_file = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '__NONE__' else None\n"
                    "target_module = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != '__NONE__' else None\n"
                    "port = int(sys.argv[3])\n"
                    "db_path = sys.argv[4] if len(sys.argv) > 4 else None\n"
                    "if db_path:\n"
                    "    os.environ['ZDA_TARGET_DB_PATH'] = db_path\n"
                    "app = None\n"
                    "if target_file and os.path.exists(target_file):\n"
                    "    target_dir = os.path.dirname(os.path.abspath(target_file))\n"
                    "    if target_dir not in sys.path:\n"
                    "        sys.path.insert(0, target_dir)\n"
                    "    mod_name = os.path.splitext(os.path.basename(target_file))[0]\n"
                    "    try:\n"
                    "        mod = importlib.import_module(mod_name)\n"
                    "        if hasattr(mod, 'init_db') and callable(mod.init_db):\n"
                    "            try:\n"
                    "                mod.init_db()\n"
                    "            except Exception:\n"
                    "                pass\n"
                    "        app = getattr(mod, 'app', None) or getattr(mod, 'application', None)\n"
                    "        if app is None and hasattr(mod, 'create_app'):\n"
                    "            app = mod.create_app()\n"
                    "    except Exception as e:\n"
                    "        sys.stderr.write(f'Module import failed: {e}\\n')\n"
                    "        sys.exit(1)\n"
                    "    if app is None:\n"
                    "        for f in os.listdir(target_dir):\n"
                    "            if f.endswith('.py') and f != os.path.basename(target_file):\n"
                    "                try:\n"
                    "                    s_mod = importlib.import_module(os.path.splitext(f)[0])\n"
                    "                    app = getattr(s_mod, 'app', None) or getattr(s_mod, 'application', None)\n"
                    "                    if app is not None:\n"
                    "                        break\n"
                    "                except Exception:\n"
                    "                    pass\n"
                    "elif target_module:\n"
                    "    try:\n"
                    "        mod = importlib.import_module(target_module)\n"
                    "        if hasattr(mod, 'init_db') and callable(mod.init_db):\n"
                    "            try:\n"
                    "                mod.init_db()\n"
                    "            except Exception:\n"
                    "                pass\n"
                    "        app = getattr(mod, 'app', None) or getattr(mod, 'application', None)\n"
                    "        if app is None and hasattr(mod, 'create_app'):\n"
                    "            app = mod.create_app()\n"
                    "    except Exception as e:\n"
                    "        sys.stderr.write(f'Target module import failed: {e}\\n')\n"
                    "        sys.exit(1)\n"
                    "if app is None:\n"
                    "    sys.stderr.write('No ASGI app instance exposed in target\\n')\n"
                    "    sys.exit(1)\n"
                    "import uvicorn\n"
                    "uvicorn.run(app, host='127.0.0.1', port=port, log_level='warning')\n"
                )

            # Scrub all secrets and sensitive credentials from target environment
            clean_env = {
                k: v for k, v in os.environ.items()
                if not is_sensitive_env_variable(k)
            }
            clean_env["PYTHONUNBUFFERED"] = "1"
            clean_env["ZDA_TARGET_DB_PATH"] = self.db_path
            
            # Resolve target file path to absolute path so it can be located when running with isolated cwd
            target_f_arg = os.path.abspath(self.target_file_path) if (self.target_file_path and os.path.exists(self.target_file_path)) else "__NONE__"
            target_m_arg = self.target_app_module if target_f_arg == "__NONE__" else "__NONE__"

            target_dir = os.path.dirname(target_f_arg) if target_f_arg != "__NONE__" else os.getcwd()
            host_root = os.getcwd()
            clean_env["PYTHONPATH"] = f"{target_dir}{os.pathsep}{host_root}"

            self.process = subprocess.Popen(
                [sys.executable, runner_script, target_f_arg, target_m_arg, str(self.port), self.db_path],
                env=clean_env,
                cwd=self.temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Readiness polling
            self.http_client = httpx.Client(
                base_url=f"http://127.0.0.1:{self.port}",
                timeout=httpx.Timeout(self.timeout_seconds),
            )

            start_t = time.monotonic()
            ready = False
            while time.monotonic() - start_t < 6.0:
                if self.process.poll() is not None:
                    _, err = self.process.communicate()
                    raise SandboxError(f"Isolated target process exited immediately: {err.decode('utf-8', errors='replace')}")

                try:
                    r = self.http_client.get("/")
                    ready = True
                    break
                except httpx.HTTPStatusError:
                    ready = True
                    break
                except Exception:
                    time.sleep(0.08)

            if not ready:
                raise SandboxError("Target sandbox failed to become responsive within startup timeout limit (6s)")

            self._is_active = True
            return self

        except Exception as e:
            self.close()
            raise SandboxError(f"Failed to start target sandbox: {e}") from e

    def execute_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> SandboxResponse:
        """
        Execute an HTTP request against the isolated sandbox with timeout and payload bounds.
        """
        if not self._is_active or not self.http_client:
            raise SandboxError("Sandbox is not active. Call start() or use context manager.")

        start_time = time.monotonic()
        try:
            # Enforce relative paths and block external schemes / SSRF
            clean_path = path.strip()
            if clean_path.startswith("http://") or clean_path.startswith("https://") or clean_path.startswith("//"):
                raise SandboxError("Target sandbox request path must be relative, not an absolute URL")
            if not clean_path.startswith("/"):
                clean_path = "/" + clean_path

            http_method = method.upper()
            if http_method == "GET":
                resp = self.http_client.get(clean_path, params=params, headers=headers)
            elif http_method == "POST":
                resp = self.http_client.post(clean_path, json=json_data, params=params, headers=headers)
            elif http_method == "PUT":
                resp = self.http_client.put(clean_path, json=json_data, params=params, headers=headers)
            elif http_method == "DELETE":
                resp = self.http_client.delete(clean_path, params=params, headers=headers)
            else:
                raise SandboxError(f"Unsupported HTTP method: {method}")

            elapsed = time.monotonic() - start_time
            if elapsed > self.timeout_seconds:
                raise ExecutionTimeoutError(
                    f"Request exceeded timeout limit of {self.timeout_seconds}s (elapsed: {elapsed:.2f}s)"
                )

            # Enforce bounded payload size
            raw_text = resp.text
            if len(raw_text.encode("utf-8")) > self.max_response_bytes:
                raw_text = raw_text[: self.max_response_bytes]

            parsed_json = None
            try:
                parsed_json = resp.json()
            except Exception:
                pass

            return SandboxResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=raw_text,
                json_data=parsed_json,
                elapsed_seconds=elapsed,
            )

        except httpx.TimeoutException:
            raise ExecutionTimeoutError(f"Request exceeded timeout limit of {self.timeout_seconds}s")
        except ExecutionTimeoutError:
            raise
        except Exception as e:
            raise SandboxError(f"Sandbox execution failed: {e}") from e

    def close(self) -> None:
        """Clean up all disposable sandbox resources and kill child process tree."""
        self._is_active = False

        if self.http_client:
            try:
                self.http_client.close()
            except Exception:
                pass
            self.http_client = None

        if self.process:
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                        capture_output=True,
                        timeout=5.0,
                    )
                else:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=1.0)
            except Exception:
                pass

            try:
                if self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=1.0)
            except Exception:
                pass
            self.process = None

        # Remove temporary directory
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass
            self.temp_dir = None
            self.db_path = None

    def __enter__(self) -> TargetSandbox:
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
