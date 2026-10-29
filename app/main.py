"""
ZeroDay Arena - Autonomous Vulnerability Remediation Backend Engine
Canonical FastAPI application entrypoint.
Aliases the production application from main.py for full consistency across tests and production runners.
"""

from main import app

__all__ = ["app"]

