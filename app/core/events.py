"""
Structured Event Logging for ZeroDay Arena.
Records observable actions, state transitions, tool results, and gate verifications.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExecutionEvent(BaseModel):
    """Observable execution event recorded during a remediation lifecycle."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    event_type: str
    severity: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL
    details: Dict[str, Any] = Field(default_factory=dict)


class EventLog:
    """In-memory event collection for a single remediation run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._events: List[ExecutionEvent] = []

    def record(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "INFO",
    ) -> ExecutionEvent:
        event = ExecutionEvent(
            run_id=self.run_id,
            event_type=event_type,
            severity=severity,
            details=details or {},
        )
        self._events.append(event)
        return event

    def get_events(self) -> List[ExecutionEvent]:
        return list(self._events)

    def count(self) -> int:
        return len(self._events)
