"""
Deterministic State Machine for ZeroDay Arena Remediation Workflow.
Enforces explicit, valid state transitions and rejects illegal moves.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set

from app.core.errors import StateTransitionError


class RunState(str, Enum):
    """Lifecycle states of a remediation run."""
    CREATED = "CREATED"
    INGESTING = "INGESTING"
    ANALYZING = "ANALYZING"
    SCANNING = "SCANNING"
    EVIDENCE_GATHERING = "EVIDENCE_GATHERING"
    REPRODUCING = "REPRODUCING"
    PATCHING = "PATCHING"
    VERIFYING = "VERIFYING"
    ACCEPTED = "ACCEPTED"
    VERIFIED_SECURE = "VERIFIED_SECURE"
    SCAN_COMPLETE_NO_FINDINGS = "SCAN_COMPLETE_NO_FINDINGS"
    VULNERABILITIES_FOUND = "VULNERABILITIES_FOUND"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    SECURITY_RETEST_FAILED = "SECURITY_RETEST_FAILED"
    FAILED = "FAILED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


LEGAL_TRANSITIONS: Dict[RunState, Set[RunState]] = {
    RunState.CREATED: {
        RunState.INGESTING, RunState.ANALYZING, RunState.SCANNING,
        RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.INGESTING: {
        RunState.ANALYZING, RunState.SCANNING,
        RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.ANALYZING: {
        RunState.EVIDENCE_GATHERING, RunState.REPRODUCING, RunState.SCAN_COMPLETE_NO_FINDINGS,
        RunState.VULNERABILITIES_FOUND, RunState.PARTIAL, RunState.ACCEPTED, RunState.VERIFIED_SECURE,
        RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.SCANNING: {
        RunState.EVIDENCE_GATHERING, RunState.REPRODUCING, RunState.SCAN_COMPLETE_NO_FINDINGS,
        RunState.VULNERABILITIES_FOUND, RunState.PARTIAL, RunState.ACCEPTED, RunState.VERIFIED_SECURE,
        RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.EVIDENCE_GATHERING: {
        RunState.REPRODUCING, RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.REPRODUCING: {
        RunState.PATCHING, RunState.NOT_REPRODUCED, RunState.INCONCLUSIVE, RunState.ACCEPTED, RunState.VERIFIED_SECURE,
        RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.PATCHING: {
        RunState.PATCHING, RunState.VERIFYING, RunState.REJECTED, RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.VERIFYING: {
        RunState.ACCEPTED, RunState.VERIFIED_SECURE, RunState.REGRESSION_FAILED, RunState.SECURITY_RETEST_FAILED,
        RunState.REJECTED, RunState.PATCHING, RunState.INCONCLUSIVE, RunState.FAILED, RunState.EXECUTION_FAILED,
        RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.REJECTED: {
        RunState.PATCHING, RunState.FAILED, RunState.EXECUTION_FAILED, RunState.CANCELLED, RunState.TIMED_OUT,
    },
    RunState.ACCEPTED: set(),
    RunState.VERIFIED_SECURE: set(),
    RunState.SCAN_COMPLETE_NO_FINDINGS: set(),
    RunState.VULNERABILITIES_FOUND: set(),
    RunState.NOT_REPRODUCED: set(),
    RunState.INCONCLUSIVE: set(),
    RunState.REGRESSION_FAILED: set(),
    RunState.SECURITY_RETEST_FAILED: set(),
    RunState.FAILED: set(),
    RunState.EXECUTION_FAILED: set(),
    RunState.PARTIAL: set(),
    RunState.CANCELLED: set(),
    RunState.TIMED_OUT: set(),
}


class RemediationStateMachine:
    """Deterministic finite state machine tracking a single remediation run."""

    TERMINAL_STATES = {
        RunState.ACCEPTED,
        RunState.VERIFIED_SECURE,
        RunState.SCAN_COMPLETE_NO_FINDINGS,
        RunState.VULNERABILITIES_FOUND,
        RunState.NOT_REPRODUCED,
        RunState.INCONCLUSIVE,
        RunState.REJECTED,
        RunState.REGRESSION_FAILED,
        RunState.SECURITY_RETEST_FAILED,
        RunState.FAILED,
        RunState.EXECUTION_FAILED,
        RunState.PARTIAL,
        RunState.CANCELLED,
        RunState.TIMED_OUT,
    }

    def __init__(self, initial_state: RunState = RunState.CREATED) -> None:
        self._current_state: RunState = initial_state
        self._history: list[RunState] = [initial_state]

    @property
    def current_state(self) -> RunState:
        return self._current_state

    @property
    def is_terminal(self) -> bool:
        return self._current_state in self.TERMINAL_STATES

    def transition_to(self, new_state: RunState, reason: str = "") -> RunState:
        """
        Transition to a new state if legally permitted.
        Raises StateTransitionError if the transition is invalid.
        """
        allowed = LEGAL_TRANSITIONS.get(self._current_state, set())
        if new_state not in allowed:
            raise StateTransitionError(
                f"Illegal state transition from {self._current_state.value} to {new_state.value}. "
                f"Permitted destinations: {[s.value for s in allowed]}. Reason: {reason}"
            )
        self._current_state = new_state
        self._history.append(new_state)
        return self._current_state

    def get_history(self) -> list[str]:
        return [s.value for s in self._history]
