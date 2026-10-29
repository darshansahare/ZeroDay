"""
Unit Tests for State Machine and Event Logging Subsystems.
"""

import pytest
from app.core.state_machine import RemediationStateMachine, RunState
from app.core.errors import StateTransitionError
from app.core.events import EventLog


def test_valid_state_transitions():
    sm = RemediationStateMachine(RunState.CREATED)
    assert sm.current_state == RunState.CREATED

    sm.transition_to(RunState.ANALYZING)
    assert sm.current_state == RunState.ANALYZING

    sm.transition_to(RunState.REPRODUCING)
    assert sm.current_state == RunState.REPRODUCING

    sm.transition_to(RunState.PATCHING)
    assert sm.current_state == RunState.PATCHING

    sm.transition_to(RunState.VERIFYING)
    assert sm.current_state == RunState.VERIFYING

    sm.transition_to(RunState.ACCEPTED)
    assert sm.current_state == RunState.ACCEPTED
    assert sm.is_terminal is True


def test_illegal_state_transition_rejected():
    sm = RemediationStateMachine(RunState.CREATED)
    # Cannot jump directly from CREATED to ACCEPTED
    with pytest.raises(StateTransitionError, match="Illegal state transition"):
        sm.transition_to(RunState.ACCEPTED)


def test_terminal_state_rejects_further_transitions():
    sm = RemediationStateMachine(RunState.CREATED)
    sm.transition_to(RunState.CANCELLED)
    assert sm.is_terminal is True

    with pytest.raises(StateTransitionError, match="Illegal state transition"):
        sm.transition_to(RunState.ANALYZING)


def test_event_log_records_and_retrieves():
    log = EventLog(run_id="run-123")
    assert log.count() == 0

    log.record("TEST_EVENT", {"detail": "sample"})
    log.record("TEST_EVENT_2", {"detail": "sample2"}, severity="WARNING")

    assert log.count() == 2
    events = log.get_events()
    assert events[0].event_type == "TEST_EVENT"
    assert events[0].severity == "INFO"
    assert events[1].event_type == "TEST_EVENT_2"
    assert events[1].severity == "WARNING"
