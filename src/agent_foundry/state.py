"""Agent Foundry v3 state machine: states, transitions, and terminality.

The durable machine is::

    accepted -> preparing -> ready -> running -> succeeded
                          \\          \\-> failed
                           \\-> failed  \\-> cancel_requested -> cancelled
                                          \\-> interrupted
                                          \\-> unknown_outcome

    any non-terminal state -> quarantined

Terminal states are immutable except for an explicit ``retry`` which opens a
new generation linked to the prior attempt. ``interrupted`` means the job is
known to have never started (no native identity was ever recorded).
``unknown_outcome`` means side effects are possible but unconfirmed; it is
never blindly replayed.
"""

from __future__ import annotations

ACCEPTED = "accepted"
PREPARING = "preparing"
READY = "ready"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCEL_REQUESTED = "cancel_requested"
CANCELLED = "cancelled"
INTERRUPTED = "interrupted"
UNKNOWN_OUTCOME = "unknown_outcome"
QUARANTINED = "quarantined"

TERMINAL = frozenset({SUCCEEDED, FAILED, CANCELLED, INTERRUPTED, UNKNOWN_OUTCOME, QUARANTINED})
NON_TERMINAL = frozenset({ACCEPTED, PREPARING, READY, RUNNING, CANCEL_REQUESTED})

# Explicit forward edges. Quarantine is handled separately: it is legal from
# any non-terminal state and illegal from any terminal state.
TRANSITIONS: dict[str, frozenset[str]] = {
    ACCEPTED: frozenset({PREPARING, FAILED, INTERRUPTED}),
    PREPARING: frozenset({READY, FAILED, CANCEL_REQUESTED, INTERRUPTED}),
    READY: frozenset({RUNNING, FAILED, CANCEL_REQUESTED, INTERRUPTED}),
    RUNNING: frozenset({SUCCEEDED, FAILED, CANCEL_REQUESTED, UNKNOWN_OUTCOME}),
    CANCEL_REQUESTED: frozenset({CANCELLED, UNKNOWN_OUTCOME, FAILED}),
    SUCCEEDED: frozenset(),
    FAILED: frozenset(),
    CANCELLED: frozenset(),
    INTERRUPTED: frozenset(),
    UNKNOWN_OUTCOME: frozenset(),
    QUARANTINED: frozenset(),
}

# States that may hold a native process/unit identity.
RUNNABLE = frozenset({READY, RUNNING, CANCEL_REQUESTED})


def is_terminal(state: str) -> bool:
    return state in TERMINAL


def can_transition(from_state: str, to_state: str) -> bool:
    """Return True when ``from_state -> to_state`` is a legal v3 edge."""
    if to_state == QUARANTINED:
        return from_state in NON_TERMINAL
    allowed = TRANSITIONS.get(from_state)
    if allowed is None:
        return False
    return to_state in allowed
