#!/usr/bin/env python3
"""Bounded exhaustive model of the secure Bluetooth session state machine.

The model abstracts cryptographic authenticity to an `authentic` frame bit and
then explores legitimate and attacker-controlled ordering, replay, tampering,
expiry, mismatch, and disposal transitions. Cryptographic byte compatibility is
covered separately by the shared Rust/Dart conformance vector.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from enum import Enum, auto


class Role(Enum):
    INITIATOR = auto()
    RESPONDER = auto()

    @property
    def peer(self) -> "Role":
        return Role.RESPONDER if self is Role.INITIATOR else Role.INITIATOR


class Phase(Enum):
    PAIRING = auto()
    PENDING = auto()
    ACTIVE = auto()
    TERMINAL = auto()


@dataclass(frozen=True, order=True)
class Frame:
    sender: Role
    counter: int
    authentic: bool = True


@dataclass(frozen=True)
class Action:
    kind: str
    role: Role | None = None
    frame: int | None = None
    delta: int = 0


@dataclass(frozen=True)
class State:
    now: int = 0
    initiator_phase: Phase = Phase.PAIRING
    responder_phase: Phase = Phase.PAIRING
    pending_at: int | None = None
    initiator_confirmed_at: int | None = None
    responder_confirmed_at: int | None = None
    initiator_tx: int = 0
    responder_tx: int = 0
    initiator_rx: int = 0
    responder_rx: int = 0
    channel: tuple[Frame, ...] = ()
    used_nonces: frozenset[tuple[Role, int]] = frozenset()
    accepted: frozenset[tuple[Role, Role, int, int]] = frozenset()


# Small finite bounds preserve the implementation's boundary relationships.
# The production constants are 120 seconds, 300 seconds, and 4,096 frames.
CONFIRMATION_WINDOW = 2
SESSION_LIFETIME = 5
MAX_FRAMES = 2
MAX_TIME = SESSION_LIFETIME + 2


def phase(state: State, role: Role) -> Phase:
    return state.initiator_phase if role is Role.INITIATOR else state.responder_phase


def confirmed_at(state: State, role: Role) -> int | None:
    return (
        state.initiator_confirmed_at
        if role is Role.INITIATOR
        else state.responder_confirmed_at
    )


def tx_counter(state: State, role: Role) -> int:
    return state.initiator_tx if role is Role.INITIATOR else state.responder_tx


def rx_counter(state: State, role: Role) -> int:
    return state.initiator_rx if role is Role.INITIATOR else state.responder_rx


def with_phase(state: State, role: Role, value: Phase) -> State:
    if role is Role.INITIATOR:
        return replace(state, initiator_phase=value)
    return replace(state, responder_phase=value)


def with_tx(state: State, role: Role, value: int) -> State:
    if role is Role.INITIATOR:
        return replace(state, initiator_tx=value)
    return replace(state, responder_tx=value)


def with_rx(state: State, role: Role, value: int) -> State:
    if role is Role.INITIATOR:
        return replace(state, initiator_rx=value)
    return replace(state, responder_rx=value)


def is_expired(state: State, role: Role) -> bool:
    confirmed = confirmed_at(state, role)
    return confirmed is not None and state.now - confirmed > SESSION_LIFETIME


def actions(state: State) -> tuple[Action, ...]:
    candidates = [Action("derive")]
    for role in Role:
        candidates.extend(
            (
                Action("confirm_match", role),
                Action("confirm_mismatch", role),
                Action("send", role),
                Action("dispose", role),
            )
        )
    for index, frame in enumerate(state.channel):
        candidates.append(Action("deliver", frame.sender.peer, index))
        tampered = Frame(frame.sender, frame.counter, False)
        if frame.authentic and tampered not in state.channel:
            candidates.append(Action("tamper", frame.sender.peer, index))
    for delta in (1, 2, 3, 5, 6):
        if state.now + delta <= MAX_TIME:
            candidates.append(Action("advance", delta=delta))
    return tuple(candidates)


def step(state: State, action: Action) -> State:
    if action.kind == "advance":
        return replace(state, now=state.now + action.delta)

    if action.kind == "derive":
        if (
            state.initiator_phase is Phase.PAIRING
            and state.responder_phase is Phase.PAIRING
        ):
            return replace(
                state,
                initiator_phase=Phase.PENDING,
                responder_phase=Phase.PENDING,
                pending_at=state.now,
            )
        return state

    role = action.role
    assert role is not None
    local_phase = phase(state, role)

    if action.kind == "dispose":
        return with_phase(state, role, Phase.TERMINAL)

    if action.kind in ("confirm_match", "confirm_mismatch"):
        if local_phase is not Phase.PENDING:
            return state
        assert state.pending_at is not None
        if (
            action.kind == "confirm_mismatch"
            or state.now - state.pending_at > CONFIRMATION_WINDOW
        ):
            return with_phase(state, role, Phase.TERMINAL)
        if role is Role.INITIATOR:
            return replace(
                state,
                initiator_phase=Phase.ACTIVE,
                initiator_confirmed_at=state.now,
            )
        return replace(
            state,
            responder_phase=Phase.ACTIVE,
            responder_confirmed_at=state.now,
        )

    if action.kind == "send":
        if local_phase is not Phase.ACTIVE:
            return state
        if is_expired(state, role):
            return with_phase(state, role, Phase.TERMINAL)
        counter = tx_counter(state, role)
        if counter >= MAX_FRAMES:
            return with_phase(state, role, Phase.TERMINAL)
        nonce = (role, counter)
        assert nonce not in state.used_nonces
        sent = with_tx(state, role, counter + 1)
        return replace(
            sent,
            channel=(*sent.channel, Frame(role, counter)),
            used_nonces=sent.used_nonces | {nonce},
        )

    assert action.frame is not None
    frame = state.channel[action.frame]
    if action.kind == "tamper":
        tampered = Frame(frame.sender, frame.counter, False)
        if frame.authentic and tampered not in state.channel:
            return replace(state, channel=(*state.channel, tampered))
        return state

    assert action.kind == "deliver"
    if local_phase is not Phase.ACTIVE:
        return state
    if is_expired(state, role):
        return with_phase(state, role, Phase.TERMINAL)
    expected = rx_counter(state, role)
    if frame.sender is not role.peer or not frame.authentic or frame.counter != expected:
        return state
    received = with_rx(state, role, expected + 1)
    acceptance = (role, frame.sender, frame.counter, state.now)
    return replace(received, accepted=received.accepted | {acceptance})


def invariant(previous: State, current: State, action: Action) -> None:
    assert 0 <= previous.now <= current.now <= MAX_TIME
    assert 0 <= current.initiator_tx <= MAX_FRAMES
    assert 0 <= current.responder_tx <= MAX_FRAMES
    assert 0 <= current.initiator_rx <= current.responder_tx
    assert 0 <= current.responder_rx <= current.initiator_tx
    assert len(current.used_nonces) == current.initiator_tx + current.responder_tx

    for role in Role:
        local_phase = phase(current, role)
        confirmed = confirmed_at(current, role)
        if local_phase is Phase.ACTIVE:
            assert confirmed is not None
        if local_phase in (Phase.PAIRING, Phase.PENDING):
            assert confirmed is None
        if confirmed is not None:
            assert current.pending_at is not None
            assert current.pending_at <= confirmed <= current.now
        if phase(previous, role) is Phase.TERMINAL:
            assert local_phase is Phase.TERMINAL

        accepted = sorted(
            frame_counter
            for receiver, sender, frame_counter, _ in current.accepted
            if receiver is role and sender is role.peer
        )
        assert accepted == list(range(rx_counter(current, role)))
        for receiver, sender, frame_counter, accepted_at in current.accepted:
            if receiver is role:
                assert sender is role.peer
                assert confirmed is not None and confirmed <= accepted_at <= current.now
                assert Frame(sender, frame_counter, True) in current.channel

    for sent_role, counter in current.used_nonces:
        assert counter < tx_counter(current, sent_role)
        assert Frame(sent_role, counter, True) in current.channel

    if action.kind == "deliver" and current.accepted != previous.accepted:
        assert action.role is not None
        assert phase(previous, action.role) is Phase.ACTIVE
        assert not is_expired(previous, action.role)
        assert rx_counter(current, action.role) == rx_counter(previous, action.role) + 1
    elif action.kind != "derive":
        assert current.accepted == previous.accepted


def verify(max_depth: int = 9) -> tuple[int, int, int]:
    initial = State()
    queue = deque([(initial, 0)])
    seen = {initial}
    transitions = 0
    terminal_states = 0
    while queue:
        state, depth = queue.popleft()
        if (
            state.initiator_phase is Phase.TERMINAL
            and state.responder_phase is Phase.TERMINAL
        ):
            terminal_states += 1
        if depth == max_depth:
            continue
        for action in actions(state):
            current = step(state, action)
            invariant(state, current, action)
            transitions += 1
            if current not in seen:
                seen.add(current)
                queue.append((current, depth + 1))
    return len(seen), transitions, terminal_states


if __name__ == "__main__":
    state_count, transition_count, terminal_count = verify()
    print(
        "secure Bluetooth model passed: "
        f"{state_count} states, {transition_count} bounded transitions, "
        f"{terminal_count} terminal states"
    )
