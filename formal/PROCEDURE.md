# Formal-methods procedure: vault session lifetime

The desktop authenticator keeps decrypted vault material in memory only while the session state machine is unlocked. Its two deadlines serve different purposes: 90 seconds of inactivity limits unattended exposure, while the five-minute hard cap bounds total exposure even under continuous activity or repeated factor-gated extensions.

## Claim boundary and assumptions

`formal/session_model.py` exhausts threshold values, activity boundaries, factor outcomes, and a continuous-activity witness. It is a finite abstraction of `src/session.rs`; headless Rust tests remain the production refinement gate. The model makes two environment assumptions explicit: supplied time is monotonic, and the GUI polls before dispatching activity that arrives after a deadline. Without a poll, the library has no background thread that can lock itself.

## Model-to-code correspondence

| Model concept | Production surface |
|---|---|
| locked/unlocked state and timer clearing | `SessionState`, `Session::lock`, `Session::unlock` |
| genuine versus app-driven activity | `Interaction::is_user_activity`, `note_interaction` |
| idle and hard-cap deadlines | `IDLE_TIMEOUT`, `MAX_SESSION`, `Session::poll` |
| factor-gated idle reset | `Session::try_extend`, `PolicyEngine`, `Gate::Extend` |
| visible countdown | `lock_seconds_remaining` |

## Required invariants

1. Locking clears both timestamps.
2. A poll at 90 seconds since genuine activity locks the vault.
3. A poll at five minutes since unlock locks regardless of activity.
4. Timer ticks, extension requests, and lock requests cannot masquerade as activity.
5. Successful extension changes only the idle deadline, never the hard-cap origin.
6. Extension at or after the hard cap fails closed and locks immediately.

## Change procedure

1. Classify every new UI event as genuine activity or non-activity in the library enum; never reset timers ad hoc in GUI code.
2. Update the Python domain and Rust table tests together when adding an interaction or changing a threshold.
3. Document monotonicity and suspend/resume semantics for any new clock source.
4. Poll deadlines before accepting an event that could reset inactivity.
5. Run:

   ```bash
   python3 formal/session_model.py
   printf '%s\n' '{"op":"replay","events":[{"op":"unlock"},{"op":"advance","seconds":90},{"op":"poll"}]}' \
     | python3 formal/session_model.py --json-stdin
   cargo test --no-default-features
   ```

6. Preserve the smallest counterexample and test `N-1`, `N`, and `N+1` at each deadline.
7. Review zeroization separately: this state machine tells callers when to drop keys, but the crypto/vault layer must prove that lock handling actually zeroizes them.

## JSON-lines adapter

`python3 formal/session_model.py --json-stdin` accepts explicit `unlock`, `advance`, `interaction`, `extend`, `poll`, and `lock` events and emits the complete trace. Production refinement stays in Rust.

## Explicitly out of scope

This model does not prove Argon2/XChaCha20 security, OS keychain behavior, GUI callback ordering beyond the stated assumption, process-memory resistance, or biometric/passkey correctness.
