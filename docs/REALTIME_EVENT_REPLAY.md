# Real-time Event Replay (Command Center)

**Status:** shipped (milestone 1 — WS command center). **Scope:** `/ws/command-center`.

## Why

The Command Center live feed is a `tokio::sync::broadcast` fan-out. Events published while a
socket is disconnected are gone forever. A SOC console that loses its connection for a few
seconds — a laptop sleeping, a Wi-Fi blip, a proxy recycle — must not **silently** miss the
alerts that landed in that window. Replay lets a reconnecting client say *"give me everything
after sequence N"* and resume without a gap.

This complements the backpressure hardening (fail-loud on `RecvError::Lagged`): that stops
in-flight loss on a slow socket; replay recovers loss across a full disconnect.

## Architecture

```
 producers ──stamp(_tid)──▶ telemetry_broadcast_tx ──▶ [ SSE endpoints ] (unchanged)
                                        │
                                        ▼
                              spawn_recorder (single task)
                                        │  assigns monotonic _seq
                                        │  records into EventReplayBuffer (bounded, per-tenant)
                                        ▼
                               cc_sequenced_tx  ──▶ /ws/command-center (live, each frame carries _seq)
                                        ▲
        reconnect: replay_since(tenant, last_event_id) ──┘  (buffered events, tenant-scoped)
```

* **One sequencer, one seq space.** A single `spawn_recorder` task drains the raw telemetry
  broadcast, assigns every event a monotonic `_seq` via `EventReplayBuffer::record`, stores it,
  and re-emits it (with `_seq`) on `cc_sequenced_tx`. Because seq is assigned in exactly one
  place, the seq a **live** client sees is the same seq **replay** resumes from.
* **WS connect** (`handle_ws_command_center`):
  1. subscribe to `cc_sequenced_tx` **first** (so nothing is missed between replay and live),
  2. send the `init` snapshot,
  3. if the client sent `?last_event_id=N`, `replay_since(tenant, N)` and resend the missed
     events (each stamped with its `_seq`),
  4. enter the live loop, **deduping** by seq (`_seq <= last_delivered` already replayed).
* **Client** (`useWeissmanSocket`): records the highest `_seq` it has seen and, on every
  reconnect, appends `?last_event_id=<seq>` to the socket URL.

## Per-tenant isolation

Replay inherits the platform's realtime tenancy model (`http::tenant_stream`):

* every stored payload keeps its `_tid` stamp;
* `replay_since` filters each candidate through `tenant_stream::visible_to`, so **tenant B can
  never replay tenant A's events**; system-tenant (`_tid = 0`) events replay to everyone;
* **fail-closed:** an unstamped payload is never recorded (so it can never be replayed).

Unit tests assert cross-tenant isolation, system-tenant fan-out, and the fail-closed path.

## Gap handling

The buffer is a bounded global ring (default 1024 events). If a client's `last_event_id` is
older than the oldest retained event, continuity cannot be proven, so `replay_since` returns
`gap = true` and the server sends a **resync notice** (`{"type":"resync","kind":"stream_lagged",
"dropped":N}`). The client bumps `resyncSignal`, whose consumers refetch authoritative state
rather than trust a partial replay. Same contract as the backpressure path — one recovery
mechanism for both "fell behind while connected" and "missed too much while disconnected".

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `WEISSMAN_CC_REPLAY_CAPACITY` | `1024` | Max telemetry events retained for replay (global ring). ~1 KiB/event ⇒ ~1 MiB at default. |

Raise it when tenants are bursty or reconnect windows are long (trade memory for fewer gaps);
lower it to cap memory on constrained replicas.

## Observability

| Metric | Type | Meaning |
|---|---|---|
| `weissman_ws_command_center_lagged_events_total` | counter | Events dropped to a slow socket **or** uncovered on reconnect (each increment ⇒ a client was told to resync). |

A rising rate means clients are outrunning the live buffer or reconnecting past the replay
window — see the runbook.

## Runbook — "operators report missing / flickering live events"

1. **Confirm the signal.** Check `weissman_ws_command_center_lagged_events_total` in Grafana
   (Weissman overview). Flat ⇒ not a replay/backpressure issue (look at producers or the DB
   ticker). Rising ⇒ continue.
2. **Bursty tenant vs. long reconnects?**
   - Spikes correlated with big scans ⇒ the live ring (`TELEMETRY_BROADCAST_CAPACITY`, 128) is
     briefly outrun. Clients auto-resync; if noisy, raise replay capacity so reconnects recover
     silently instead of gapping.
   - Spikes correlated with client reconnects (deploys, network) ⇒ raise
     `WEISSMAN_CC_REPLAY_CAPACITY` so the replay window covers the reconnect gap.
3. **Tune.** Set `WEISSMAN_CC_REPLAY_CAPACITY` to cover `peak_events_per_second ×
   worst_reconnect_seconds`. Restart the replica(s) to apply (buffer is process-local).
4. **Verify a client actually resumes.** In the browser console, `useWeissmanSocket` reconnects
   to `…/ws/command-center?last_event_id=<n>`; after a forced disconnect the missed events
   should arrive before new live ones, with no `resyncSignal` bump (bump ⇒ still gapping ⇒ go
   to step 3).

## Limitations & follow-ups

* **Process-local.** The buffer lives in each replica. A client that reconnects to a *different*
  replica (behind a load balancer without sticky sessions) has no shared history there and will
  full-resync. Durable cross-replica replay (Redis Streams `XADD`/`XRANGE`) is the planned
  follow-up; the `EventReplayBuffer` API is storage-agnostic to allow the swap.
* **WS only.** SSE endpoints (`/api/telemetry/stream`) still stream live-only. Native SSE
  `Last-Event-ID` replay can reuse the same buffer in a follow-up.
