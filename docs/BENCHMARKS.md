# Benchmarks

**Status: partial.** This document currently covers three load points (250, 500 and 1000
clients) for the thread-per-client server. More load levels and an asyncio comparison are planned (see
[Planned work](#planned-work)). Numbers are from a single laptop and should be read as a
baseline for comparison, not as a capacity claim.

## Methodology

- **Machine:** Apple M1 (8 cores), 8 GB RAM, macOS 27.0, Python 3.12.4, argon2-cffi 25.1.0.
  Server and load generator run on the **same machine** over loopback, with TLS enabled.
- **Code under test:** commit `876fb08` (thread-per-client server). The N = 500 and the first
  N = 1000 run (session A) were made at `e1ed466` and `c35410a`, which differ from `876fb08`
  only in this document. The second N = 1000 run (session B) was made at `aba21b0` with the
  generator lag probe from `d6dea2c`; the server code is unchanged.
- **Tool:** `benchmarks/loadtest.py` — an asyncio client that logs in N users, then has S of
  them publish R messages/s for D seconds while all N listen. Each message carries a
  timestamp, so every receiver measures end-to-end latency. Since `d6dea2c` it also measures
  how late its own event loop wakes up during the send phase ("generator lag"), to show how much
  of the measured latency the single-process generator itself can account for.
- **Scenario:** N clients (250, 500 and 1000 so far), S = 10 senders, R = 5 msg/s, D = 30 s.
  The server broadcasts each message to every other client, so the offered load is
  `S × R × (N − 1)`: 12,450 deliveries/s at N = 250, 24,950 at N = 500 and 49,950 at N = 1000.
- **Runs:** one 10 s warm-up (discarded), then three measured runs; the table reports the
  median of the three. A fresh server process is started for each load level. N = 1000 was
  measured in two separate sessions (A and B); results differ between sessions (see
  Observations), so different server variants must only be compared within one session.
- **Server resources:** sampled with `top -pid <server> -stats pid,cpu,mem,th -s 2`. The first
  sample is discarded (it is a cumulative average). "Steady" values are the median of the
  samples taken while all N clients were connected; "login peak" is the maximum over the run.
  Because samples are 2 s apart, the login peak is a lower bound and varies between sessions.
- **Abuse limits relaxed:** all clients share `127.0.0.1`, so the per-IP connection cap and the
  per-user message rate limit were raised via `TLSOCKET_MAX_CONN_PER_IP` and
  `TLSOCKET_MAX_MSGS_PER_WINDOW`. Logins run 20 at a time (`--login-concurrency 20`).
- **Users:** pre-seeded with `benchmarks/seed_users.py`. Every login still performs a real
  Argon2id verification.

## Results: thread-per-client server

| N | Offered load (deliveries/s) | Login wall | Login p95 | Delivered (deliveries/s) | Loss | Latency p50 / p95 / p99 | Generator lag p99 | CPU (steady) | RSS (steady / login peak, sampled) | Threads |
|---|---|---|---|---|---|---|---|---|---|---|
| 250 | 12,450 | 7.0 s | 766 ms | 12,371 | 0.00% | 4.9 / 11.0 / 11.6 ms | not measured | 13.6% of one core | 54 MB / 1,105 MB | 253 |
| 500 | 24,950 | 14.5 s | 789 ms | 24,798 | 0.00% | 5.7 / 8.8 / 10.1 ms | not measured | 14.7% of one core | 75 MB / 502 MB | 503 |
| 1000 (session A) | 49,950 | 33.2 s | 998 ms | 49,667 | 0.00% | 10.4 / 24.3 / 34.5 ms | not measured | 24.4% of one core | 116 MB / 1,182 MB | 1003 |
| 1000 (session B) | 49,950 | 30.0 s | 858 ms | 49,624 | 0.00% | 14.4 / 32.9 / 41.5 ms | 16.5 ms | 30.1% of one core | 117 MB / 1,008 MB | 1003 |

In every measured run all expected messages were delivered (373,500 of 373,500 at N = 250;
753,490 of 753,490 at N = 500; 1,508,490 of 1,508,490 at N = 1000 in session A and
1,498,500 of 1,498,500 in session B) and no client was dropped.

The N = 1000 rows come with a caveat: in session B the generator's own event loop woke up
16.5 ms late at p99 (p50 1.1 ms, max 21.8 ms), about 40% of the p99 latency. The generator kept
up (sent 100% of target, no loss), but its stalls contribute to the tail, so N = 1000 latency
should be read as an upper bound on the server's own latency (see [Limitations](#limitations)).

## Observations

- **The server is not saturated at these loads.** Offered load doubled twice (about 12.4k, 24.8k
  and 49.7k deliveries/s) while steady CPU rose only from 13.6% to 14.7% to 24.4–30.1% of one
  core and p99 latency (median of three runs) went from 11.6 to 10.1 to 34.5–41.5 ms. CPU grew
  more slowly than load; the cause has not been investigated, so no per-delivery CPU cost is
  claimed.
- **Latency starts to rise at N = 1000** (p50 5.7 ms at N = 500 to 10.4–14.4 ms, p99 10.1 to
  34.5–41.5 ms), but about 40% of the p99 is explained by generator stalls (session B), so this
  is not yet evidence of the server's knee. The knee has not been located.
- **Results vary between sessions.** Two N = 1000 sessions with identical code and commands
  differed by about 6 points of steady CPU (24.4% vs 30.1%) and 7 ms of p99 latency (34.5 vs
  41.5 ms). Only comparisons made within a single session are meaningful.
- **Login, not relaying, dominates CPU and memory peaks.** Argon2id verification runs in
  parallel across cores: CPU peaked at roughly 800–870% during the login burst, and RSS at
  0.5–1.2 GB (502 MB and 791 MB in two N = 500 sessions, 1,105 MB at N = 250, 1,182 MB and
  1,008 MB in the two N = 1000 sessions), then dropped to the steady values. The RSS peaks are
  sampling-dependent, so treat them as lower bounds.
- **Thread count is not the memory cost here.** 253, 503 and 1003 threads use ~54, 75 and
  116–117 MB resident memory, i.e. roughly 82–84 KB per additional connection (derived from the
  250 to 500 and 500 to 1000 intervals). Per-thread stacks are reserved address space, not
  resident memory, which qualifies the "~8 MB per thread" figure in [ADR-001](DECISIONS.md).

## A bug found by the load test

At ~250 concurrent logins the first version of this benchmark intermittently lost one client
per run (2 of 3 runs, ~0.4% of deliveries), and one run crashed on the client with
`ssl.SSLError: DECRYPTION_FAILED_OR_BAD_RECORD_MAC`. Two problems in the server's login path:

1. The `OK Connected` reply was written directly to the socket, outside `_send_lock`, while
   other threads broadcast "joined the chat" to the same TLS connection. Concurrent writes on
   one TLS connection corrupted a record, or made a broadcaster treat the new client as dead
   and drop it.
2. The client was added to the registry *before* `OK` was sent, so it could receive a
   "joined" broadcast ahead of `OK Connected`.

Fixed in `876fb08` by sending `OK` through `registry.send()` first, then registering the
client. Three runs after the fix: 0.00% loss each. Other writes to client sockets (error
replies, admin command responses) still bypass the lock; they are lower-risk but share the
same class of bug.

## Limitations

- Single machine, loopback: the load generator and the server compete for CPU. At higher
  load the generator (one Python process) may saturate before the server does.
- `log_event` writes log files synchronously, so logging cost is part of the server's cost.
- Login time is dominated by Argon2id and is reported separately from relay performance.
- The load generator is a single Python process. At N = 1000 (session B) it was not saturated
  (sent 100% of target, event-loop lag p50 1.1 ms), but its stalls (p99 16.5 ms, max 21.8 ms)
  are about 40% of the measured p99 latency, so N = 1000 latency is an upper bound on the
  server's own latency. "Sent % of target" alone cannot detect this, because the send loop
  catches up after any delay. Generator lag was not measured at N = 250 and N = 500; latency was
  flat between them, which argues against a large effect there. A lighter or multi-process
  generator would be needed for clean server-side latency at high N.
- Three load points only; no confidence intervals beyond the three runs per point.

## Reproducing

```bash
pip install -e ".[dev]"
./scripts/gen_certs.sh                     # if certs/ does not exist
mkdir -p bench_data bench_logs bench_results
python benchmarks/seed_users.py 1000
ulimit -n 10240                            # in every terminal used below

# terminal 1: server
TLSOCKET_DATA_DIR=bench_data TLSOCKET_LOG_DIR=bench_logs \
TLSOCKET_MAX_CONN_PER_IP=100000 TLSOCKET_MAX_MSGS_PER_WINDOW=1000000 \
tlsocket-server < /dev/null > bench_logs/server.out 2>&1

# terminal 2: load generator
python benchmarks/loadtest.py --clients 250 --senders 10 --rate 5 --duration 30

# terminal 3 (optional): server CPU / memory / threads
PID=$(pgrep -f "bin/tlsocket-server" | head -1)
top -pid $PID -stats pid,cpu,mem,th -l 0 -s 2 | grep --line-buffered -E '^[0-9]+ '
```

Wait a few seconds between runs so the server can clean up the previous sessions, and restart
the server between load levels so memory numbers start from a clean process.

## Planned work

- Run every comparison within a single session, and report generator lag for each run, so the
  generator's contribution can be judged for every server variant.
- Measure N = 50 and 100, and a fixed-N sweep over the send rate to find the maximum
  sustainable message rate.
- Add an asyncio server variant and compare it with this baseline under identical methodology
  (same machine, TLS, limits and load generator), then update ADR-001 with measured numbers.
- If the load generator saturates, split it across several processes before trusting results
  at higher N.
- Repeat the full comparison on a second machine, always running both server variants in the
  same session.
