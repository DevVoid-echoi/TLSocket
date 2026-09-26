import argparse
import asyncio
import random
import ssl
import time


def pct(sorted_vals, p):
    """Tính giá trị bách phân vị (Percentile) từ một danh sách đã sắp xếp.

    Sử dụng phương pháp Hạng gần nhất (Nearest Rank) làm tròn xuống.

    Args:
        sorted_vals (list[float | int]): Danh sách các số đã được sắp xếp tăng dần.
        p (float | int): Giá trị bách phân vị cần tính (từ 0 đến 100).

    Returns:
        float | int: Giá trị tại bách phân vị thứ p, hoặc NaN nếu danh sách rỗng.
    """
    if not sorted_vals:
        return float("nan")
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * p / 100))]

async def connect_login(host, port, ctx, name, sem):
    async with sem:
        t0 = time.perf_counter()
        r, w = await asyncio.open_connection(host, port, ssl=ctx, server_hostname="localhost")
        w.write(f"LOGIN {name} pw123\n".encode())
        await w.drain()
        line = await asyncio.wait_for(r.readline(), timeout=30)
        if not line.startswith(b"OK Connected"):
            raise RuntimeError(f"{name}: login failed: {line!r}")
        return r, w, time.perf_counter() - t0

async def reader(r, latencies, received, closed, idx):
    while True:
        line = await r.readline()
        if not line:
            closed.add(idx)
            return
        i = line.rfind(b": t=")
        if i != -1:
            latencies.append(time.perf_counter_ns() - int(line[i + 4:]))
            received[idx] += 1

async def sender(w, rate, duration):
    await asyncio.sleep(random.random () / rate)
    sent = 0
    start = time.perf_counter()
    nxt = start
    while nxt < start + duration:
        w.write(f"MSG t={time.perf_counter_ns()}\n".encode())
        await w.drain()
        sent += 1
        nxt += 1.0/rate
        delay = nxt - time.perf_counter()
        if delay > 0:
            await asyncio.sleep(delay)
    return sent

async def lag_probe(samples, stop):
    while not stop.is_set():
        t0 = time.perf_counter()
        await asyncio.sleep(0.01)
        samples.append((time.perf_counter() - t0 - 0.01) * 1000)

async def main(a):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(a.cert)
    sem = asyncio.Semaphore(a.login_concurrency)

    t0 = time.perf_counter()
    results = await asyncio.gather(
        *(connect_login(a.host, a.port, ctx, f"user{i}", sem) for i in range(a.clients))
    )
    login_wall = time.perf_counter() - t0
    logins = sorted(x[2] * 1000 for x in results)
    conns = [(r, w) for r, w, _ in results]

    latencies: list[int] = []
    received = [0] * a.clients
    closed: set[int] = set()
    readers = [asyncio.create_task(reader(r, latencies, received, closed, i)) for i, (r, _) in enumerate(conns)]
    await asyncio.sleep(1)

    lag, stop = [], asyncio.Event()
    probe = asyncio.create_task(lag_probe(lag, stop))
    t1 = time.perf_counter()
    counts = await asyncio.gather(*(sender(conns[i][1], a.rate, a.duration) for i in range(a.senders)))
    stop.set()
    await probe
    run_wall = time.perf_counter() - t1
    await asyncio.sleep(2)

    for t in readers:
        t.cancel()
    res = await asyncio.gather(*readers, return_exceptions=True)
    errs = [x for x in res if isinstance(x, Exception)]
    for _, w in conns:
        w.close()

    sent = sum(counts)
    target = a.senders * a.rate * a.duration
    expected = sent * (a.clients - 1)
    delivered = len(latencies)
    lat = sorted(x / 1e6 for x in latencies)
    sl = sorted(lag)
    bad = []
    for i in range(a.clients):
        want = sent - (counts[i] if i<a.senders else 0)
        if received[i] != want:
            bad.append((f"user{i}", received[i], want))

    print(f"clients={a.clients} senders={a.senders} rate={a.rate}/s duration={a.duration}s")
    print(f"login   : wall={login_wall:.1f}s  p50={pct(logins, 50):.0f}ms  p95={pct(logins, 95):.0f}ms")
    print(f"sent    : {sent} ({sent / target:.0%} of target {target:.0f})")
    print(f"delivered: {delivered} / expected {expected}  loss={1 - delivered / max(expected, 1):.2%}")
    print(f"throughput: {delivered / run_wall:.0f} deliveries/s")
    print(f"latency : p50={pct(lat, 50):.1f}ms  p95={pct(lat, 95):.1f}ms  p99={pct(lat, 99):.1f}ms")
    print(f"gen lag : p50={pct(sl, 50):.1f}ms  p99={pct(sl, 99):.1f}ms  max={sl[-1]:.1f}ms")
    print("Client & number of messages missing:", bad[:10] or "None")
    print("Reader found EOF:", sorted(closed) or "None", " | reader error:", errs or "None")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--cert", default="certs/server.crt")
    p.add_argument("--clients", type=int, default=100)
    p.add_argument("--senders", type=int, default=10)
    p.add_argument("--rate", type=float, default=5.0)
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--login-concurrency", type=int, default=20)
    asyncio.run(main(p.parse_args()))
