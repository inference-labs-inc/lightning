import json
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from btlightning import Lightning, LightningServer

MINER_SEED = bytes([1] * 32)
VALIDATOR_SEED = bytes([2] * 32)
MINER_HOTKEY = "5CcyqxXnJucaCnQQvvUg5EPzj1uoNAxACZvzArHw5aVDvgNH"
VALIDATOR_HOTKEY = "5CfCr47V5Dte6bwxNBE8K9oNnQd9fiay6aDEEkgYtFv7w4Fq"

LATENCY_ITERATIONS = 1000
SETUP_ITERATIONS = 100
CONCURRENCY = 32
THROUGHPUT_TOTAL = 10000
PAYLOAD_SIZES = [
    ("256B", 256),
    ("1KB", 1024),
    ("10KB", 10240),
    ("100KB", 102400),
    ("1MB", 1048576),
]


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = round(p / 100.0 * (len(sorted_vals) - 1))
    return sorted_vals[min(idx, len(sorted_vals) - 1)]


def make_payload(size: int) -> dict:
    return {"payload": b"\x42" * size}


def start_server(port: int) -> LightningServer:
    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=port)
    server.set_miner_keypair(MINER_SEED)
    server.register_synapse_handler("echo", lambda data: data)
    server.start()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    return server


def make_client(port: int) -> tuple:
    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    client.set_validator_keypair(VALIDATOR_SEED)
    axon = {"hotkey": MINER_HOTKEY, "ip": "127.0.0.1", "port": port}
    client.initialize_connections([axon])
    return client, axon


def main():
    print("lightning-py benchmark", file=sys.stderr)

    print(f"  measuring connection setup ({SETUP_ITERATIONS} iterations)...", file=sys.stderr)
    setup_times = []
    for i in range(SETUP_ITERATIONS):
        port = 20000 + i
        server = start_server(port)
        start = time.perf_counter()
        client, axon = make_client(port)
        resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"ping": True}})
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert resp["success"], resp.get("error", "unknown error")
        setup_times.append(elapsed_ms)
        client.close()
        server.stop()
        if (i + 1) % 20 == 0:
            print(f"    {i + 1}/{SETUP_ITERATIONS}", file=sys.stderr)

    setup_times.sort()
    connection_setup_ms = {
        "p50": percentile(setup_times, 50.0),
        "p95": percentile(setup_times, 95.0),
        "p99": percentile(setup_times, 99.0),
    }

    port = 20500
    server = start_server(port)
    client, axon = make_client(port)

    resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"warmup": True}})
    assert resp["success"]

    latency_ms = {}
    throughput_rps = {}

    for label, size in PAYLOAD_SIZES:
        data = make_payload(size)
        request = {"synapse_type": "echo", "data": data}

        print(
            f"  measuring latency {label} ({LATENCY_ITERATIONS} iterations)...",
            file=sys.stderr,
        )
        times = []
        for _ in range(LATENCY_ITERATIONS):
            start = time.perf_counter()
            resp = client.query_axon(axon, request)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            assert resp["success"], resp.get("error", "unknown error")
            times.append(elapsed_ms)

        times.sort()
        latency_ms[label] = {
            "p50": percentile(times, 50.0),
            "p95": percentile(times, 95.0),
            "p99": percentile(times, 99.0),
        }

        print(
            f"  measuring throughput {label} ({THROUGHPUT_TOTAL} requests, {CONCURRENCY} concurrent)...",
            file=sys.stderr,
        )

        def single_request(r=request):
            resp = client.query_axon(axon, r)
            assert resp["success"], resp.get("error", "unknown error")

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futures = [pool.submit(single_request) for _ in range(THROUGHPUT_TOTAL)]
            for f in as_completed(futures):
                f.result()
        elapsed = time.perf_counter() - start

        throughput_rps[label] = THROUGHPUT_TOTAL / elapsed

    client.close()
    server.stop()

    results = {
        "connection_setup_ms": connection_setup_ms,
        "latency_ms": latency_ms,
        "throughput_rps": throughput_rps,
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
