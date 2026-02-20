import asyncio
import base64
import json
import sys
import time
import typing

from bittensor_wallet.mock import get_mock_wallet
from bittensor.core.synapse import Synapse
from bittensor.core.axon import Axon
from bittensor.core.dendrite import Dendrite
from bittensor.core.chain_data import AxonInfo

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


class EchoSynapse(Synapse):
    data: str = ""
    response_data: typing.Optional[str] = None


def forward_fn(synapse: EchoSynapse) -> EchoSynapse:
    synapse.response_data = synapse.data
    return synapse


def make_payload(size: int) -> str:
    return base64.b64encode(b"\x42" * size).decode()


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = round(p / 100.0 * (len(sorted_vals) - 1))
    return sorted_vals[min(idx, len(sorted_vals) - 1)]


def wire_size(synapse: EchoSynapse) -> int:
    body = json.dumps(synapse.model_dump()).encode()
    headers = synapse.to_headers()
    header_bytes = sum(
        len(k.encode()) + len(str(v).encode()) + 4
        for k, v in headers.items()
    )
    return len(body) + header_bytes


def start_axon(wallet, port: int) -> Axon:
    axon = Axon(wallet=wallet, port=port, ip="127.0.0.1", external_ip="127.0.0.1")
    axon.attach(forward_fn=forward_fn)
    axon.start()
    time.sleep(0.5)
    return axon


async def main():
    print("bittensor benchmark", file=sys.stderr)
    wallet = get_mock_wallet()

    print(f"  measuring connection setup ({SETUP_ITERATIONS} iterations)...", file=sys.stderr)
    setup_times = []
    for i in range(SETUP_ITERATIONS):
        port = 19000 + i
        axon = start_axon(wallet, port)
        target = AxonInfo(
            version=1,
            ip="127.0.0.1",
            port=port,
            ip_type=4,
            hotkey=wallet.hotkey.ss58_address,
            coldkey=wallet.coldkeypub.ss58_address,
        )
        start = time.perf_counter()
        async with Dendrite(wallet=wallet) as dendrite:
            resp = await dendrite.forward(
                target,
                synapse=EchoSynapse(data="ping"),
                timeout=30.0,
                deserialize=False,
            )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        setup_times.append(elapsed_ms)
        axon.stop()
        if (i + 1) % 20 == 0:
            print(f"    {i + 1}/{SETUP_ITERATIONS}", file=sys.stderr)

    setup_times.sort()
    connection_setup_ms = {
        "p50": percentile(setup_times, 50.0),
        "p95": percentile(setup_times, 95.0),
        "p99": percentile(setup_times, 99.0),
    }

    port = 19500
    axon = start_axon(wallet, port)
    target = AxonInfo(
        version=1,
        ip="127.0.0.1",
        port=port,
        ip_type=4,
        hotkey=wallet.hotkey.ss58_address,
        coldkey=wallet.coldkeypub.ss58_address,
    )

    latency_ms = {}
    throughput_rps = {}
    wire_bytes = {}

    async with Dendrite(wallet=wallet) as dendrite:
        await dendrite.forward(
            target,
            synapse=EchoSynapse(data="warmup"),
            timeout=30.0,
            deserialize=False,
        )

        for label, size in PAYLOAD_SIZES:
            data_str = make_payload(size)

            synapse = EchoSynapse(data=data_str)
            wire_bytes[label] = wire_size(synapse)

            print(
                f"  measuring latency {label} ({LATENCY_ITERATIONS} iterations)...",
                file=sys.stderr,
            )
            times = []
            for _ in range(LATENCY_ITERATIONS):
                start = time.perf_counter()
                await dendrite.forward(
                    target,
                    synapse=EchoSynapse(data=data_str),
                    timeout=30.0,
                    deserialize=False,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
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
            sem = asyncio.Semaphore(CONCURRENCY)

            async def single_request(d, t, data):
                async with sem:
                    await d.forward(
                        t,
                        synapse=EchoSynapse(data=data),
                        timeout=30.0,
                        deserialize=False,
                    )

            start = time.perf_counter()
            tasks = [
                single_request(dendrite, target, data_str)
                for _ in range(THROUGHPUT_TOTAL)
            ]
            await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start

            throughput_rps[label] = THROUGHPUT_TOTAL / elapsed

    axon.stop()

    results = {
        "connection_setup_ms": connection_setup_ms,
        "latency_ms": latency_ms,
        "throughput_rps": throughput_rps,
        "wire_bytes": wire_bytes,
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
