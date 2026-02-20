import json
import platform
import subprocess
import sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.dirname(os.path.abspath(__file__))


def run_lightning():
    print("=== Running lightning benchmark ===", file=sys.stderr)
    env = os.environ.copy()
    if platform.system() == "Darwin":
        env["RUSTFLAGS"] = "-C link-arg=-Wl,-ld_classic"
    subprocess.run(
        ["cargo", "build", "--release", "-p", "lightning-bench"],
        cwd=REPO_ROOT,
        check=True,
        env=env,
    )
    result = subprocess.run(
        [os.path.join(REPO_ROOT, "target", "release", "lightning-bench")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    print(result.stderr, file=sys.stderr)
    return json.loads(result.stdout)


def run_bittensor():
    print("=== Running bittensor benchmark ===", file=sys.stderr)
    result = subprocess.run(
        [sys.executable, os.path.join(BENCH_DIR, "bittensor_bench.py")],
        capture_output=True,
        text=True,
        cwd=BENCH_DIR,
    )
    print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        print(f"bittensor benchmark failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def fmt(val, unit=""):
    if isinstance(val, float):
        if val >= 1000:
            return f"{val:,.0f}{unit}"
        if val >= 10:
            return f"{val:.1f}{unit}"
        return f"{val:.2f}{unit}"
    if isinstance(val, int):
        return f"{val:,}{unit}"
    return str(val)


def generate_markdown(lightning, bittensor):
    machine = f"{platform.machine()}, {platform.system()} {platform.release()}"
    sizes = ["256B", "1KB", "10KB", "100KB", "1MB"]

    lines = [
        "## Performance",
        "",
        f"Benchmarked on `{machine}`. Echo handler over loopback. Source: [`benchmarks/`](benchmarks/).",
        "",
        "| | bittensor (dendrite/axon) | lightning |",
        "|---|---|---|",
        "| Protocol | HTTP/1.1 | QUIC |",
        "| Serialization | JSON | MessagePack |",
        "| Transport encryption | None | TLS 1.3 |",
        "| Auth model | Per-request | Per-connection |",
        "",
        "| Metric | bittensor | lightning |",
        "|---|---|---|",
    ]

    bt_setup = bittensor["connection_setup_ms"]
    lt_setup = lightning["connection_setup_ms"]
    lines.append(
        f"| Connection setup (p50) | {fmt(bt_setup['p50'])} ms | {fmt(lt_setup['p50'])} ms |"
    )

    for size in sizes:
        if size in bittensor["latency_ms"] and size in lightning["latency_ms"]:
            bt_lat = bittensor["latency_ms"][size]
            lt_lat = lightning["latency_ms"][size]
            lines.append(
                f"| Latency p50 ({size}) | {fmt(bt_lat['p50'])} ms | {fmt(lt_lat['p50'])} ms |"
            )
            lines.append(
                f"| Latency p99 ({size}) | {fmt(bt_lat['p99'])} ms | {fmt(lt_lat['p99'])} ms |"
            )

    for size in sizes:
        if size in bittensor["throughput_rps"] and size in lightning["throughput_rps"]:
            lines.append(
                f"| Throughput ({size}) | {fmt(bittensor['throughput_rps'][size])} req/s | {fmt(lightning['throughput_rps'][size])} req/s |"
            )

    for size in sizes:
        if size in bittensor["wire_bytes"] and size in lightning["wire_bytes"]:
            lines.append(
                f"| Wire size ({size} payload) | {fmt(bittensor['wire_bytes'][size])} bytes | {fmt(lightning['wire_bytes'][size])} bytes |"
            )

    lines.append("")

    detail_lines = [
        "<details>",
        "<summary>Full results (all payload sizes)</summary>",
        "",
        "### Latency (ms)",
        "",
        "| Payload | | bittensor p50 | p95 | p99 | lightning p50 | p95 | p99 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for size in sizes:
        if size in bittensor["latency_ms"] and size in lightning["latency_ms"]:
            bt = bittensor["latency_ms"][size]
            lt = lightning["latency_ms"][size]
            detail_lines.append(
                f"| {size} | | {fmt(bt['p50'])} | {fmt(bt['p95'])} | {fmt(bt['p99'])} | {fmt(lt['p50'])} | {fmt(lt['p95'])} | {fmt(lt['p99'])} |"
            )
    detail_lines.extend(
        [
            "",
            "### Throughput (req/s)",
            "",
            "| Payload | bittensor | lightning |",
            "|---|---|---|",
        ]
    )
    for size in sizes:
        if size in bittensor["throughput_rps"] and size in lightning["throughput_rps"]:
            detail_lines.append(
                f"| {size} | {fmt(bittensor['throughput_rps'][size])} | {fmt(lightning['throughput_rps'][size])} |"
            )
    detail_lines.extend(
        [
            "",
            "### Wire overhead (bytes)",
            "",
            "| Payload | bittensor | lightning |",
            "|---|---|---|",
        ]
    )
    for size in sizes:
        if size in bittensor["wire_bytes"] and size in lightning["wire_bytes"]:
            detail_lines.append(
                f"| {size} | {fmt(bittensor['wire_bytes'][size])} | {fmt(lightning['wire_bytes'][size])} |"
            )
    detail_lines.extend(["", "</details>", ""])

    return "\n".join(lines + detail_lines)


def main():
    lightning = run_lightning()
    bittensor = run_bittensor()

    with open(os.path.join(BENCH_DIR, "results_lightning.json"), "w") as f:
        json.dump(lightning, f, indent=2)
    with open(os.path.join(BENCH_DIR, "results_bittensor.json"), "w") as f:
        json.dump(bittensor, f, indent=2)

    md = generate_markdown(lightning, bittensor)
    print(md)

    with open(os.path.join(BENCH_DIR, "results.md"), "w") as f:
        f.write(md)

    print("\nResults written to benchmarks/results.md", file=sys.stderr)


if __name__ == "__main__":
    main()
