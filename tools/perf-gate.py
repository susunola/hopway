#!/usr/bin/env python3
"""Compare HopWay micro-benchmarks against the committed baseline.

Each scenario has its own gate because they move for different reasons: rule
matching is CPU work on the routing hot path, the relay copy measures the
per-chunk allocation strategy, fake-IP churn measures tunnel bookkeeping, and
the UDP loopback benchmark covers the datagram relay. A single global
percentage would hide a regression in one of them behind noise in another.

Usage:
    tools/perf-gate.py                 # verify, exit 1 on a regression
    tools/perf-gate.py --count 5       # more samples, median is used
    tools/perf-gate.py --update        # rewrite the baseline
"""

import argparse
import json
import os
import re
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "perf-baseline.json")
DEFAULT_TAGS = "with_quic,with_utls,badlinkname,tfogo_checklinkname0"

# (package, benchmark regexp) pairs. Keep this list short: every entry is a
# scenario someone must be able to explain when it regresses.
SCENARIOS = [
    ("./internal/engine", "BenchmarkMatchRuleCounts/100000"),
    ("./internal/wire", "BenchmarkRelayWrappedCopy/pooled"),
    ("./internal/tun", "BenchmarkFakeIPChurn"),
    ("./internal/socks5", "BenchmarkUDPRelayLoopback"),
]

LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([0-9.]+) ns/op")


def run_benchmarks(tags, benchtime, count):
    samples = {}
    for package, pattern in SCENARIOS:
        command = [
            "go", "test", "-tags", tags, "-ldflags=-checklinkname=0",
            "-run", "^$", "-bench", pattern, "-benchtime", benchtime,
            "-count", str(count), package,
        ]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(f"benchmark run failed for {package} {pattern}")
        for line in result.stdout.splitlines():
            match = LINE.match(line.strip())
            if not match:
                continue
            name, ns = match.group(1), float(match.group(2))
            samples.setdefault(name, []).append(ns)
    medians = {}
    for name, values in samples.items():
        if len(values) != count:
            print(f"warning: {name} produced {len(values)}/{count} samples", file=sys.stderr)
        medians[name] = round(statistics.median(values), 1)
    return medians


def load_baseline():
    with open(BASELINE, encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--benchtime", default="100ms")
    parser.add_argument("--tags", default=os.environ.get("HOPWAY_TAGS", DEFAULT_TAGS))
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()

    measured = run_benchmarks(args.tags, args.benchtime, args.count)
    baseline = load_baseline()

    if args.update:
        for name, value in measured.items():
            entry = baseline.setdefault("benchmarks", {}).setdefault(name, {})
            entry["nsPerOp"] = value
        with open(BASELINE, "w", encoding="utf-8") as handle:
            json.dump(baseline, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        print(f"updated {os.path.relpath(BASELINE, ROOT)} with {len(measured)} scenarios")
        return 0

    failed = []
    print(f"{'benchmark':<52}{'baseline':>12}{'measured':>12}{'limit':>10}  result")
    for name, value in sorted(measured.items()):
        entry = baseline.get("benchmarks", {}).get(name)
        if entry is None:
            print(f"{name:<52}{'-':>12}{value:>12.1f}{'-':>10}  no baseline")
            continue
        reference = float(entry["nsPerOp"])
        tolerance = float(entry.get("tolerance", 0.35))
        limit = reference * (1.0 + tolerance)
        verdict = "ok" if value <= limit else "REGRESSION"
        if value > limit:
            failed.append(name)
        print(f"{name:<52}{reference:>12.1f}{value:>12.1f}{limit:>10.1f}  {verdict}")

    if failed:
        print(
            "\nperformance gate failed: " + ", ".join(failed) +
            "\nRe-run with --count 5 to rule out noise. If the change is intended, "
            "run tools/perf-gate.py --update and explain it in the commit message.",
            file=sys.stderr,
        )
        return 1
    print("\nperformance gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
