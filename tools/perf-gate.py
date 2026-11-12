#!/usr/bin/env python3
"""Compare HopWay micro-benchmarks against the committed baseline.

Each scenario has its own gate because they move for different reasons: rule
matching is CPU work on the routing hot path, the relay copy measures the
per-chunk allocation strategy, fake-IP churn measures tunnel bookkeeping, and
the UDP loopback benchmark covers the datagram relay. A single global
percentage would hide a regression in one of them behind noise in another.

A result that lands close to its limit is re-measured before the gate fails:
short benchmarks jitter, and the report keeps the observed range so a reader
can tell a real step from one noisy run.

Usage:
    tools/perf-gate.py                 # verify, exit 1 on a regression
    tools/perf-gate.py --count 5       # more samples per round
    tools/perf-gate.py --retry 2       # re-measure a borderline scenario twice
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
# Re-measure when the median is this close to the limit: a gate should only
# fail on a repeatable step, not on one noisy run.
BORDERLINE = 0.10


def run_scenario(package, pattern, tags, benchtime, count):
    """Run one scenario; return {benchmark name: [ns/op, ...]}."""
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
    samples = {}
    for line in result.stdout.splitlines():
        match = LINE.match(line.strip())
        if match:
            name, ns = match.group(1), float(match.group(2))
            samples.setdefault(name, []).append(ns)
    return samples


def merge(target, source):
    for name, values in source.items():
        target.setdefault(name, []).extend(values)


def scenario_for(name):
    for package, pattern in SCENARIOS:
        if pattern in name or name.startswith(pattern.split("/")[0]):
            return package, pattern
    return None


def load_baseline():
    with open(BASELINE, encoding="utf-8") as handle:
        return json.load(handle)


def limits(baseline, name):
    entry = baseline.get("benchmarks", {}).get(name)
    if entry is None:
        return None, None
    reference = float(entry["nsPerOp"])
    tolerance = float(entry.get("tolerance", 0.35))
    return reference, reference * (1.0 + tolerance)


def report(samples, baseline):
    failed = []
    print(f"{'benchmark':<52}{'baseline':>10}{'median':>10}{'range':>17}{'limit':>10}  result")
    for name in sorted(samples):
        values = samples[name]
        median = statistics.median(values)
        reference, limit = limits(baseline, name)
        low, high = min(values), max(values)
        spread = f"{low:.0f}..{high:.0f}"
        if reference is None:
            print(f"{name:<52}{'-':>10}{median:>10.1f}{spread:>17}{'-':>10}  no baseline")
            continue
        verdict = "ok" if median <= limit else "REGRESSION"
        if median > limit:
            failed.append(name)
        print(f"{name:<52}{reference:>10.1f}{median:>10.1f}{spread:>17}{limit:>10.1f}  {verdict}")
    return failed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--retry", type=int, default=1, help="extra rounds for a borderline scenario")
    parser.add_argument("--benchtime", default="100ms")
    parser.add_argument("--tags", default=os.environ.get("HOPWAY_TAGS", DEFAULT_TAGS))
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()

    samples = {}
    for package, pattern in SCENARIOS:
        merge(samples, run_scenario(package, pattern, args.tags, args.benchtime, args.count))

    baseline = load_baseline()
    if args.update:
        for name, values in samples.items():
            entry = baseline.setdefault("benchmarks", {}).setdefault(name, {})
            entry["nsPerOp"] = round(statistics.median(values), 1)
        with open(BASELINE, "w", encoding="utf-8") as handle:
            json.dump(baseline, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        print(f"updated {os.path.relpath(BASELINE, ROOT)} with {len(samples)} scenarios")
        return 0

    # Re-measure borderline scenarios before deciding. This keeps a noisy
    # first round from failing the gate and makes the reported range useful.
    retried = set()
    for _ in range(max(args.retry, 0)):
        pending = []
        for name, values in samples.items():
            reference, limit = limits(baseline, name)
            if reference is None or name in retried:
                continue
            if statistics.median(values) > limit * (1.0 - BORDERLINE):
                pending.append(name)
        if not pending:
            break
        for name in pending:
            scenario = scenario_for(name)
            if scenario is None:
                continue
            package, pattern = scenario
            print(f"re-measuring {name} (close to its limit)", file=sys.stderr)
            merge(samples, run_scenario(package, pattern, args.tags, args.benchtime, args.count))
            retried.add(name)

    failed = report(samples, baseline)
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
