"""Repeatable local hashing measurements; no timing thresholds or transfer claims."""

import argparse
import base64
import hashlib
import importlib.metadata
import json
import math
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from itertools import pairwise
from pathlib import Path

from quickxorhash_native import FileHashAccumulator, calculate_file_hashes

ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
CASES = (
    "update",
    "update-copy",
    "file",
    "incremental",
    "resume",
    "replay",
    "checkpoint",
    "calls",
    "update-threaded",
    "file-threaded",
)


def verify_vectors():
    count = 0
    for line in (
        (ROOT / "tests/fixtures/quickxorhash_vectors.tsv").read_text().splitlines()
    ):
        if line.startswith("#"):
            continue
        encoded, expected = line.split("\t")
        payload = base64.b64decode(encoded)
        accumulator = FileHashAccumulator()
        accumulator.update(payload)
        metadata = accumulator.finalise()
        assert metadata == {
            "size": len(payload),
            "sha1_hash": hashlib.sha1(payload).hexdigest(),
            "quick_xor_hash": expected,
        }
        count += 1
    return count


def rss_bytes():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == "darwin" else value * 1024


def stream(path, accumulator, chunk_size, start=0, stop=None):
    calls = 0
    total = 0
    with path.open("rb") as source:
        source.seek(start)
        while stop is None or total < stop:
            length = chunk_size if stop is None else min(chunk_size, stop - total)
            chunk = source.read(length)
            calls += 1
            if not chunk:
                break
            total += len(chunk)
            accumulator.update(chunk)
    return calls, total


def sample(case, path, chunk_size):
    # Validate/pre-read outside timing: the cache condition is deliberately warm.
    with path.open("rb") as source:
        expected_sha1 = hashlib.file_digest(source, "sha1").hexdigest()
    expected = calculate_file_hashes(str(path), buffer_size=chunk_size)
    assert expected["sha1_hash"] == expected_sha1
    size = path.stat().st_size
    prefix = size // 2
    accumulator = FileHashAccumulator()
    prepared = None
    payload = None
    if case in ("resume", "checkpoint"):
        stream(path, accumulator, chunk_size, stop=prefix)
        prepared = accumulator.snapshot()
        accumulator = FileHashAccumulator()
        if case == "checkpoint":
            expected = calculate_file_hashes(
                str(path), stop_after=prefix, buffer_size=chunk_size
            )
    if case in ("update", "update-copy", "update-threaded"):
        payload = path.read_bytes()
        if case == "update-copy":
            payload = bytearray(payload)
    if case == "calls":
        payload = bytes(range(256)) * math.ceil(chunk_size / 256)
        payload = payload[:chunk_size]
        tail = payload[: size % chunk_size]
    else:
        tail = None

    stopped = threading.Event()
    ready = threading.Event()
    ticks = []

    def heartbeat():
        ticks.append(time.perf_counter())
        ready.set()
        while not stopped.wait(0.001):
            ticks.append(time.perf_counter())

    threaded = case.endswith("-threaded")
    if threaded:
        thread = threading.Thread(target=heartbeat)
        thread.start()
        ready.wait()
    rss_before = rss_bytes()
    cpu_start = time.process_time()
    started = time.perf_counter()
    read_calls = None
    read_bytes = None
    update_calls = None
    operations = 1
    if case in ("update", "update-copy", "update-threaded"):
        accumulator.update(payload)
        metadata = accumulator.finalise()
        update_calls = 1
    elif case in ("file", "file-threaded"):
        metadata = calculate_file_hashes(str(path), buffer_size=chunk_size)
    elif case == "incremental":
        read_calls, read_bytes = stream(path, accumulator, chunk_size)
        metadata = accumulator.finalise()
    elif case == "replay":
        first_calls, first_bytes = stream(path, accumulator, chunk_size, stop=prefix)
        # Model reconstruction of an interrupted run's prefix, then continuation.
        read_calls, read_bytes = stream(path, accumulator, chunk_size, start=prefix)
        read_calls += first_calls
        read_bytes += first_bytes
        metadata = accumulator.finalise()
    elif case == "resume":
        accumulator = FileHashAccumulator.restore(prepared)
        read_calls, read_bytes = stream(path, accumulator, chunk_size, start=prefix)
        metadata = accumulator.finalise()
    elif case == "checkpoint":
        operations = 2000
        for _ in range(operations):
            accumulator = FileHashAccumulator.restore(prepared)
            prepared = accumulator.snapshot()
        metadata = accumulator.finalise()
    else:
        update_calls = size // chunk_size + bool(tail)
        for _ in range(size // chunk_size):
            accumulator.update(payload)
        if tail:
            accumulator.update(tail)
        metadata = accumulator.finalise()
    ended = time.perf_counter()
    cpu = time.process_time() - cpu_start
    peak_rss = rss_bytes()
    if threaded:
        stopped.set()
        thread.join()
    assert metadata == expected, (case, metadata, expected)
    active_ticks = [tick for tick in ticks if started < tick < ended]
    boundaries = [started, *active_ticks, ended]
    return {
        "case": case,
        "size": size,
        "chunk_size": chunk_size,
        "elapsed_seconds": ended - started,
        "cpu_seconds": cpu,
        "peak_rss_bytes": peak_rss,
        "peak_rss_growth_bytes": peak_rss - rss_before,
        "python_read_calls": read_calls,
        "python_bytes_read": read_bytes,
        "update_calls": update_calls,
        "operations": operations,
        "prefix_bytes": prefix if case in ("resume", "replay", "checkpoint") else 0,
        "heartbeat_ticks_during_call": len(active_ticks),
        "heartbeat_max_gap_seconds": max(b - a for a, b in pairwise(boundaries)),
        "metadata": metadata,
    }


def command_version(command):
    try:
        return subprocess.check_output(
            command, text=True, stderr=subprocess.STDOUT
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        return str(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes-mib", default="1,128")
    parser.add_argument("--chunks-kib", default="1,64,256,1024,5120")
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build-profile", default="unspecified")
    parser.add_argument("--sample", choices=CASES, help=argparse.SUPPRESS)
    parser.add_argument("--path", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--chunk-size", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.sample:
        print(json.dumps(sample(args.sample, args.path, args.chunk_size)))
        return
    sizes = [int(value) * MIB for value in args.sizes_mib.split(",")]
    chunks = [int(value) * 1024 for value in args.chunks_kib.split(",")]
    cases = args.cases.split(",")
    if min(*sizes, *chunks, args.repeats) <= 0 or set(cases) - set(CASES):
        parser.error(
            "sizes, chunks and repeats must be positive; cases must be recognised"
        )
    golden_vectors = verify_vectors()
    samples = []
    with tempfile.TemporaryDirectory(prefix="native-hash-bench-") as temporary:
        for size in sizes:
            path = Path(temporary) / f"payload-{size}.bin"
            block = bytes(range(256)) * 4096
            with path.open("wb") as destination:
                for _ in range(size // len(block)):
                    destination.write(block)
            for case in cases:
                buffers = (
                    chunks
                    if case not in ("update", "update-copy", "update-threaded")
                    else [chunks[0]]
                )
                for chunk in buffers:
                    for repeat in range(args.repeats):
                        result = subprocess.run(
                            [
                                sys.executable,
                                str(Path(__file__).resolve()),
                                "--sample",
                                case,
                                "--path",
                                str(path),
                                "--chunk-size",
                                str(chunk),
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        item = json.loads(result.stdout)
                        item["repeat"] = repeat
                        samples.append(item)
                    print(
                        f"measured {case}: {size} bytes, {chunk} byte chunks",
                        file=sys.stderr,
                    )
    groups = []
    for key in dict.fromkeys(
        (item["case"], item["size"], item["chunk_size"]) for item in samples
    ):
        rows = [
            item
            for item in samples
            if (item["case"], item["size"], item["chunk_size"]) == key
        ]
        seconds = [item["elapsed_seconds"] for item in rows]
        groups.append(
            {
                "case": key[0],
                "size": key[1],
                "chunk_size": key[2],
                "median_seconds": statistics.median(seconds),
                "min_seconds": min(seconds),
                "max_seconds": max(seconds),
                "stdev_seconds": statistics.stdev(seconds) if len(seconds) > 1 else 0,
            }
        )
    import quickxorhash_native

    extension = next(Path(quickxorhash_native.__file__).parent.glob("*.so"))
    report = {
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu": command_version(["sysctl", "-n", "machdep.cpu.brand_string"]),
            "python": sys.version,
            "executable": sys.executable,
            "gil_enabled": sys._is_gil_enabled(),
            "rustc": command_version(["rustc", "--version"]),
            "cargo": command_version(["cargo", "--version"]),
            "maturin": importlib.metadata.version("maturin"),
            "build_profile": args.build_profile,
            "extension": str(extension),
            "extension_sha256": hashlib.sha256(extension.read_bytes()).hexdigest(),
        },
        "conditions": {
            "cache": "warm: full pre-read and native correctness pass before each sample; no cold-cache claim",
            "timed_scope": "workload plus finalise; excludes payload preparation, prefix snapshot preparation and validation",
            "rss": "isolated-process total high-water RSS and growth; includes setup; not an allocation count",
            "reads": "observed Python read calls include EOF; native read syscall counts unavailable",
            "checkpoint": "2000 snapshot/restore pairs; metadata is the prepared half-file prefix",
            "concurrency": "threaded cases use a 1ms Python heartbeat; scheduler-dependent, no pass threshold",
            "transfer": "local hashing only; no network or upload throughput measured",
        },
        "golden_vectors_checked": golden_vectors,
        "groups": groups,
        "samples": samples,
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
