"""Public-interface concurrency checks; subprocesses bound deadlock failures."""

import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from quickxorhash_native import FileHashAccumulator, calculate_file_hashes


@pytest.mark.skipif(not sys._is_gil_enabled(), reason="GIL-enabled contract")
@pytest.mark.parametrize("kind", ["bytes", "bytearray", "memoryview"])
def test_update_allows_python_progress_and_preserves_owned_input(kind):
    result = subprocess.run(
        [sys.executable, __file__, "update", kind],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX file-read seam")
def test_file_hashing_allows_python_fifo_producer_progress():
    try:
        result = subprocess.run(
            [sys.executable, __file__, "fifo"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("Python FIFO producer could not run while native file read waited")
    assert result.returncode == 0, result.stdout + result.stderr


def test_file_errors_and_prefix_contract_remain_stable(tmp_path):
    with pytest.raises(OSError):
        calculate_file_hashes(str(tmp_path / "missing"))
    with pytest.raises(OSError):
        calculate_file_hashes(str(tmp_path))
    path = tmp_path / "payload"
    path.write_bytes(b"prefix and suffix")
    with pytest.raises(OSError, match="buffer_size must be greater than zero"):
        calculate_file_hashes(str(path), buffer_size=0)
    for size in (0, 6, 100):
        expected = FileHashAccumulator()
        expected.update(path.read_bytes()[:size])
        assert (
            calculate_file_hashes(str(path), stop_after=size, buffer_size=3)
            == expected.finalise()
        )


def verify_update(kind):
    original = b"\x5a" * (128 * 1024 * 1024)
    reference = FileHashAccumulator()
    reference.update(original)
    expected = reference.finalise()
    expected_sha1 = hashlib.sha1(original).hexdigest()
    assert expected["sha1_hash"] == expected_sha1
    source = original if kind == "bytes" else bytearray(original)
    chunk = memoryview(source) if kind == "memoryview" else source
    accumulator = FileHashAccumulator()
    starting = threading.Event()
    finished = threading.Event()
    errors = []

    def update():
        starting.set()
        try:
            accumulator.update(chunk)
        except BaseException as error:
            errors.append(error)
        finally:
            finished.set()

    worker = threading.Thread(target=update)
    worker.start()
    assert starting.wait(10)
    rejected = set()
    changed = False
    while not finished.is_set():
        for name, operation in (
            ("update", lambda: accumulator.update(b"")),
            ("finalise", accumulator.finalise),
            ("snapshot", accumulator.snapshot),
        ):
            try:
                operation()
            except RuntimeError as error:
                assert "borrow" in str(error).lower(), str(error)
                rejected.add(name)
        if rejected and kind != "bytes" and not changed:
            source[0] = 0
            source[-1] = 0
            if kind == "bytearray":
                source.extend(b"resized after native input copy")
            changed = True
        time.sleep(0.0001)
    worker.join(10)
    assert not worker.is_alive()
    assert not errors, errors
    assert rejected == {"update", "finalise", "snapshot"}, rejected
    assert accumulator.finalise() == expected
    # Rejected overlap must not poison the accumulator or persisted checkpoint.
    restored = FileHashAccumulator.restore(accumulator.snapshot())
    for item in (accumulator, restored, reference):
        item.update(b"suffix")
    assert accumulator.finalise() == restored.finalise() == reference.finalise()


def verify_fifo():
    payload = b"frappe checkpoint prefix" * 257
    expected = FileHashAccumulator()
    expected.update(payload)
    with tempfile.TemporaryDirectory(prefix="native-fifo-") as temporary:
        fifo = Path(temporary) / "input"
        os.mkfifo(fifo)
        results = []
        errors = []
        started = threading.Event()

        def read():
            started.set()
            try:
                results.append(calculate_file_hashes(str(fifo), buffer_size=159))
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=read)
        worker.start()
        assert started.wait(5)
        with fifo.open("wb") as destination:
            destination.write(payload)
        worker.join(5)
        assert not worker.is_alive()
        assert not errors, errors
        assert results == [expected.finalise()]


if __name__ == "__main__":
    if sys.argv[1] == "update":
        verify_update(sys.argv[2])
    else:
        verify_fifo()
