import base64
import hashlib
from pathlib import Path

import pytest

from quickxorhash_native import (
    DEFAULT_HASH_BUFFER_SIZE,
    FileHashAccumulator,
    __version__,
    calculate_file_hashes,
)


def test_runtime_version_matches_version_two_release():
    assert __version__ == "2.0.0"


def _hash_bytes(payload: bytes, chunk_size: int = 17):
    accumulator = FileHashAccumulator()
    for index in range(0, len(payload), chunk_size):
        accumulator.update(payload[index : index + chunk_size])
    return accumulator.finalise()


def _interoperability_vectors():
    fixture = Path(__file__).parent / "fixtures" / "quickxorhash_vectors.tsv"
    vectors = []
    for line in fixture.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        payload, expected_hash = line.split("\t")
        vectors.append((base64.b64decode(payload, validate=True), expected_hash))
    return vectors


def _checkpoint_v1_fixture():
    fixture = Path(__file__).parent / "fixtures" / "checkpoint_v1.txt"
    values = {}
    for line in fixture.read_text().splitlines():
        if line and not line.startswith("#"):
            name, value = line.split("=", 1)
            values[name] = value
    return values


def test_python_api_matches_incremental_updates(tmp_path):
    payload = (b"hello world" * 97) + b"\x00\x01\x02"
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)

    file_hashes = calculate_file_hashes(str(path), buffer_size=17)
    incremental_hashes = _hash_bytes(payload)

    assert file_hashes == incremental_hashes
    assert file_hashes["size"] == len(payload)
    assert file_hashes["sha1_hash"] == hashlib.sha1(payload).hexdigest()


@pytest.mark.parametrize(("payload", "expected_hash"), _interoperability_vectors())
def test_python_api_matches_interoperability_vectors(payload, expected_hash):
    assert _hash_bytes(payload)["quick_xor_hash"] == expected_hash


def test_file_hashes_empty_file(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")

    assert calculate_file_hashes(str(path)) == {
        "size": 0,
        "sha1_hash": hashlib.sha1(b"").hexdigest(),
        "quick_xor_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }


def test_file_hashes_rejects_zero_buffer_size(tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(b"payload")

    with pytest.raises(OSError, match="buffer_size must be greater than zero"):
        calculate_file_hashes(str(path), buffer_size=0)


def test_file_hashes_stop_after_reads_prefix_only(tmp_path):
    payload = b"0123456789abcdef"
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)

    assert calculate_file_hashes(str(path), stop_after=7, buffer_size=3) == _hash_bytes(
        payload[:7],
        chunk_size=3,
    )


def test_default_hash_buffer_size_is_positive():
    assert DEFAULT_HASH_BUFFER_SIZE > 0


def test_streaming_hash_matches_one_shot_at_block_boundaries(tmp_path):
    chunk_sizes = (1, 7, 31, 159, 160, 161, 512)
    buffer_sizes = (1, 7, 159, 160, 161, 512)
    path = tmp_path / "payload.bin"

    for length in (0, 1, 159, 160, 161, 319, 320, 321, 511, 512, 513):
        payload = bytes((index * 37 + 11) % 256 for index in range(length))
        expected = _hash_bytes(payload, chunk_size=1)

        for chunk_size in chunk_sizes:
            assert _hash_bytes(payload, chunk_size=chunk_size) == expected

        path.write_bytes(payload)
        for buffer_size in buffer_sizes:
            assert calculate_file_hashes(str(path), buffer_size=buffer_size) == expected


def test_accumulator_checkpoint_survives_block_boundary_states():
    suffix = b" suffix after a persisted checkpoint"

    for prefix_length in (0, 1, 159, 160, 161, 319, 320, 321):
        prefix = bytes((index * 37 + 11) % 256 for index in range(prefix_length))
        uninterrupted = FileHashAccumulator()
        uninterrupted.update(prefix + suffix)

        checkpointed = FileHashAccumulator()
        checkpointed.update(prefix)
        restored = FileHashAccumulator.restore(checkpointed.snapshot())
        restored.update(suffix)

        assert restored.finalise() == uninterrupted.finalise()


def test_accumulator_restores_immutable_v1_fixture():
    fixture = _checkpoint_v1_fixture()
    prefix = base64.b64decode(fixture["prefix_base64"], validate=True)
    suffix = base64.b64decode(fixture["suffix_base64"], validate=True)

    restored = FileHashAccumulator.restore(fixture["snapshot"])
    assert restored.finalise() == _hash_bytes(prefix)

    restored.update(suffix)
    assert restored.finalise() == {
        "size": int(fixture["expected_size"]),
        "sha1_hash": fixture["expected_sha1"],
        "quick_xor_hash": fixture["expected_quick_xor_hash"],
    }


def test_corrupt_accumulator_checkpoint_is_rejected():
    accumulator = FileHashAccumulator()
    accumulator.update(b"checkpoint")
    snapshot = accumulator.snapshot()
    replacement = "A" if snapshot[-3] != "A" else "B"

    with pytest.raises(ValueError, match="checkpoint"):
        FileHashAccumulator.restore(f"{snapshot[:-3]}{replacement}{snapshot[-2:]}")


def test_malformed_accumulator_checkpoints_are_rejected():
    snapshot = FileHashAccumulator().snapshot()

    for invalid_snapshot in (snapshot[:-4], base64.b64encode(b"NOPE").decode()):
        with pytest.raises(ValueError, match="checkpoint"):
            FileHashAccumulator.restore(invalid_snapshot)
