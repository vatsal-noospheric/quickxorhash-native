import base64
import hashlib
import re
from pathlib import Path

import pytest
from quickxorhash_native import (
    DEFAULT_HASH_BUFFER_SIZE,
    FileHashAccumulator,
    calculate_file_hashes,
)


def _hash_bytes(payload: bytes, chunk_size: int = 17):
    accumulator = FileHashAccumulator()
    for index in range(0, len(payload), chunk_size):
        accumulator.update(payload[index : index + chunk_size])
    return accumulator.finalise()


def _rust_test_vectors():
    vector_source = Path(__file__).with_name("test_vectors.rs").read_text()
    return [
        (base64.b64decode(payload), expected_hash)
        for payload, expected_hash in re.findall(
            r'\("([^"]*)",\s*"([^"]*)"\)',
            vector_source,
        )
    ]


def test_python_api_matches_incremental_updates(tmp_path):
    payload = (b"hello world" * 97) + b"\x00\x01\x02"
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)

    file_hashes = calculate_file_hashes(str(path), buffer_size=17)
    incremental_hashes = _hash_bytes(payload)

    assert file_hashes == incremental_hashes
    assert file_hashes["size"] == len(payload)
    assert file_hashes["sha1_hash"] == hashlib.sha1(payload).hexdigest()  # noqa: S324


@pytest.mark.parametrize(("payload", "expected_hash"), _rust_test_vectors())
def test_python_api_matches_rclone_quickxorhash_vectors(payload, expected_hash):
    assert _hash_bytes(payload)["quick_xor_hash"] == expected_hash


def test_file_hashes_empty_file(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")

    assert calculate_file_hashes(str(path)) == {
        "size": 0,
        "sha1_hash": hashlib.sha1(b"").hexdigest(),  # noqa: S324
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
