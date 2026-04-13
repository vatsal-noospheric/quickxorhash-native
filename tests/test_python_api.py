import hashlib

from quickxorhash_native import FileHashAccumulator, calculate_file_hashes


def test_python_api_matches_incremental_updates(tmp_path):
    payload = (b"hello world" * 97) + b"\x00\x01\x02"
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)

    file_hashes = calculate_file_hashes(str(path), buffer_size=17)

    accumulator = FileHashAccumulator()
    for index in range(0, len(payload), 17):
        accumulator.update(payload[index : index + 17])
    incremental_hashes = accumulator.finalise()

    assert file_hashes == incremental_hashes
    assert file_hashes["size"] == len(payload)
    assert file_hashes["sha1_hash"] == hashlib.sha1(payload).hexdigest()  # noqa: S324
