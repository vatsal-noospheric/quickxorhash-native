import base64
import zlib

import pytest

from quickxorhash_native import FileHashAccumulator


@pytest.mark.parametrize(
    "snapshot",
    ["!" * 388, "A" * (8 * 1024 * 1024)],
    ids=["oversized-malformed", "oversized-base64"],
)
def test_oversized_checkpoint_is_rejected_before_decoding(snapshot):
    with pytest.raises(ValueError, match="invalid format"):
        FileHashAccumulator.restore(snapshot)


def changed_payload(snapshot, offset=None, value=None, trailing=b""):
    payload = bytearray(base64.b64decode(snapshot)[:-4])
    if offset is not None:
        payload[offset] = value
    payload.extend(trailing)
    checksum = zlib.crc32(payload).to_bytes(4, "little")
    return base64.b64encode(payload + checksum).decode()


@pytest.mark.parametrize(
    "transform",
    [
        lambda state: "not-base64!",
        lambda state: state[:-4],
        lambda state: changed_payload(state, 0, ord("N")),
        lambda state: changed_payload(state, 4, 99),
        lambda state: changed_payload(state, 5, 1),
        lambda state: changed_payload(state, 21, 160),
        lambda state: changed_payload(state, 189, 255),
        lambda state: changed_payload(state, trailing=b"extra"),
    ],
    ids=[
        "base64",
        "truncated",
        "magic",
        "version",
        "size",
        "index",
        "sha1-length",
        "trailing",
    ],
)
def test_malformed_checkpoint_retains_value_error_category(transform):
    snapshot = FileHashAccumulator().snapshot()
    with pytest.raises(ValueError, match="checkpoint"):
        FileHashAccumulator.restore(transform(snapshot))


@pytest.mark.parametrize("size", [0, 63, 64, 65, 159, 160, 161])
def test_checkpoint_limits_preserve_empty_and_block_boundary_continuation(size):
    payload = bytes((index * 37 + 11) % 256 for index in range(size))
    original = FileHashAccumulator()
    original.update(payload)
    restored = FileHashAccumulator.restore(original.snapshot())
    original.update(b"suffix")
    restored.update(b"suffix")
    assert restored.finalise() == original.finalise()
