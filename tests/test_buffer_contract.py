from array import array

import pytest

from quickxorhash_native import FileHashAccumulator


def metadata(payload):
    accumulator = FileHashAccumulator()
    accumulator.update(payload)
    return accumulator.finalise()


class ByteBuffer:
    def __init__(self, payload):
        self.payload = payload

    def __buffer__(self, _flags):
        return memoryview(self.payload)


@pytest.mark.parametrize(
    "factory",
    [
        bytes,
        bytearray,
        memoryview,
        lambda data: memoryview(bytearray(data)),
        lambda data: array("B", data),
        ByteBuffer,
    ],
    ids=[
        "bytes",
        "bytearray",
        "readonly-view",
        "writable-view",
        "byte-array",
        "python-buffer",
    ],
)
@pytest.mark.parametrize(
    "payload", [b"", bytes(range(256)) * 3 + b"suffix"], ids=["empty", "nonempty"]
)
def test_byte_buffers_match_bytes_for_empty_and_multiple_updates(factory, payload):
    accumulator = FileHashAccumulator()
    for part in (payload[:13], payload[13:160], payload[160:]):
        accumulator.update(factory(part))
    assert accumulator.finalise() == metadata(payload)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "text",
        [1, 2],
        12,
        memoryview(b"abcdefghijklmnop")[::2],
        memoryview(b"abcdefgh").cast("H"),
        array("b", [-1, 0, 1]),
    ],
    ids=[
        "none",
        "text",
        "list",
        "integer",
        "strided",
        "wide-elements",
        "signed-elements",
    ],
)
def test_unsupported_inputs_leave_accumulator_and_checkpoint_unchanged(value):
    accumulator = FileHashAccumulator()
    accumulator.update(b"prefix")
    previous_metadata = accumulator.finalise()
    previous_checkpoint = accumulator.snapshot()
    with pytest.raises(TypeError):
        accumulator.update(value)
    assert accumulator.finalise() == previous_metadata
    assert accumulator.snapshot() == previous_checkpoint
    accumulator.update(b"suffix")
    assert accumulator.finalise() == metadata(b"prefixsuffix")


def test_released_memoryview_is_rejected_without_mutating_state():
    view = memoryview(b"payload")
    view.release()
    accumulator = FileHashAccumulator()
    before = accumulator.snapshot()
    with pytest.raises(TypeError):
        accumulator.update(view)
    assert accumulator.snapshot() == before


def test_writable_buffer_is_hashed_at_the_time_of_update():
    payload = bytearray(b"original")
    accumulator = FileHashAccumulator()
    accumulator.update(memoryview(payload))
    payload[:] = b"modified"
    assert accumulator.finalise() == metadata(b"original")
