from collections.abc import Buffer
from typing import Self, TypedDict

__version__: str
BLOCK_SIZE: int
DEFAULT_HASH_BUFFER_SIZE: int
HASH_CHECKPOINT_VERSION: int

class FileHashMetadata(TypedDict):
    size: int
    sha1_hash: str
    quick_xor_hash: str

class FileHashAccumulator:
    def __new__(cls) -> Self: ...
    # Requires C-contiguous unsigned-byte data; invalid inputs raise TypeError.
    # Overlapping access during an update raises RuntimeError; retry after it finishes.
    def update(self, chunk: Buffer, /) -> None: ...
    def finalise(self) -> FileHashMetadata: ...
    def snapshot(self) -> str: ...
    @staticmethod
    def restore(snapshot: str) -> FileHashAccumulator: ...

def calculate_file_hashes(
    path: str,
    stop_after: int | None = None,
    buffer_size: int = ...,
) -> FileHashMetadata: ...
