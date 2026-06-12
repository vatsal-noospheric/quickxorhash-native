from collections.abc import Buffer
from typing import TypedDict

BLOCK_SIZE: int
DEFAULT_HASH_BUFFER_SIZE: int


class FileHashMetadata(TypedDict):
    size: int
    sha1_hash: str
    quick_xor_hash: str


class FileHashAccumulator:
    def __new__(cls) -> "FileHashAccumulator": ...
    def update(self, chunk: Buffer, /) -> None: ...
    def finalise(self) -> FileHashMetadata: ...


def calculate_file_hashes(
    path: str,
    stop_after: int | None = None,
    buffer_size: int = DEFAULT_HASH_BUFFER_SIZE,
) -> FileHashMetadata: ...
