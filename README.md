# quickxorhash-native

Rust-backed QuickXorHash and file-hash helpers for Python.

QuickXorHash is the non-cryptographic hash exposed by Microsoft OneDrive file
metadata. This package calculates file size, SHA1, and QuickXorHash in one
streaming pass so a caller can verify uploaded OneDrive backups without reading
large archives multiple times.

[QuickXorHash]: https://learn.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash

## Python API

```python
from quickxorhash_native import FileHashAccumulator, calculate_file_hashes

result = calculate_file_hashes("/tmp/example.bin")
assert set(result) == {"size", "sha1_hash", "quick_xor_hash"}

accumulator = FileHashAccumulator()
accumulator.update(b"hello ")
accumulator.update(b"world")
incremental_result = accumulator.finalise()
```

The module exposes `__version__`, `BLOCK_SIZE`, `DEFAULT_HASH_BUFFER_SIZE`, and
`HASH_CHECKPOINT_VERSION` alongside the hashing interface.

`calculate_file_hashes(path, stop_after=None, buffer_size=1048576)` returns a
dict with:

- `size`: bytes processed
- `sha1_hash`: lowercase hexadecimal SHA1 digest
- `quick_xor_hash`: base64 QuickXorHash digest

## Supported runtime

Version 2 supports CPython 3.14 on macOS ARM64 and Linux AArch64. It is
native-only: releases contain platform wheels and never a source distribution.
The extension uses Python's stable ABI from CPython 3.14 onwards, so each target
has one `cp314-abi3` wheel rather than a separate wheel for each later CPython
3.14 patch release.

## Development

```bash
python -m pip install "maturin>=1.14,<2.0" "pytest>=9.0.3" "ruff>=0.15.17"
maturin develop -i "$(command -v python)"
pytest
ruff check .
ruff format --check .
cargo test
```

Build a wheel for development:

```bash
maturin build --release --out dist
```

Release candidates must pass the repository-owned release contract:

```bash
python -m tools.release_contract preflight --tag v2.0.0
python -m tools.release_contract verify-wheel \
  --target macos-arm64 dist/quickxorhash_native-2.0.0-cp314-abi3-macosx_11_0_arm64.whl
python -m tools.release_contract assemble --tag v2.0.0 --dist dist
```

`verify-wheel` installs the wheel into a clean CPython 3.14 environment with
Rust absent from `PATH`, then exercises the public hashing and checkpoint API.
`preflight` validates the source metadata and release tag before any wheel
builds start.
`assemble` accepts exactly one macOS ARM64 wheel and one manylinux AArch64
wheel, rejects source distributions and unexpected assets, and writes a sorted
`SHA256SUMS` manifest.

## Licence

This package is based on the original Rust `quickxorhash` implementation by
[Guy Rutenberg](https://www.guyrutenberg.com) and preserves the dual
`MIT OR Apache-2.0` licensing model.
