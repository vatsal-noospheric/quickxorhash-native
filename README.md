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

`FileHashAccumulator.update(chunk)` accepts `bytes`, `bytearray`, and other
C-contiguous unsigned-byte buffers, including read-only and writable
`memoryview` objects. Non-contiguous views, signed-byte or multi-byte formats,
released views, and objects without the buffer protocol raise `TypeError`
without changing the accumulator. Buffers other than `bytes` are copied before
hashing; changing a mutable buffer after `update` returns cannot change the
recorded hashes. The `bytes` path hashes directly without copying.

Whole-file hashing releases the Python interpreter during native file I/O and
hashing. Updates of at least 1 MiB also release it during Rust hashing; shorter
updates remain attached to avoid overhead on small calls. Mutable buffer
validation and copying happen while attached, before Rust uses its owned copy.
An accumulator being updated rejects overlapping `update`, `finalise` or
`snapshot` calls with `RuntimeError`. Use a
separate accumulator for an independent stream, or wait and retry. Rejection
does not change the recorded state. These rules are verified on GIL-enabled
CPython 3.14; free-threaded execution is not established by these results.

`snapshot()` returns a Base64 checkpoint. `FileHashAccumulator.restore(state)`
restores checkpoint v1, including snapshots from earlier v2.0.0 wheels. Invalid
checkpoints raise `ValueError`. Encoded input is bounded before decoding by the
supported v1 frame size (currently 384 ASCII characters); CRC, version and
processed-byte consistency checks still apply.

## Supported runtime

Version 2 supports CPython 3.14 on macOS ARM64 and Linux AArch64. It
is native-only: releases contain platform wheels and never a source
distribution. The extension is built against the CPython 3.14 stable-ABI
baseline (`cp314-abi3`), but the package's declared support range remains
`>=3.14,<3.15`; each target has one wheel for the CPython 3.14 patch releases.

## Development

```bash
python -m pip install "maturin>=1.14.1,<2.0" "pytest>=9.1.1" "ruff>=0.16.3"
maturin develop -i "$(command -v python)"
pytest
ruff check .
ruff format --check .
cargo test
```

Repeatable hashing and checkpoint measurements are described in
[docs/performance.md](docs/performance.md). They report local workloads and
Python-thread responsiveness, without inferring upload throughput.

Build a wheel for development:

```bash
maturin build --release --out dist
```

Release candidates must pass the repository-owned release contract:

```bash
python -m tools.release_contract preflight --tag v2.0.1
python -m tools.release_contract verify-wheel \
  --target macos-arm64 dist/quickxorhash_native-2.0.1-cp314-abi3-macosx_11_0_arm64.whl
python -m tools.release_contract assemble --tag v2.0.1 --dist dist
```

`verify-wheel` installs the wheel into a clean CPython 3.14 environment with
Rust absent from `PATH`, then exercises the public hashing and checkpoint API.
`preflight` validates the source metadata and release tag before any wheel
builds start.
`assemble` accepts exactly one macOS ARM64 wheel and one manylinux AArch64
wheel, rejects source distributions and unexpected assets, and writes
a sorted `SHA256SUMS` manifest.

## Local ARM64 wheel builds

On macOS ARM64 with OrbStack Docker running, use:

```bash
tools/build_arm_wheels.sh
```

The command builds the current declared version for macOS ARM64 and Linux ARM64,
verifies each installed wheel in a clean Python 3.14 environment, runs the
complete Python and Rust contract suites, and assembles the two-wheel bundle
with `SHA256SUMS`. It does not publish, install into the app environment, or
perform Git actions. Existing output directories are preserved; pass a fresh
output directory as the first argument for another run.

The builder uses Rust 1.97.1, maturin 1.14.1 and a digest-pinned ARM64
manylinux2014 image. Linux uses glibc 2.17 and GIL-enabled CPython 3.14.
The macOS Rust installation lives under `dist/arm-builder-cache`; alternatively
set `ARM_WHEEL_MAC_RUST_BIN` to an existing Rust 1.97.1 bin directory. The host
needs `python3.14`, `uv`, Docker and `rsync`. Source snapshots, tool caches and
verification logs remain under ignored `dist/` directories.

The configured OrbStack Ubuntu shortcut is `~/.local/bin/quickxorhash-arm-wheels`.
It launches the host builder through `macctl`; the
Linux compiler and wheel tests still run in the ARM64 container. An ARM64 wheel
cannot be installed into that x86_64 VM's Python interpreter.

## Licence

This package is based on the original Rust `quickxorhash` implementation by
[Guy Rutenberg](https://www.guyrutenberg.com) and preserves the dual
`MIT OR Apache-2.0` licensing model.
