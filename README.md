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

`calculate_file_hashes(path, stop_after=None, buffer_size=1048576)` returns a
dict with:

- `size`: bytes processed
- `sha1_hash`: lowercase hexadecimal SHA1 digest
- `quick_xor_hash`: base64 QuickXorHash digest

## Development

```bash
python -m pip install "maturin>=1.14,<2.0" "pytest>=9.0.3" "ruff>=0.15.17"
maturin develop -i "$(command -v python)"
pytest
cargo test
```

Build a wheel:

```bash
maturin build --release --out dist
```

The `Wheels` GitHub Actions workflow builds release wheels for Python 3.13 and
3.14 on Linux and macOS. Publish and consume those wheels from a tag before
removing Rust build dependencies from downstream deployment environments.

## Licence

This package is based on the original Rust `quickxorhash` implementation by
[Guy Rutenberg](https://www.guyrutenberg.com) and preserves the dual
`MIT OR Apache-2.0` licensing model.
