# Changelog

## 2.0.0 (unreleased)

### Changed

- Require CPython 3.14 and use its stable ABI as the wheel baseline.
- Support only macOS ARM64 and Linux AArch64 in the initial release matrix.
- Treat the package as native-only; Version 2 releases contain no source
  distribution or pure-Python fallback.
- Expose the package version at runtime as `quickxorhash_native.__version__`.

### Added

- Add resumable `FileHashAccumulator` checkpoints with versioning, structural
  validation, and corruption detection.
- Add an executable release contract that validates wheel identity, metadata,
  type-support files, the exact platform set, installed public behaviour, and
  SHA-256 checksums before publication.

### Compatibility

- Version 2 serves the Frappe 16 and Python 3.14 deployment line. It does not
  replace the legacy Version 0.1.1 release used by the Frappe 15 site.
