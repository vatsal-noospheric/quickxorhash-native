# quickxorhash-native

Rust-backed [QuickXorHash] implementation with a small Python extension module.

A quick, simple non-cryptographic hash algorithm that works by XORing the bytes in a
circular-shifting fashion.

[QuickXorHash]: https://learn.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash

## Examples
```
use quickxorhash_native::QuickXorHash;

let mut qx = QuickXorHash::new();
qx.update(b"hello world");
assert_eq!(qx.finalise(), [104, 40, 3, 27, 216, 240, 6, 16, 220, 225, 13, 114, 107, 3, 25, 0, 0, 0, 0, 0]);
```

### Python

```bash
maturin develop -i /path/to/python
```

```python
from quickxorhash_native import FileHashAccumulator, calculate_file_hashes

result = calculate_file_hashes("/tmp/example.bin")

accumulator = FileHashAccumulator()
accumulator.update(b"hello ")
accumulator.update(b"world")
assert accumulator.finalise()["quick_xor_hash"] == result["quick_xor_hash"]
```

## Notes

This package is based on the original Rust `quickxorhash` implementation by
[Guy Rutenberg](https://www.guyrutenberg.com) and preserves the dual
`MIT OR Apache-2.0` licensing model.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Authors
- Author: [Guy Rutenberg](https://www.guyrutenberg.com)
