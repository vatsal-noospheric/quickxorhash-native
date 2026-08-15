use base64::prelude::{Engine as _, BASE64_STANDARD};
use quickxorhash_native::QuickXorHash;

const VECTOR_FIXTURE: &str = include_str!("fixtures/quickxorhash_vectors.tsv");

fn vectors() -> impl Iterator<Item = (&'static str, &'static str)> {
    VECTOR_FIXTURE.lines().filter_map(|line| {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let (payload, expected) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("invalid QuickXorHash fixture row: {line:?}"));
        assert!(
            !expected.contains('\t'),
            "fixture row has extra columns: {line:?}"
        );
        Some((payload, expected))
    })
}

fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 37 + 11) % 256) as u8)
        .collect()
}

#[test]
fn interoperability_vectors_match() {
    let mut count = 0;
    for (payload, expected) in vectors() {
        let mut quick_xor = QuickXorHash::new();
        quick_xor.update(&BASE64_STANDARD.decode(payload).unwrap());
        assert_eq!(
            quick_xor.finalise_base64(),
            expected,
            "fixture vector {count}"
        );
        count += 1;
    }
    assert_eq!(count, 70, "fixture unexpectedly changed vector count");
}

#[test]
fn interoperability_vectors_survive_update_partitions() {
    for chunk_size in [1, 2, 7, 31, 64, 159, 160, 161, 512] {
        for (payload, expected) in vectors() {
            let payload = BASE64_STANDARD.decode(payload).unwrap();
            let mut quick_xor = QuickXorHash::new();
            for chunk in payload.chunks(chunk_size) {
                quick_xor.update(chunk);
            }
            assert_eq!(quick_xor.finalise_base64(), expected);
        }
    }
}

#[test]
fn streaming_hash_matches_one_shot_at_block_boundaries() {
    for length in [0, 1, 159, 160, 161, 319, 320, 321, 511, 512, 513] {
        let payload = deterministic_payload(length);
        let mut one_shot = QuickXorHash::new();
        one_shot.update(&payload);
        let expected = one_shot.finalise();

        for chunk_size in [1, 7, 31, 159, 160, 161, 512] {
            let mut streaming = QuickXorHash::new();
            for chunk in payload.chunks(chunk_size) {
                streaming.update(chunk);
            }
            assert_eq!(
                streaming.finalise(),
                expected,
                "length={length}, chunk_size={chunk_size}"
            );
        }
    }
}
