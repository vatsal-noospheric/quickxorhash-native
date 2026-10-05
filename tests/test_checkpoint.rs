use base64::prelude::{Engine as _, BASE64_STANDARD};
use quickxorhash_native::{FileHashAccumulator, SnapshotError, BLOCK_SIZE};

const CHECKPOINT_V1_FIXTURE: &str = include_str!("fixtures/checkpoint_v1.txt");
const CHECKPOINT_SHA1_LENGTH_OFFSET: usize = 4 + 1 + (3 * 8) + BLOCK_SIZE;

fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 37 + 11) % 256) as u8)
        .collect()
}

fn rewrite_snapshot_payload(snapshot: &str, offset: usize, value: u8) -> String {
    let mut bytes = BASE64_STANDARD.decode(snapshot).unwrap();
    bytes[offset] = value;
    BASE64_STANDARD.encode(bytes)
}

fn snapshot_with_version(snapshot: &str, version: u8) -> String {
    rewrite_snapshot_payload_with_checksum(snapshot, 4, version)
}

fn rewrite_snapshot_payload_with_checksum(snapshot: &str, offset: usize, value: u8) -> String {
    let mut bytes = BASE64_STANDARD.decode(snapshot).unwrap();
    bytes[offset] = value;
    let payload_length = bytes.len() - 4;
    let checksum = crc32fast::hash(&bytes[..payload_length]).to_le_bytes();
    bytes[payload_length..].copy_from_slice(&checksum);
    BASE64_STANDARD.encode(bytes)
}

fn checkpoint_sha1_state_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let length_start = CHECKPOINT_SHA1_LENGTH_OFFSET;
    let length_end = length_start + 2;
    let length = usize::from(u16::from_le_bytes(
        bytes[length_start..length_end].try_into().unwrap(),
    ));
    length_end..length_end + length
}

fn fixture_value(name: &str) -> &str {
    let prefix = format!("{name}=");
    CHECKPOINT_V1_FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("checkpoint fixture is missing {name}"))
}

#[test]
fn immutable_v1_fixture_restores_continues_and_matches_final_hashes() {
    let prefix = BASE64_STANDARD
        .decode(fixture_value("prefix_base64"))
        .unwrap();
    let suffix = BASE64_STANDARD
        .decode(fixture_value("suffix_base64"))
        .unwrap();
    let snapshot = fixture_value("snapshot");
    let snapshot_bytes = BASE64_STANDARD.decode(snapshot).unwrap();
    assert_eq!(snapshot_bytes[4], 1, "fixture must remain checkpoint v1");

    let mut prefix_accumulator = FileHashAccumulator::new();
    prefix_accumulator.update(&prefix);
    let mut restored = FileHashAccumulator::restore(snapshot).unwrap();
    assert_eq!(restored.finalise(), prefix_accumulator.finalise());

    restored.update(&suffix);
    let metadata = restored.finalise();
    assert_eq!(
        metadata.size,
        fixture_value("expected_size").parse::<usize>().unwrap()
    );
    assert_eq!(metadata.sha1_hash, fixture_value("expected_sha1"));
    assert_eq!(
        metadata.quick_xor_hash,
        fixture_value("expected_quick_xor_hash")
    );

    let mut uninterrupted = FileHashAccumulator::new();
    uninterrupted.update(&prefix);
    uninterrupted.update(&suffix);
    assert_eq!(metadata, uninterrupted.finalise());
}

#[test]
fn restored_checkpoint_matches_uninterrupted_hashes_at_boundaries() {
    let suffix = b" suffix after a persisted checkpoint";

    for prefix_length in [0, 1, 159, 160, 161, 319, 320, 321] {
        let prefix = deterministic_payload(prefix_length);
        let mut uninterrupted = FileHashAccumulator::new();
        uninterrupted.update(&prefix);
        uninterrupted.update(suffix);

        let mut checkpointed = FileHashAccumulator::new();
        checkpointed.update(&prefix);
        let snapshot = checkpointed.snapshot();
        let mut restored = FileHashAccumulator::restore(&snapshot).unwrap();
        restored.update(suffix);

        assert_eq!(restored.finalise(), uninterrupted.finalise());
    }
}

#[test]
fn crc_valid_checkpoint_rejects_mixed_sha1_state() {
    let mut shorter = FileHashAccumulator::new();
    shorter.update(b"short checkpoint");
    let shorter_bytes = BASE64_STANDARD.decode(shorter.snapshot()).unwrap();

    let mut longer = FileHashAccumulator::new();
    longer.update(&deterministic_payload(BLOCK_SIZE));
    let mut longer_bytes = BASE64_STANDARD.decode(longer.snapshot()).unwrap();
    let shorter_sha1 = checkpoint_sha1_state_range(&shorter_bytes);
    let longer_sha1 = checkpoint_sha1_state_range(&longer_bytes);
    assert_eq!(shorter_sha1.len(), longer_sha1.len());
    longer_bytes[longer_sha1].copy_from_slice(&shorter_bytes[shorter_sha1]);

    // Keep the longer checkpoint's declared size and QuickXor state, but make
    // its serialized SHA-1 state come from the shorter checkpoint.
    let payload_length = longer_bytes.len() - 4;
    let checksum = crc32fast::hash(&longer_bytes[..payload_length]).to_le_bytes();
    longer_bytes[payload_length..].copy_from_slice(&checksum);

    let mixed_snapshot = BASE64_STANDARD.encode(longer_bytes);
    assert!(matches!(
        FileHashAccumulator::restore(&mixed_snapshot),
        Err(SnapshotError::Corrupt)
    ));
}

#[test]
fn corrupt_checkpoint_is_rejected() {
    let mut accumulator = FileHashAccumulator::new();
    accumulator.update(b"checkpoint data");
    let snapshot = accumulator.snapshot();
    let encoded = BASE64_STANDARD.decode(snapshot).unwrap();
    let corrupted = rewrite_snapshot_payload(
        &BASE64_STANDARD.encode(&encoded),
        encoded.len() / 2,
        encoded[encoded.len() / 2] ^ 1,
    );

    assert!(matches!(
        FileHashAccumulator::restore(&corrupted),
        Err(SnapshotError::Corrupt)
    ));
}

#[test]
fn truncated_checkpoint_is_rejected() {
    let snapshot = FileHashAccumulator::new().snapshot();
    let mut bytes = BASE64_STANDARD.decode(snapshot).unwrap();
    bytes.truncate(bytes.len() - 1);
    let truncated = BASE64_STANDARD.encode(bytes);

    assert!(FileHashAccumulator::restore(&truncated).is_err());
}

#[test]
fn unsupported_checkpoint_version_is_rejected() {
    let snapshot = FileHashAccumulator::new().snapshot();
    let unsupported = snapshot_with_version(&snapshot, 99);

    assert!(matches!(
        FileHashAccumulator::restore(&unsupported),
        Err(SnapshotError::UnsupportedVersion(99))
    ));
}

#[test]
fn invalid_checkpoint_magic_is_rejected() {
    let snapshot = FileHashAccumulator::new().snapshot();
    let invalid_magic = rewrite_snapshot_payload_with_checksum(&snapshot, 0, b'N');

    assert!(matches!(
        FileHashAccumulator::restore(&invalid_magic),
        Err(SnapshotError::InvalidFormat)
    ));
}

#[test]
fn oversized_checkpoint_is_rejected_before_base64_decoding() {
    let encoded_length = FileHashAccumulator::new().snapshot().len();
    let invalid_encoding = "!".repeat(encoded_length + 4);
    assert!(matches!(
        FileHashAccumulator::restore(&invalid_encoding),
        Err(SnapshotError::InvalidFormat)
    ));

    let oversized_base64 = "A".repeat(8 * 1024 * 1024);
    assert!(matches!(
        FileHashAccumulator::restore(&oversized_base64),
        Err(SnapshotError::InvalidFormat)
    ));
}
