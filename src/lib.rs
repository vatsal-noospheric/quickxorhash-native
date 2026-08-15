//! QuickXorHash implementation with Python bindings.
//!
//! This crate provides the core QuickXorHash algorithm in Rust plus a small
//! PyO3 extension module that exposes the file-hashing surface needed by
//! `frappe_onedrive_backup`.

use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read, Result as IoResult};
use std::path::Path;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use sha1::{
    digest::common::hazmat::{SerializableState, SerializedState},
    Digest, Sha1,
};

const WIDTH_IN_BYTES: usize = 160 / 8;
const SHIFT: usize = 11;
pub const BLOCK_SIZE: usize = 160;
pub const DEFAULT_HASH_BUFFER_SIZE: usize = 1024 * 1024;
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const CHECKPOINT_MAGIC: &[u8; 4] = b"QXHC";
pub const HASH_CHECKPOINT_VERSION: u8 = 1;
const SHA1_BLOCK_SIZE: u64 = 64;
const SHA1_BLOCK_LENGTH_OFFSET: usize = 20;
const SHA1_BUFFER_LENGTH_OFFSET: usize = 28;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashMetadata {
    pub size: usize,
    pub sha1_hash: String,
    pub quick_xor_hash: String,
}

pub struct QuickXorHash {
    data: [u8; BLOCK_SIZE],
    length: usize,
    index: usize,
}

impl Default for QuickXorHash {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickXorHash {
    pub fn new() -> Self {
        Self {
            data: [0; BLOCK_SIZE],
            length: 0,
            index: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let prefix = std::cmp::min((BLOCK_SIZE - self.index) % BLOCK_SIZE, bytes.len());

        self.data[self.index..]
            .iter_mut()
            .zip(bytes[..prefix].iter())
            .for_each(|(slot, byte)| *slot ^= *byte);
        self.index = (self.index + prefix) % BLOCK_SIZE;

        if bytes.len() > prefix {
            debug_assert!(self.index == 0);

            let chunks = bytes[prefix..].chunks_exact(BLOCK_SIZE);
            let tail = chunks.remainder();

            for block in chunks {
                self.data
                    .iter_mut()
                    .zip(block.iter())
                    .for_each(|(slot, byte)| *slot ^= *byte);
            }

            self.data
                .iter_mut()
                .zip(tail.iter())
                .for_each(|(slot, byte)| *slot ^= *byte);
            self.index += tail.len();
        }

        self.length += bytes.len();
    }

    pub fn finalise(&self) -> [u8; WIDTH_IN_BYTES] {
        let mut output = [0_u8; WIDTH_IN_BYTES];
        let mut shift = 0;

        for byte in self.data.iter().copied() {
            let shift_bytes = shift / 8;
            let shift_bits = shift % 8;
            let high = match shift_bits {
                0 => 0,
                _ => byte >> (8 - shift_bits),
            };
            let low = byte << shift_bits;

            output[shift_bytes % WIDTH_IN_BYTES] ^= low;
            output[(shift_bytes + 1) % WIDTH_IN_BYTES] ^= high;
            shift += SHIFT;
        }

        let length_bytes = self.length.to_le_bytes();
        let len = length_bytes.len();
        for (index, byte) in length_bytes.iter().enumerate() {
            output[WIDTH_IN_BYTES - len + index] ^= *byte;
        }

        output
    }

    pub fn finalise_base64(&self) -> String {
        BASE64_STANDARD.encode(self.finalise())
    }
}

pub struct FileHashAccumulator {
    quick_xor: QuickXorHash,
    sha1: Sha1,
    total_size: usize,
}

impl Default for FileHashAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl FileHashAccumulator {
    pub fn new() -> Self {
        Self {
            quick_xor: QuickXorHash::new(),
            sha1: Sha1::new(),
            total_size: 0,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }

        self.quick_xor.update(chunk);
        self.sha1.update(chunk);
        self.total_size += chunk.len();
    }

    pub fn finalise(&self) -> HashMetadata {
        HashMetadata {
            size: self.total_size,
            sha1_hash: encode_lower_hex(&self.sha1.clone().finalize()),
            quick_xor_hash: self.quick_xor.finalise_base64(),
        }
    }

    pub fn snapshot(&self) -> String {
        let sha1_state = self.sha1.serialize();
        let mut payload =
            Vec::with_capacity(4 + 1 + 8 + 8 + 8 + BLOCK_SIZE + 2 + sha1_state.len() + 4);
        payload.extend_from_slice(CHECKPOINT_MAGIC);
        payload.push(HASH_CHECKPOINT_VERSION);
        payload.extend_from_slice(&(self.total_size as u64).to_le_bytes());
        payload.extend_from_slice(&(self.quick_xor.length as u64).to_le_bytes());
        payload.extend_from_slice(&(self.quick_xor.index as u64).to_le_bytes());
        payload.extend_from_slice(&self.quick_xor.data);
        payload.extend_from_slice(&(sha1_state.len() as u16).to_le_bytes());
        payload.extend_from_slice(sha1_state.as_slice());
        payload.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        BASE64_STANDARD.encode(payload)
    }

    pub fn restore(snapshot: &str) -> Result<Self, SnapshotError> {
        let bytes = BASE64_STANDARD
            .decode(snapshot)
            .map_err(|_| SnapshotError::InvalidEncoding)?;
        if bytes.len() < 4 {
            return Err(SnapshotError::InvalidFormat);
        }
        let checksum_start = bytes.len() - 4;
        let (payload, checksum_bytes) = bytes.split_at(checksum_start);
        let expected_checksum = u32::from_le_bytes(
            checksum_bytes
                .try_into()
                .map_err(|_| SnapshotError::InvalidFormat)?,
        );
        if crc32fast::hash(payload) != expected_checksum {
            return Err(SnapshotError::Corrupt);
        }

        let mut reader = SnapshotReader::new(payload);
        if reader.take(4)? != CHECKPOINT_MAGIC {
            return Err(SnapshotError::InvalidFormat);
        }
        let version = reader.take_u8()?;
        if version != HASH_CHECKPOINT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        let total_size =
            usize::try_from(reader.take_u64()?).map_err(|_| SnapshotError::InvalidFormat)?;
        let quick_xor_length =
            usize::try_from(reader.take_u64()?).map_err(|_| SnapshotError::InvalidFormat)?;
        let quick_xor_index =
            usize::try_from(reader.take_u64()?).map_err(|_| SnapshotError::InvalidFormat)?;
        let quick_xor_data: [u8; BLOCK_SIZE] = reader
            .take(BLOCK_SIZE)?
            .try_into()
            .map_err(|_| SnapshotError::InvalidFormat)?;
        let sha1_length = usize::from(reader.take_u16()?);
        let sha1_bytes = reader.take(sha1_length)?;
        if !reader.is_finished() {
            return Err(SnapshotError::InvalidFormat);
        }
        if total_size != quick_xor_length || quick_xor_index != quick_xor_length % BLOCK_SIZE {
            return Err(SnapshotError::Corrupt);
        }
        let serialized_sha1 = SerializedState::<Sha1>::try_from(sha1_bytes)
            .map_err(|_| SnapshotError::InvalidFormat)?;
        let sha1 = Sha1::deserialize(&serialized_sha1).map_err(|_| SnapshotError::InvalidFormat)?;
        let serialized_sha1 = serialized_sha1.as_slice();
        let sha1_block_length = u64::from_le_bytes(
            serialized_sha1[SHA1_BLOCK_LENGTH_OFFSET..SHA1_BUFFER_LENGTH_OFFSET]
                .try_into()
                .map_err(|_| SnapshotError::InvalidFormat)?,
        );
        let sha1_buffer_length = u64::from(serialized_sha1[SHA1_BUFFER_LENGTH_OFFSET]);
        let sha1_processed_size = sha1_block_length
            .checked_mul(SHA1_BLOCK_SIZE)
            .and_then(|length| length.checked_add(sha1_buffer_length))
            .ok_or(SnapshotError::Corrupt)?;
        if u64::try_from(total_size).map_err(|_| SnapshotError::InvalidFormat)?
            != sha1_processed_size
        {
            return Err(SnapshotError::Corrupt);
        }

        Ok(Self {
            quick_xor: QuickXorHash {
                data: quick_xor_data,
                length: quick_xor_length,
                index: quick_xor_index,
            },
            sha1,
            total_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidEncoding,
    InvalidFormat,
    UnsupportedVersion(u8),
    Corrupt,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("checkpoint is not valid base64"),
            Self::InvalidFormat => formatter.write_str("checkpoint has an invalid format"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "checkpoint version {version} is not supported")
            }
            Self::Corrupt => formatter.write_str("checkpoint integrity validation failed"),
        }
    }
}

impl std::error::Error for SnapshotError {}

struct SnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SnapshotError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SnapshotError::InvalidFormat)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SnapshotError::InvalidFormat)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, SnapshotError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SnapshotError::InvalidFormat)?,
        ))
    }

    fn take_u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| SnapshotError::InvalidFormat)?,
        ))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        output.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn calculate_file_hashes<P: AsRef<Path>>(
    path: P,
    stop_after: Option<usize>,
    buffer_size: usize,
) -> IoResult<HashMetadata> {
    if buffer_size == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "buffer_size must be greater than zero",
        ));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(buffer_size, file);
    let mut accumulator = FileHashAccumulator::new();
    let mut remaining = stop_after;
    let mut buffer = vec![0_u8; buffer_size];

    while let Some(bytes_read) = read_next_chunk(&mut reader, &mut buffer, remaining)? {
        accumulator.update(&buffer[..bytes_read]);
        reduce_remaining(&mut remaining, bytes_read);
    }

    Ok(accumulator.finalise())
}

fn read_next_chunk<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    remaining: Option<usize>,
) -> IoResult<Option<usize>> {
    let read_size = next_read_size(remaining, buffer.len());
    if read_size == 0 {
        return Ok(None);
    }

    let bytes_read = reader.read(&mut buffer[..read_size])?;
    if bytes_read == 0 {
        return Ok(None);
    }

    Ok(Some(bytes_read))
}

fn next_read_size(remaining: Option<usize>, buffer_size: usize) -> usize {
    match remaining {
        Some(remaining_bytes) => remaining_bytes.min(buffer_size),
        None => buffer_size,
    }
}

fn reduce_remaining(remaining: &mut Option<usize>, bytes_read: usize) {
    if let Some(remaining_bytes) = remaining.as_mut() {
        *remaining_bytes = remaining_bytes.saturating_sub(bytes_read);
    }
}

fn metadata_to_pydict<'py>(
    py: Python<'py>,
    metadata: &HashMetadata,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("size", metadata.size)?;
    dict.set_item("sha1_hash", &metadata.sha1_hash)?;
    dict.set_item("quick_xor_hash", &metadata.quick_xor_hash)?;
    Ok(dict)
}

#[pyclass(name = "FileHashAccumulator")]
struct PyFileHashAccumulator {
    inner: FileHashAccumulator,
}

#[pymethods]
impl PyFileHashAccumulator {
    #[new]
    fn py_new() -> Self {
        Self {
            inner: FileHashAccumulator::new(),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
    }

    fn finalise<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        metadata_to_pydict(py, &self.inner.finalise())
    }

    fn snapshot(&self) -> String {
        self.inner.snapshot()
    }

    #[staticmethod]
    fn restore(snapshot: &str) -> PyResult<Self> {
        FileHashAccumulator::restore(snapshot)
            .map(|inner| Self { inner })
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }
}

#[pyfunction(name = "calculate_file_hashes")]
#[pyo3(signature = (path, stop_after=None, buffer_size=DEFAULT_HASH_BUFFER_SIZE))]
fn py_calculate_file_hashes<'py>(
    py: Python<'py>,
    path: &str,
    stop_after: Option<usize>,
    buffer_size: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let metadata = calculate_file_hashes(path, stop_after, buffer_size)
        .map_err(|error| PyIOError::new_err(error.to_string()))?;
    metadata_to_pydict(py, &metadata)
}

#[pymodule]
fn quickxorhash_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    add_constants(module)?;
    add_classes(module)?;
    add_functions(module)?;
    Ok(())
}

fn add_constants(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", PACKAGE_VERSION)?;
    module.add("BLOCK_SIZE", BLOCK_SIZE)?;
    module.add("DEFAULT_HASH_BUFFER_SIZE", DEFAULT_HASH_BUFFER_SIZE)?;
    module.add("HASH_CHECKPOINT_VERSION", HASH_CHECKPOINT_VERSION)?;
    Ok(())
}

fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyFileHashAccumulator>()?;
    Ok(())
}

fn add_functions(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(py_calculate_file_hashes, module)?)?;
    Ok(())
}
