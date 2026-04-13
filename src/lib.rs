//! QuickXorHash implementation with Python bindings.
//!
//! This crate provides the core QuickXorHash algorithm in Rust plus a small
//! PyO3 extension module that exposes the file-hashing surface needed by
//! `frappe_onedrive_backup`.

use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read, Result as IoResult};
use std::path::Path;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use sha1::{Digest, Sha1};

const WIDTH_IN_BYTES: usize = 160 / 8;
const SHIFT: usize = 11;
pub const BLOCK_SIZE: usize = 160;
pub const DEFAULT_HASH_BUFFER_SIZE: usize = 1024 * 1024;

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
            sha1_hash: format!("{:x}", self.sha1.clone().finalize()),
            quick_xor_hash: self.quick_xor.finalise_base64(),
        }
    }
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

    loop {
        let read_size = match remaining {
            Some(remaining_bytes) => remaining_bytes.min(buffer_size),
            None => buffer_size,
        };

        if read_size == 0 {
            break;
        }

        let bytes_read = reader.read(&mut buffer[..read_size])?;
        if bytes_read == 0 {
            break;
        }

        accumulator.update(&buffer[..bytes_read]);

        if let Some(remaining_bytes) = remaining.as_mut() {
            *remaining_bytes = remaining_bytes.saturating_sub(bytes_read);
        }
    }

    Ok(accumulator.finalise())
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
    module.add("BLOCK_SIZE", BLOCK_SIZE)?;
    module.add("DEFAULT_HASH_BUFFER_SIZE", DEFAULT_HASH_BUFFER_SIZE)?;
    module.add_class::<PyFileHashAccumulator>()?;
    module.add_function(wrap_pyfunction!(py_calculate_file_hashes, module)?)?;
    Ok(())
}
