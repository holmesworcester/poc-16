use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read};

fn io_error(err: io::Error) -> PyErr {
    if err.kind() == io::ErrorKind::InvalidData {
        PyValueError::new_err(err.to_string())
    } else {
        PyIOError::new_err(err.to_string())
    }
}

#[pyfunction]
fn prepare_file(input_path: &str, outboard_path: &str) -> PyResult<Vec<u8>> {
    let mut input = File::open(input_path).map_err(io_error)?;
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(outboard_path)
        .map_err(io_error)?;
    let mut encoder = bao::encode::Encoder::new_outboard(output);
    io::copy(&mut input, &mut encoder).map_err(io_error)?;
    let root = encoder.finalize().map_err(io_error)?;
    Ok(root.as_bytes().to_vec())
}

#[pyfunction]
fn extract_slice(
    input_path: &str,
    outboard_path: &str,
    start: u64,
    count: u64,
) -> PyResult<Vec<u8>> {
    if count == 0 {
        return Err(PyValueError::new_err("Bao slice count must be positive"));
    }
    let input = File::open(input_path).map_err(io_error)?;
    let outboard = File::open(outboard_path).map_err(io_error)?;
    let mut extractor = bao::encode::SliceExtractor::new_outboard(input, outboard, start, count);
    let mut proof = Vec::new();
    extractor.read_to_end(&mut proof).map_err(io_error)?;
    Ok(proof)
}

#[pyfunction]
fn decode_slice(
    proof: &[u8],
    root: &[u8],
    start: u64,
    count: u64,
    expected_length: u64,
) -> PyResult<Vec<u8>> {
    if root.len() != bao::HASH_SIZE || proof.len() < 8 || count == 0 {
        return Err(PyValueError::new_err("invalid Bao slice parameters"));
    }
    let encoded_length = u64::from_le_bytes(proof[..8].try_into().unwrap());
    if encoded_length != expected_length
        || start
            .checked_add(count)
            .is_none_or(|end| end > expected_length)
    {
        return Err(PyValueError::new_err(
            "Bao slice does not match descriptor geometry",
        ));
    }
    let root_array: [u8; bao::HASH_SIZE] = root.try_into().unwrap();
    let hash = bao::Hash::from(root_array);
    let cursor = Cursor::new(proof);
    let mut decoder = bao::decode::SliceDecoder::new(cursor, &hash, start, count);
    let mut output = Vec::with_capacity(count as usize);
    decoder.read_to_end(&mut output).map_err(io_error)?;
    let cursor = decoder.into_inner();
    if cursor.position() != proof.len() as u64 || output.len() != count as usize {
        return Err(PyValueError::new_err("non-canonical or short Bao slice"));
    }
    Ok(output)
}

#[pymodule]
fn tinyp2p_bao(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(prepare_file, module)?)?;
    module.add_function(wrap_pyfunction!(extract_slice, module)?)?;
    module.add_function(wrap_pyfunction!(decode_slice, module)?)?;
    Ok(())
}
