use std::{io, io::Write};

use bytes::{BufMut, Bytes, BytesMut};
use flate2::{
    Compression,
    write::{GzDecoder, GzEncoder, ZlibDecoder, ZlibEncoder},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompressError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub fn zlib_compress<T: AsRef<[u8]>>(data: T) -> Result<Bytes, CompressError> {
    let data = data.as_ref();
    let compressed_data = BytesMut::with_capacity(data.len() / 2);
    let mut encoder = ZlibEncoder::new(compressed_data.writer(), Compression::default());
    encoder.write_all(data)?;
    let writer = encoder.finish()?;
    Ok(writer.into_inner().freeze())
}

pub fn zlib_uncompress<T: AsRef<[u8]>>(data: T) -> Result<Bytes, CompressError> {
    let data = data.as_ref();
    let decompressed_data = BytesMut::with_capacity(data.len() * 2);
    let mut decoder = ZlibDecoder::new(decompressed_data.writer());
    decoder.write_all(data)?;
    let writer = decoder.finish()?;
    Ok(writer.into_inner().freeze())
}

pub fn gzip_compress<T: AsRef<[u8]>>(data: T) -> Result<Bytes, CompressError> {
    let data = data.as_ref();
    let compressed_data = BytesMut::with_capacity(data.len() / 2);
    let mut encoder = GzEncoder::new(compressed_data.writer(), Compression::default());
    encoder.write_all(data)?;
    let writer = encoder.finish()?;
    Ok(writer.into_inner().freeze())
}

pub fn gzip_uncompress<T: AsRef<[u8]>>(data: T) -> Result<Bytes, CompressError> {
    let data = data.as_ref();
    let decompressed_data = BytesMut::with_capacity(data.len() * 2);
    let mut decoder = GzDecoder::new(decompressed_data.writer());
    decoder.write_all(data)?;
    let writer = decoder.finish()?;
    Ok(writer.into_inner().freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deflate_and_inflate() {
        let original_data = b"This is a test string that will be compressed and then decompressed.";
        let compressed = zlib_compress(original_data).unwrap();
        let decompressed = zlib_uncompress(&compressed).unwrap();
        assert_eq!(decompressed, original_data.to_vec());
    }

    #[test]
    fn test_empty_data() {
        let original_data = b"";
        let compressed = zlib_compress(original_data).unwrap();
        let decompressed = zlib_uncompress(&compressed).unwrap();
        assert_eq!(decompressed, original_data.to_vec());
    }
}
