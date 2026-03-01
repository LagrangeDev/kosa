use digest::{Digest, common::hazmat::SerializableState};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek};

pub trait AsyncReadSeek: AsyncRead + AsyncSeek + Send + Unpin {}
impl<T: AsyncRead + AsyncSeek + Send + Unpin> AsyncReadSeek for T {}
pub type AsyncStream = Box<dyn AsyncReadSeek + Send + Sync>;

#[macro_export]
macro_rules! stream_hash {
    ($stream:expr, $($hasher:ident),*) => {{
        use std::io::SeekFrom;
        use digest::Digest;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let mut buffer = [0u8; 1024*8];
        let mut total_size = 0;
        loop {
            let count = $stream.read(&mut buffer).await?;
            if count == 0 { break; }
            let chunk = &buffer[..count];
            $( $hasher.update(chunk); )*
            total_size += count
        }
        $stream.seek(SeekFrom::Start(0)).await?;
        (total_size, $( $hasher.finalize() ),*)
    }};
}

pub async fn sha1_stream<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> anyhow::Result<(Vec<Vec<u8>>, [u8; 20])> {
    const BLOCK_SIZE: usize = 1024 * 1024;
    let mut sha1_hasher = Sha1::new();
    let mut sha1_states: Vec<Vec<u8>> = Vec::new();
    let mut buffer = Vec::with_capacity(BLOCK_SIZE);
    loop {
        buffer.clear();
        let n = stream
            .take(BLOCK_SIZE as u64)
            .read_to_end(&mut buffer)
            .await?;
        if n == 0 {
            break;
        }
        sha1_hasher.update(&buffer);
        if n == BLOCK_SIZE {
            sha1_states.push(sha1_hasher.serialize()[..20].to_vec());
        } else {
            break;
        }
    }
    let final_hash = sha1_hasher.finalize().into();
    Ok((sha1_states, final_hash))
}
