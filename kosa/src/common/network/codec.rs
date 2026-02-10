use actix::Message;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub(crate) struct Packet(pub(crate) Bytes);

#[derive(Debug)]
pub(crate) struct LengthCodec;

impl Encoder<Packet> for LengthCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = item.0;
        let len = 4 + data.len();
        dst.reserve(len);
        dst.put_u32(len as u32);
        dst.put_slice(data.as_ref());
        Ok(())
    }
}

impl Decoder for LengthCodec {
    type Item = Packet;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let length = BigEndian::read_u32(src) as usize;
        if length < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too short frame length",
            ));
        } else if length > 1024 * 1024 * 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too big frame length",
            ));
        }

        if src.len() < length {
            return Ok(None);
        }
        let data = src.split_to(length).freeze();
        Ok(Some(Packet(data)))
    }
}
