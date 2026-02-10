use bytes::{BufMut, Bytes, BytesMut};

use crate::utils::binary::Prefix;

#[derive(Debug, Default)]
pub struct Writer {
    buffer: BytesMut,
}

impl AsMut<[u8]> for Writer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    pub fn to_bytes(self) -> Bytes {
        self.buffer.freeze()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.to_vec()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buffer.freeze().into()
    }

    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.reserve(size_of::<u8>());
        self.buffer.put_u8(value);
        self
    }

    pub fn write_i8(&mut self, value: i8) -> &mut Self {
        self.buffer.reserve(size_of::<i8>());
        self.buffer.put_i8(value);
        self
    }

    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.buffer.reserve(size_of::<u16>());
        self.buffer.put_u16(value);
        self
    }

    pub fn write_i16(&mut self, value: i16) -> &mut Self {
        self.buffer.reserve(size_of::<i16>());
        self.buffer.put_i16(value);
        self
    }

    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.reserve(size_of::<u32>());
        self.buffer.put_u32(value);
        self
    }

    pub fn write_i32(&mut self, value: i32) -> &mut Self {
        self.buffer.reserve(size_of::<i32>());
        self.buffer.put_i32(value);
        self
    }

    pub fn write_u64(&mut self, value: u64) -> &mut Self {
        self.buffer.reserve(size_of::<u64>());
        self.buffer.put_u64(value);
        self
    }

    pub fn write_i64(&mut self, value: i64) -> &mut Self {
        self.buffer.reserve(size_of::<i64>());
        self.buffer.put_i64(value);
        self
    }

    pub fn write_bytes(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        let data = data.as_ref();
        self.buffer.reserve(data.len());
        self.buffer.put_slice(data);
        self
    }

    pub fn skip(&mut self, len: usize) -> &mut Self {
        self.buffer.reserve(len);
        self.buffer.put_bytes(0, len);
        self
    }
    pub fn write_str(&mut self, value: impl AsRef<str>) -> &mut Self {
        self.write_bytes(value.as_ref());
        self
    }

    pub fn write_bytes_with_prefix(
        &mut self,
        p: Prefix,
        include_prefix: bool,
        data: impl AsRef<[u8]>,
    ) -> &mut Self {
        let data = data.as_ref();
        let mut length = data.len();
        if include_prefix {
            length += p.size();
        }

        match p {
            Prefix::U8 => self.write_u8(length as u8),
            Prefix::U16 => self.write_u16(length as u16),
            Prefix::U32 => self.write_u32(length as u32),
        };

        self.write_bytes(data)
    }

    pub fn write_str_with_prefix(
        &mut self,
        p: Prefix,
        include_prefix: bool,
        s: impl AsRef<str>,
    ) -> &mut Self {
        self.write_bytes_with_prefix(p, include_prefix, s.as_ref().as_bytes())
    }

    pub fn write_with_prefix_add<F>(
        &mut self,
        p: Prefix,
        include_prefix: bool,
        addition: usize,
        f: F,
    ) -> &mut Self
    where
        F: FnOnce(&mut Writer),
    {
        let prefix_size = p.size();
        if prefix_size == 0 {
            f(self);
            return self;
        };

        let barrier = self.buffer.len();
        match p {
            Prefix::U8 => self.write_u8(0),
            Prefix::U16 => self.write_u16(0),
            Prefix::U32 => self.write_u32(0),
        };

        f(self);

        let mut written = self.buffer.len() - barrier + addition;
        if !include_prefix {
            written -= prefix_size;
        };

        match p {
            Prefix::U8 => {
                debug_assert!(written <= u8::MAX as usize);
                self.buffer[barrier] = written as u8;
            }
            Prefix::U16 => {
                debug_assert!(written <= u16::MAX as usize);
                self.buffer[barrier..barrier + 2].copy_from_slice(&(written as u16).to_be_bytes());
            }
            Prefix::U32 => {
                debug_assert!(written <= u32::MAX as usize);
                self.buffer[barrier..barrier + 4].copy_from_slice(&(written as u32).to_be_bytes());
            }
        }

        self
    }

    pub fn write_with_prefix<F>(&mut self, p: Prefix, include_prefix: bool, f: F) -> &mut Self
    where
        F: FnOnce(&mut Writer),
    {
        self.write_with_prefix_add(p, include_prefix, 0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_and_bytes_are_big_endian() {
        let mut w = Writer::new();
        w.write_u8(0xAB)
            .write_i8(-2)
            .write_u16(0x0123)
            .write_i16(-2)
            .write_u32(0x01020304)
            .write_i32(-2)
            .write_u64(0x0102030405060708)
            .write_i64(-2)
            .write_bytes([0xDE, 0xAD]);

        let got = w.to_vec();
        let mut expect = Vec::new();
        expect.extend_from_slice(&[0xAB]);
        expect.extend_from_slice(&(-2i8).to_be_bytes());
        expect.extend_from_slice(&0x0123u16.to_be_bytes());
        expect.extend_from_slice(&(-2i16).to_be_bytes());
        expect.extend_from_slice(&0x01020304u32.to_be_bytes());
        expect.extend_from_slice(&(-2i32).to_be_bytes());
        expect.extend_from_slice(&0x0102030405060708u64.to_be_bytes());
        expect.extend_from_slice(&(-2i64).to_be_bytes());
        expect.extend_from_slice(&[0xDE, 0xAD]);

        assert_eq!(got, expect);
    }

    #[test]
    fn bytes_with_prefix_include_prefix_true() {
        let mut w = Writer::new();
        w.write_bytes_with_prefix(Prefix::U16, true, b"hey");

        // length includes prefix size (2) + payload (3) = 5
        assert_eq!(w.to_vec(), [0x00, 0x05, b'h', b'e', b'y']);
    }

    #[test]
    fn bytes_with_prefix_include_prefix_false() {
        let mut w = Writer::new();
        w.write_bytes_with_prefix(Prefix::U16, false, b"hey");

        // length excludes prefix size, so it's just payload (3)
        assert_eq!(w.to_vec(), [0x00, 0x03, b'h', b'e', b'y']);
    }

    #[test]
    fn write_with_prefix_backfills_value() {
        let mut w = Writer::new();
        w.write_with_prefix(Prefix::U16, false, |w| {
            w.write_u8(0x11).write_u8(0x22).write_u8(0x33);
        });

        // prefix should be 3 (payload only), then payload bytes
        assert_eq!(w.to_vec(), [0x00, 0x03, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn write_with_prefix_add_accounts_for_addition_and_include_prefix() {
        let mut w = Writer::new();
        w.write_with_prefix_add(Prefix::U8, true, 2, |w| {
            w.write_bytes([1u8, 2, 3]);
        });

        // prefix includes prefix (1) + payload (3) + addition (2) = 6
        assert_eq!(w.to_vec(), [6u8, 1, 2, 3]);
    }

    #[test]
    fn write_str_writes_utf8_bytes() {
        let mut w = Writer::new();
        w.write_str("hi");
        assert_eq!(w.to_vec(), [b'h', b'i']);
    }
}
