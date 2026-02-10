mod reader;
mod writer;

pub use reader::{Reader, ReaderError};
pub use writer::Writer;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Prefix {
    U8,
    U16,
    U32,
}

impl Prefix {
    pub const fn size(self) -> usize {
        match self {
            Prefix::U8 => 1,
            Prefix::U16 => 2,
            Prefix::U32 => 4,
        }
    }
}
