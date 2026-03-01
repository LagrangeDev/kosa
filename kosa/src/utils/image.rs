use std::{
    fmt::{Display, Formatter},
    io::SeekFrom,
};

use imagesize::{ImageSize, ImageType};
use strum::FromRepr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

pub async fn decode<R: AsyncRead + AsyncSeek + Unpin>(
    stream: &mut R,
) -> anyhow::Result<(Format, ImageSize)> {
    let mut buffer = Vec::with_capacity(1024);
    stream.take(1024).read_to_end(&mut buffer).await?;
    stream.seek(SeekFrom::Start(0)).await?;

    let format: Format =
        imagesize::image_type(buffer.as_slice()).map_or_else(|_| Format::UnKnown, |t| t.into());
    let size = imagesize::blob_size(buffer.as_slice()).unwrap_or(ImageSize {
        width: 720,
        height: 1080,
    });
    Ok((format, size))
}

#[derive(Default, Debug, Copy, Clone, FromRepr)]
#[repr(u32)]
pub enum Format {
    #[default]
    UnKnown = 0,
    Jpeg = 1000,
    Png = 1001,
    Webp = 1002,
    Jpeg2000 = 1003,
    Bmp = 1005,
    Tiff = 1006,
    Gif = 2000,
}

impl From<ImageType> for Format {
    fn from(image_type: ImageType) -> Self {
        match image_type {
            ImageType::Jpeg => Self::Jpeg,
            ImageType::Png => Self::Png,
            ImageType::Webp => Self::Webp,
            ImageType::Bmp => Self::Bmp,
            ImageType::Tiff => Self::Tiff,
            ImageType::Gif => Self::Gif,
            _ => Self::UnKnown,
        }
    }
}

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Format::UnKnown => {
                    "unknown"
                }
                Format::Jpeg => {
                    "jpg"
                }
                Format::Png => {
                    "png"
                }
                Format::Webp => {
                    "webp"
                }
                Format::Jpeg2000 => {
                    "jpg"
                }
                Format::Bmp => {
                    "bmp"
                }
                Format::Tiff => {
                    "tiff"
                }
                Format::Gif => {
                    "gif"
                }
            }
        )
    }
}
