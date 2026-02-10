use bytes::Bytes;
use kosa_proto::common::v2::{SsoReserveFields, SsoSecureInfo};
use prost::Message;
use thiserror::Error;

use crate::{
    common::{AppInfo, Protocol, Session},
    service::{EncryptType, Metadata, RequestType},
    utils::{
        binary::{Prefix, Reader, ReaderError, Writer},
        compress::{CompressError, zlib_uncompress},
        crypto::tea,
        random_hex_string,
    },
};

const EMPTY_D2KEY: [u8; 16] = [0; 16];

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("{0}")]
    CompressError(#[from] CompressError),
    #[error("{0}")]
    ReaderError(#[from] ReaderError),
    #[error("unknown auth flag: {0}")]
    UnkownAuthFlag(u8),
    #[error("unknown data flag: {0}")]
    UnkownDataFlag(u32),
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SsoPacket {
    pub(crate) command: String,
    pub(crate) data: Bytes,
    pub(crate) sequence: i32,
    pub(crate) _ret_code: i32,
    pub(crate) _extra: String,
}

impl SsoPacket {
    pub(crate) fn encode(
        &self,
        metadata: &Metadata,
        app_info: &AppInfo,
        session: &Session,
        sso_secure_info: Option<SsoSecureInfo>,
    ) -> Bytes {
        let mut writer = Writer::new();
        match metadata.request_type {
            RequestType::D2Auth => {
                writer.write_with_prefix(Prefix::U32, true, |w| {
                    w.write_u32(self.sequence as u32)
                        .write_u32(app_info.sub_app_id as u32)
                        .write_u32(2052)
                        .write_bytes([
                            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ])
                        .write_bytes_with_prefix(
                            Prefix::U32,
                            true,
                            session.wlogin_sigs.load().a2.as_ref(),
                        )
                        .write_str_with_prefix(Prefix::U32, true, self.command.as_str())
                        .write_u32(4)
                        .write_str_with_prefix(Prefix::U32, true, hex::encode(session.guid))
                        .write_u32(4)
                        .write_str_with_prefix(
                            Prefix::U16,
                            true,
                            app_info.current_version.as_str(),
                        );
                    Self::write_sso_reserved_field(w, metadata, session, sso_secure_info);
                });
                writer.write_bytes_with_prefix(Prefix::U32, true, self.data.as_ref());
            }
            RequestType::Simple => {
                writer.write_with_prefix(Prefix::U32, true, |w| {
                    w.write_str_with_prefix(Prefix::U32, true, self.command.as_str())
                        .write_u32(4);
                    Self::write_sso_reserved_field(w, metadata, session, sso_secure_info);
                });
                writer.write_bytes_with_prefix(Prefix::U32, true, self.data.as_ref());
            }
        };

        let sso_frame = writer.to_bytes();

        let cipher = match metadata.encrypt_type {
            EncryptType::None => sso_frame,
            EncryptType::D2 => tea::encrypt(sso_frame, &session.wlogin_sigs.load().d2_key),
            EncryptType::Empty => tea::encrypt(sso_frame, &EMPTY_D2KEY),
        };

        let mut writer = Writer::new();
        match metadata.request_type {
            RequestType::D2Auth => {
                writer.write_u32(12).write_u8(metadata.encrypt_type as u8);
                if metadata.encrypt_type == EncryptType::D2 {
                    writer.write_bytes_with_prefix(
                        Prefix::U32,
                        true,
                        session.wlogin_sigs.load().d2.as_ref(),
                    );
                } else {
                    writer.write_u32(4);
                }
            }
            RequestType::Simple => {
                writer
                    .write_u32(13)
                    .write_u8(metadata.encrypt_type as u8)
                    .write_u32(self.sequence as u32);
            }
        };
        writer
            .write_u8(0)
            .write_str_with_prefix(Prefix::U32, true, session.uin().to_string())
            .write_bytes(cipher);
        writer.to_bytes()
    }

    pub(crate) fn decode(data: Bytes, session: &Session) -> Result<SsoPacket, DecodeError> {
        let mut reader = Reader::new(data);
        let _ = reader.read_u32()?; // length
        let _ = reader.read_u32()?; // protocol
        let auth_flag = reader.read_u8()?; // flag
        let _ = reader.read_u8()?; // dummy
        let _ = reader.read_string_with_prefix(Prefix::U32, true); // uin

        let encrypted = reader.bytes();

        let decrypted = match EncryptType::from_repr(auth_flag) {
            Some(EncryptType::None) => encrypted,
            Some(EncryptType::Empty) => tea::decrypt(encrypted, &EMPTY_D2KEY),
            Some(EncryptType::D2) => tea::decrypt(encrypted, &session.wlogin_sigs.load().d2_key),
            None => {
                return Err(DecodeError::UnkownAuthFlag(auth_flag));
            }
        };

        let mut sso_reader = Reader::new(decrypted);
        let head = sso_reader.read_bytes_with_prefix(Prefix::U32, true)?;
        let body = sso_reader.read_bytes_with_prefix(Prefix::U32, true)?;

        let mut head_reader = Reader::new(head);
        let sequence = head_reader.read_i32()?;
        let _ret_code = head_reader.read_i32()?;
        let _extra = head_reader.read_string_with_prefix(Prefix::U32, true)?;
        let command = head_reader.read_string_with_prefix(Prefix::U32, true)?;
        let _ = head_reader.read_bytes_with_prefix(Prefix::U32, true)?; // msg cookie
        let data_flag = head_reader.read_u32()?;
        let _ = head_reader.read_bytes_with_prefix(Prefix::U32, true)?; // reserved

        let data = match data_flag {
            0 | 4 => body,
            1 => zlib_uncompress(body)?,
            _ => return Err(DecodeError::UnkownDataFlag(data_flag)),
        };

        Ok(SsoPacket {
            command,
            data,
            sequence,
            _ret_code,
            _extra,
        })
    }

    pub(crate) fn write_sso_reserved_field(
        writer: &mut Writer,
        metadata: &Metadata,
        session: &Session,
        sso_secure_info: Option<SsoSecureInfo>,
    ) {
        let mut reserved = SsoReserveFields {
            trace_parent: Self::generate_trace_parent(),
            uid: session.uid(),
            sec_info: sso_secure_info,
            ..Default::default()
        };

        if Protocol::ANDROID.contains(metadata.support_protocols) {
            reserved.msg_type = Some(32);
            reserved.nt_core_version = Some(100);
        }

        let data = reserved.encode_to_vec();
        // writer.write_u32(4);
        writer.write_bytes_with_prefix(Prefix::U32, true, data);
    }

    pub(crate) fn generate_trace_parent() -> String {
        format!("01-{}-{}-01", random_hex_string(16), random_hex_string(8))
    }
}
