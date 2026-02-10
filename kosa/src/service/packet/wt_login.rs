#![allow(dead_code)]
use std::ops::Deref;

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use chrono::Utc;
use thiserror::Error;

use crate::{
    common::{AppInfo, Session},
    service::packet::tlv::{Tlv, TlvQrCode},
    utils::{
        binary::{Prefix, Reader, ReaderError, Writer},
        crypto::{ecdh::EcdhError, pow::generate_tlv548, tea},
    },
};

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("invalid packet header")]
    InvalidHeader,
    #[error("unknown encrypt type")]
    UnknownEncryptType,
    #[error("ecdh error: {0}")]
    Ecdh(#[from] EcdhError),
    #[error("reader error: {0}")]
    ReaderError(#[from] ReaderError),
}

#[repr(u8)]
#[derive(Debug, Clone)]
pub(crate) enum EncryptMethod {
    St = 0x45,
    Ecdh = 0x07,
    EcdhSt = 0x87,
}

/// fetch qrcode
pub(crate) fn build_trans_emp_31(
    unusual_sig: &[u8],
    qrcode_size: u32,
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let mut writer = Writer::with_capacity(1000);
    writer
        .write_u16(0)
        .write_u32(app_info.app_id as u32)
        .write_u64(0) // uin
        .write_bytes([]) // TGT
        .write_u8(0)
        .write_bytes_with_prefix(Prefix::U16, false, []);
    let mut tlvs = TlvQrCode::new(app_info, session);
    if !unusual_sig.is_empty() {
        tlvs.tlv11(unusual_sig);
    }
    tlvs.tlv16()
        .tlv1b(qrcode_size)
        .tlv1d()
        .tlv33()
        .tlv35()
        .tlv66()
        .tlvd1();
    writer.write_bytes(tlvs.pack());
    let body = writer.to_bytes();

    build_code2d_packet(
        0x31,
        body,
        EncryptMethod::EcdhSt,
        false,
        false,
        app_info,
        session,
    )
}

/// poll qrcode
pub(crate) fn build_trans_emp_12(qr_sig: &[u8], app_info: &AppInfo, session: &Session) -> Bytes {
    let mut writer = Writer::with_capacity(300);
    writer
        .write_u16(0)
        .write_u32(app_info.app_id as u32)
        .write_bytes_with_prefix(Prefix::U16, false, qr_sig)
        .write_u64(0) // uin
        .write_bytes([]) // tgt
        .write_u8(0)
        .write_bytes_with_prefix(Prefix::U16, false, [])
        .write_u16(0); // tlv count=0
    let body = writer.to_bytes();
    build_code2d_packet(
        0x12,
        body,
        EncryptMethod::EcdhSt,
        false,
        false,
        app_info,
        session,
    )
}

/// VerifyCode
pub(crate) fn build_qr_login_19(k: &[u8], app_info: &AppInfo, session: &Session) -> Bytes {
    let mut writer = Writer::with_capacity(300);
    writer
        .write_u16(0)
        .write_u32(app_info.app_id as u32)
        .write_u64(session.uin() as u64)
        .write_bytes_with_prefix(Prefix::U16, false, k) // code in java, k in qrcode url
        .write_bytes_with_prefix(
            Prefix::U16,
            false,
            session.wlogin_sigs.deref().load().a2.as_ref(),
        )
        .write_bytes(session.guid.as_ref())
        .write_u8(1)
        .write_u16(1)
        .write_u8(8);

    let tlv_types: [u16; _] = [0x03, 0x05, 0x20, 0x35, 0x36];
    writer.write_u16(tlv_types.len() as u16);
    tlv_types.iter().for_each(|tlv| {
        writer.write_u16(*tlv);
    });

    let mut tlvs = TlvQrCode::new(app_info, session);
    tlvs.tlv09().tlv12c().tlv39();

    writer.write_bytes(tlvs.pack());
    let body = writer.to_bytes();
    build_code2d_packet(0x13, body, EncryptMethod::St, true, true, app_info, session)
}

/// CloseCode
pub(crate) fn build_qr_login_20(k: &[u8], app_info: &AppInfo, session: &Session) -> Bytes {
    let mut writer = Writer::with_capacity(300);
    writer
        .write_u16(0)
        .write_u32(app_info.app_id as u32)
        .write_u64(session.uin() as u64)
        .write_bytes_with_prefix(Prefix::U16, false, k) // code in java, k in qrcode url
        .write_bytes_with_prefix(
            Prefix::U16,
            false,
            session.wlogin_sigs.deref().load().a2.as_ref(),
        )
        .write_u8(8);

    let mut tlvs = TlvQrCode::new(app_info, session);
    tlvs.tlv02()
        .tlv04()
        .tlv15()
        .tlv68()
        .tlv16()
        .tlv18()
        .tlv19()
        .tlv1d()
        .tlv12c();

    writer.write_bytes(tlvs.pack());

    let body = writer.to_bytes();
    build_code2d_packet(0x14, body, EncryptMethod::St, true, true, app_info, session)
}

pub(crate) fn build_qr_login_22(k: &[u8], app_info: &AppInfo, session: &Session) -> Bytes {
    let mut writer = Writer::with_capacity(300);
    writer
        .write_u16(0)
        .write_u32(app_info.app_id as u32)
        .write_bytes_with_prefix(Prefix::U16, false, k)
        .write_u64(session.uin() as u64)
        .write_u8(8)
        .write_u16(0);

    let mut tlvs = TlvQrCode::new(app_info, session);
    tlvs.tlv12c();

    writer.write_bytes(tlvs.pack());
    let body = writer.to_bytes();

    build_code2d_packet(0x16, body, EncryptMethod::St, true, true, app_info, session)
}

/// login packet
pub(crate) fn build_oicq_09(app_info: &AppInfo, session: &Session) -> Bytes {
    let mut tlvs = Tlv::new(0x09, app_info, session);
    tlvs.tlv106_encrypted_a1()
        .tlv144()
        .tlv116()
        .tlv142()
        .tlv145()
        .tlv018()
        .tlv141()
        .tlv177()
        .tlv191(0)
        .tlv100()
        .tlv107()
        .tlv318()
        .tlv16a()
        .tlv166()
        .tlv521();

    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::EcdhSt,
        false,
        app_info,
        session,
    )
}

/// login packet for Android with password
pub(crate) fn build_oicq_09_android(
    passwd: &str,
    energy: &[u8],
    attach: &[u8],
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let pow = generate_tlv548().unwrap_or_default();

    let mut tlvs = Tlv::new(0x09, app_info, session);

    tlvs.tlv018_android()
        .tlv001()
        .tlv106_pwd(passwd)
        .tlv116()
        .tlv100_android(app_info.sdk_info.main_sigmap.bits())
        .tlv107_android()
        .tlv142()
        .tlv144_report(false)
        .tlv145()
        .tlv147()
        .tlv154()
        .tlv141_android()
        .tlv008()
        .tlv511()
        .tlv187()
        .tlv188()
        .tlv191(0x82)
        .tlv177()
        .tlv516()
        .tlv521_android()
        .tlv525()
        .tlv544(energy)
        .tlv545()
        .tlv548(pow.as_ref())
        .tlv553(attach);

    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::EcdhSt,
        false,
        app_info,
        session,
    )
}

/// captcha submit packet
pub(crate) fn build_oicq_02_android(
    ticket: &str,
    energy: &[u8],
    attach: &[u8],
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let mut tlvs = Tlv::new(0x02, app_info, session);
    tlvs.tlv193(ticket.as_bytes()).tlv008();
    if !session.state.tlv104.is_empty() {
        tlvs.tlv104(session.state.tlv104.as_ref());
    };
    tlvs.tlv116();
    if !session.state.tlv104.is_empty() {
        tlvs.tlv547(session.state.tlv547.as_ref());
    };
    tlvs.tlv544(energy);
    tlvs.tlv553(attach);
    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::EcdhSt,
        false,
        app_info,
        session,
    )
}

/// email login packet
pub(crate) fn build_oicq_04_android(
    qid: &str,
    attach: &[u8],
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let pow = generate_tlv548().unwrap_or_default();

    let mut tlvs = Tlv::new(0x04, app_info, session);
    tlvs.tlv100()
        .tlv112(qid)
        .tlv107_android()
        .tlv154()
        .tlv008()
        .tlv553(attach)
        .tlv521_android()
        .tlv124_android()
        .tlv128()
        .tlv116()
        .tlv191(0x82)
        .tlv11b()
        .tlv52d()
        .tlv548(pow.as_ref());

    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::Ecdh,
        false,
        app_info,
        session,
    )
}

/// SMS verification packet
pub(crate) fn build_oicq_07_android(
    code: &str,
    energy: &[u8],
    attach: &[u8],
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let mut tlvs = Tlv::new(0x07, app_info, session);
    tlvs.tlv008();
    if !session.state.tlv104.is_empty() {
        tlvs.tlv104(session.state.tlv104.as_ref());
    };
    tlvs.tlv116();
    if !session.state.tlv174.is_empty() {
        tlvs.tlv174(session.state.tlv174.as_ref());
    };
    tlvs.tlv17c(code)
        .tlv401()
        .tlv198()
        .tlv544(energy)
        .tlv553(attach);
    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::EcdhSt,
        false,
        app_info,
        session,
    )
}

/// SMS request packet
pub(crate) fn build_oicq_08_android(attach: &[u8], app_info: &AppInfo, session: &Session) -> Bytes {
    let mut tlvs = Tlv::new(0x08, app_info, session);
    tlvs.tlv008();
    if !session.state.tlv104.is_empty() {
        tlvs.tlv104(session.state.tlv104.as_ref());
    };
    tlvs.tlv116();
    if !session.state.tlv174.is_empty() {
        tlvs.tlv174(session.state.tlv174.as_ref());
    };
    tlvs.tlv17a().tlv197().tlv553(attach);
    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::EcdhSt,
        false,
        app_info,
        session,
    )
}

/// token refresh packet
pub(crate) fn build_oicq_15_android(
    energy: &[u8],
    attach: &[u8],
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let mut tlvs = Tlv::new(0x0f, app_info, session);
    tlvs.tlv018_android()
        .tlv001()
        .tlv106_encrypted_a1()
        .tlv116()
        .tlv100_android(34607328)
        .tlv107_android()
        .tlv144_report(false)
        .tlv142()
        .tlv145()
        .tlv16a()
        .tlv154()
        .tlv141_android()
        .tlv008()
        .tlv511()
        .tlv147()
        .tlv177()
        .tlv400()
        .tlv187()
        .tlv188()
        .tlv516()
        .tlv521_android()
        .tlv525()
        .tlv544(energy)
        .tlv553(attach)
        .tlv545();

    build_packet(
        0x810,
        tlvs.pack(),
        EncryptMethod::EcdhSt,
        false,
        app_info,
        session,
    )
}

pub(crate) fn build_encrypt_head(w: &mut Writer, use_wt_session: bool, session: &Session) {
    let wlogin_sigs = session.wlogin_sigs.deref().load();
    if use_wt_session {
        w.write_bytes_with_prefix(Prefix::U16, false, wlogin_sigs.wt_session_ticket.as_ref());
    } else {
        w.write_u8(0x02)
            .write_u8(1)
            .write_bytes(wlogin_sigs.random_key.as_slice())
            .write_i16(305)
            .write_i16(1)
            .write_bytes_with_prefix(Prefix::U16, false, session.p256.public_key_bytes());
    };
}

pub(crate) fn build_packet(
    command: i16,
    payload: Bytes,
    encrypt_method: EncryptMethod,
    use_wt_session: bool,
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let wlogin_sigs = session.wlogin_sigs.deref().load();
    let key = match encrypt_method {
        EncryptMethod::St => {
            if use_wt_session {
                wlogin_sigs.wt_session_ticket_key
            } else {
                wlogin_sigs.random_key
            }
        }
        EncryptMethod::Ecdh | EncryptMethod::EcdhSt => session.p256.share_key_hash(),
    };
    let cipher = tea::encrypt(payload, &key);

    let mut writer = Writer::with_capacity(cipher.len() + 80);
    writer
        .write_u8(2)
        .write_with_prefix_add(Prefix::U16, true, 1, |w| {
            w.write_u16(8001) //version
                .write_i16(command)
                .write_i16(0)
                .write_u32(session.uin() as u32)
                .write_u8(3)
                .write_u8(encrypt_method as u8)
                .write_u8(0)
                .write_i32(2)
                .write_i32(app_info.app_client_version as i32)
                .write_i32(0);
            build_encrypt_head(w, use_wt_session, session);
            w.write_bytes(cipher).write_u8(3);
        });
    writer.to_bytes()
}

pub(crate) fn build_code2d_packet(
    command: i16,
    tlv: Bytes,
    encrypt_method: EncryptMethod,
    encrypt: bool,
    use_wt_session: bool,
    app_info: &AppInfo,
    session: &Session,
) -> Bytes {
    let wlogin_sigs = session.wlogin_sigs.deref().load();
    let mut writer = Writer::with_capacity(tlv.len() + 80);
    writer
        .write_u32(Utc::now().timestamp() as u32)
        .write_u8(2) // encryptMethod == EncryptMethod.EM_ST || encryptMethod == EncryptMethod.EM_ECDH_ST
        .write_with_prefix_add(Prefix::U16, true, 1, |w| {
            w.write_i16(command)
                .write_bytes([0u8; 21]) // skip 21 bytes
                .write_u8(3) // flag
                .write_u16(0) // close
                .write_u16(0x32) // Version Code: 50
                .write_u32(0) // trans_emp sequence
                .write_u64(session.uin() as u64)
                .write_bytes(tlv)
                .write_u8(3);
        });
    let req_body = writer.to_bytes();

    let req_span = if encrypt {
        tea::encrypt(req_body, &wlogin_sigs.st_key)
    } else {
        req_body
    };

    let mut writer = Writer::with_capacity(req_span.len() + 14);
    writer
        .write_u8(encrypt as u8)
        .write_u16(req_span.len() as u16)
        .write_u32(app_info.app_id as u32)
        .write_u32(0x72)
        .write_bytes_with_prefix(
            Prefix::U16,
            false,
            if encrypt {
                wlogin_sigs.st.as_ref()
            } else {
                &[]
            },
        )
        .write_bytes_with_prefix(Prefix::U8, false, []) // rollback
        .write_bytes(req_span);
    let body = writer.to_bytes();

    build_packet(
        0x812,
        body,
        encrypt_method,
        use_wt_session,
        app_info,
        session,
    )
}

pub(crate) fn parse(data: Bytes, session: &Session) -> Result<(u16, Bytes), ParseError> {
    if data.len() < 20 {
        return Err(ParseError::PacketTooShort);
    };

    let wlogin_sigs = session.wlogin_sigs.deref().load();

    let mut reader = Reader::new(data);
    let header = reader.read_u8()?;
    if header != 2 {
        return Err(ParseError::InvalidHeader);
    }

    let _length = reader.read_u16()?;
    let _version = reader.read_u16()?;
    let command = reader.read_u16()?;
    let _sequence = reader.read_u16()?;
    let _uin = reader.read_u32()?;
    let _flag = reader.read_u8()?;
    let encrypt_type = reader.read_u8()?;
    let state = reader.read_u8()?;

    let encrypted = reader.read_bytes(reader.len() - 1)?;

    let decrypt_data = match encrypt_type {
        0 => {
            let key = if state == 180 {
                wlogin_sigs.random_key
            } else {
                session.p256.share_key_hash()
            };
            tea::decrypt(encrypted, &key)
        }
        3 => {
            let key = wlogin_sigs.wt_session_ticket_key;
            tea::decrypt(encrypted, &key)
        }
        4 => {
            let raw = tea::decrypt(&encrypted, &session.p256.share_key_hash());
            let mut raw_reader = Reader::new(raw);
            let public_key = raw_reader.read_bytes_with_prefix(Prefix::U16, false)?;
            let key = session
                .p256
                .compute_shared_secret_hash(public_key.as_ref())?;
            let encrypted = raw_reader.read_bytes(raw_reader.len())?;
            tea::decrypt(encrypted, &key)
        }
        _ => return Err(ParseError::UnknownEncryptType),
    };
    Ok((command, decrypt_data))
}

pub(crate) fn parse_code2d_packet(
    data: Bytes,
    session: &Session,
) -> Result<(u16, Bytes), ParseError> {
    if data.len() < 5 {
        return Err(ParseError::PacketTooShort);
    }

    let encrypt = data[1];
    let layer = BigEndian::read_u16(&data[2..]);

    let span = if encrypt == 0 {
        data.slice(5..5 + layer as usize)
    } else {
        tea::decrypt(
            data.slice(5..5 + layer as usize),
            &session.wlogin_sigs.deref().load().st_key,
        )
    };

    let mut reader = Reader::new(span);

    let _header = reader.read_u8()?;
    let _length = reader.read_u16()?;
    let command = reader.read_u16()?;
    reader.skip(21)?;
    let _flag = reader.read_u8()?;
    let _retry_time = reader.read_u16()?;
    let _version = reader.read_u16()?;
    let _sequence = reader.read_u32()?;
    let _uin = reader.read_u64()?;

    Ok((command, reader.bytes()))
}
