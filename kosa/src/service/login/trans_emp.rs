use bytes::Bytes;
use kosa_macros::command;
use kosa_proto::login::v2::QrExtInfo;
use prost::Message;
use strum::FromRepr;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    service::{
        EncryptType, Metadata, RequestType, ServiceContext, ServiceRequest,
        packet::{
            tlv::decode_tlv,
            wt_login::{build_trans_emp_12, build_trans_emp_31, parse, parse_code2d_packet},
        },
    },
    utils::binary::{Prefix, Reader},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, FromRepr)]
#[repr(u8)]
pub enum QrcodeState {
    Confirmed = 0,
    CodeExpired = 17,
    WaitingForScan = 48,
    WaitingConfirm = 53,
    Canceled = 54,
    Invalid = 144,
}

#[command("wtlogin.trans_emp")]
pub(crate) struct TransEmpReq12 {
    qr_sig: Bytes,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TransEmpResp12 {
    pub(crate) state: u8,
    pub(crate) uin: i64,
    pub(crate) tgtgkey: [u8; 16],
    pub(crate) no_pic_sig: Bytes,
    pub(crate) temp_passwd: Bytes,
}

impl ServiceRequest for TransEmpReq12 {
    type Response = TransEmpResp12;
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::Empty,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::from_bits_retain(
            Protocol::PC.bits() | Protocol::ANDROID_PHONE.bits(),
        ),
    };

    fn encode(req: Self, app_info: &AppInfo, session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_trans_emp_12(req.qr_sig.as_ref(), app_info, session))
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let (_, wtlogin_data) = parse(data, session)?;
        let (command, trans_emp_data) = parse_code2d_packet(wtlogin_data, session)?;

        let mut reader = Reader::new(trans_emp_data);
        let _ = reader.read_u16()?; // dummy
        let _ = reader.read_u32()?; // appid
        let ret_code = reader.read_u8()?;

        if command != 0x12 {
            return Err(anyhow::anyhow!("command not 0x12"));
        };

        let resp = if ret_code != 0 {
            TransEmpResp12 {
                state: ret_code,
                uin: 0,
                tgtgkey: Default::default(),
                no_pic_sig: Default::default(),
                temp_passwd: Default::default(),
            }
        } else {
            let uin = reader.read_i64()?;
            let _ = reader.read_u32()?; // retry
            let mut tlvs = decode_tlv(&mut reader)?;
            TransEmpResp12 {
                state: ret_code,
                uin,
                tgtgkey: tlvs.remove(&0x1E).unwrap_or_default().as_ref().try_into()?,
                no_pic_sig: tlvs.remove(&0x19).unwrap_or_default(),
                temp_passwd: tlvs.remove(&0x18).unwrap_or_default(),
            }
        };
        Ok(resp)
    }
}

#[command("wtlogin.trans_emp")]
#[derive(Debug, Clone, Default)]
pub(crate) struct TransEmpReq31 {
    pub(crate) qrcode_size: u32,
    pub(crate) unusual_sig: Bytes,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TransEmpResp31 {
    pub(crate) qr_sig: Bytes,
    pub(crate) url: String,
    pub(crate) image: Bytes,
}

impl ServiceRequest for TransEmpReq31 {
    type Response = TransEmpResp31;
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::Empty,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::from_bits_retain(
            Protocol::PC.bits() | Protocol::ANDROID_PHONE.bits(),
        ),
    };

    fn encode(req: Self, app_info: &AppInfo, session: &Session) -> anyhow::Result<Bytes> {
        Ok(build_trans_emp_31(
            req.unusual_sig.as_ref(),
            req.qrcode_size,
            app_info,
            session,
        ))
    }

    fn decode(
        data: Bytes,
        _app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Self::Response> {
        let (_, wtlogin_data) = parse(data, session)?;
        let (command, trans_emp_data) = parse_code2d_packet(wtlogin_data, session)?;

        let mut reader = Reader::new(trans_emp_data);
        let _ = reader.read_u16()?; // dummy
        let _ = reader.read_u32()?; // appid
        let _ = reader.read_u8()?; // ret code

        if command != 0x31 {
            return Err(anyhow::anyhow!("command not 0x31"));
        };

        let qr_sig = reader.read_bytes_with_prefix(Prefix::U16, false)?;
        let mut tlvs = decode_tlv(&mut reader)?;
        let url = QrExtInfo::decode(tlvs.remove(&0xD1).unwrap_or_default())?
            .qr_url
            .unwrap_or_default();

        let image = tlvs.remove(&0x17).unwrap_or_default();

        Ok(TransEmpResp31 { qr_sig, url, image })
    }
}

impl ServiceContext {
    pub(crate) async fn fetch_qrcode(
        &self,
        qrcode_size: u32,
    ) -> anyhow::Result<(Bytes, String, Bytes)> {
        let req = TransEmpReq31 {
            qrcode_size,
            unusual_sig: Bytes::default(),
        };
        let resp = self.send_request(req).await?;
        Ok((resp.qr_sig, resp.url, resp.image))
    }

    pub async fn get_qrcode_result(&self, qr_sig: Bytes) -> anyhow::Result<QrcodeState> {
        let req = TransEmpReq12 { qr_sig };
        let resp = self.send_request(req).await?;

        let state = QrcodeState::from_repr(resp.state)
            .ok_or_else(|| anyhow::anyhow!("unknown state code {}", resp.state))?;
        if state == QrcodeState::Confirmed {
            self.session.update_wlogin_sigs(|w| {
                w.tgtgt_key = resp.tgtgkey;
                w.no_pic_sig = resp.no_pic_sig.clone();
                w.a1 = resp.temp_passwd.clone();
                Ok(())
            })?;
            self.session.update_bot_info(|b| {
                b.uin = resp.uin;
                Ok(())
            })?
        };
        Ok(state)
    }
}

impl Bot {
    pub async fn fetch_qrcode(&self, qrcode_size: u32) -> anyhow::Result<(Bytes, String, Bytes)> {
        self.service.fetch_qrcode(qrcode_size).await
    }

    pub async fn get_qrcode_result(&self, qr_sig: Bytes) -> anyhow::Result<QrcodeState> {
        self.service.get_qrcode_result(qr_sig).await
    }
}
