use ahash::AHashMap;
use bytes::Bytes;
use kosa_macros::{ServiceState, command, register_service};
use kosa_proto::system::v2::ThirdPartyLoginResponse;
use prost::Message;
use strum::FromRepr;

use crate::{
    common::{AppInfo, Bot, Protocol, Session},
    event::SessionUpdated,
    service::{
        EncryptType, Metadata, RequestType, Service, ServiceContext,
        packet::{tlv::decode_tlv, wt_login},
    },
    utils::{
        binary::{Prefix, Reader},
        crypto::tea,
    },
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, FromRepr)]
#[repr(u8)]
pub enum LoginState {
    Success = 0,
    CaptchaVerify = 2,
    SmsRequired = 160,
    DeviceLock = 204,
    DeviceLockViaSmsNewArea = 239,
    PreventByIncorrectPassword = 1,
    PreventByReceiveIssue = 3,
    PreventByTokenExpired = 15,
    PreventByAccountBanned = 40,
    PreventByOperationTimeout = 155,
    PreventBySmsSentFailed = 162,
    PreventByIncorrectSmsCode = 163,
    PreventByLoginDenied = 167,
    PreventByOutdatedVersion = 235,
    PreventByHighRiskOfEnvironment = 237,
    Unknown = 240,
}

#[command("wtlogin.login")]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct LoginService;

#[derive(Debug, Clone)]
pub(crate) enum LoginReq {
    Qrcode,
    Tgtgt { password: String },
    Captcha { ticket: String },
    FetchSmsCode,
    SubmitSmsCode { code: String },
}

#[derive(Debug, Clone)]
pub(crate) struct LoginResp {
    pub(crate) ret_code: u8,
    pub(crate) state: LoginState,
    pub(crate) tlvs: AHashMap<u16, Bytes>,
}

#[register_service]
impl Service<LoginReq, LoginResp> for LoginService {
    const METADATA: Metadata = Metadata {
        encrypt_type: EncryptType::Empty,
        request_type: RequestType::D2Auth,
        support_protocols: Protocol::all(),
    };

    fn build(
        _state: &Self,
        req: LoginReq,
        app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<Bytes> {
        let data = match (req, app_info.protocol) {
            (LoginReq::Qrcode, protocol) if Protocol::PC.contains(protocol) => {
                wt_login::build_oicq_09(app_info, session)
            }
            (LoginReq::Tgtgt { password }, protocol) if Protocol::ANDROID.contains(protocol) => {
                wt_login::build_oicq_09_android(password.as_str(), &[], &[], app_info, session)
            }
            (LoginReq::Captcha { ticket }, protocol) if Protocol::ANDROID.contains(protocol) => {
                wt_login::build_oicq_02_android(ticket.as_str(), &[], &[], app_info, session)
            }
            _ => unimplemented!(),
        };
        Ok(data)
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        session: &Session,
    ) -> anyhow::Result<LoginResp> {
        let (cmd, data) = wt_login::parse(data, session)?;
        if cmd != 0x810 {
            anyhow::bail!("unexpected command in login response")
        }

        let mut reader = Reader::new(data);
        let _ = reader.read_u16()?; // internal cmd
        let state = reader.read_u8()?;
        let mut tlvs = decode_tlv(&mut reader)?;

        if let Some(error_tlv) = tlvs.get(&0x146).cloned() {
            let mut err_reader = Reader::new(error_tlv);
            let _ = err_reader.read_u32()?;
            let title = err_reader.read_string_with_prefix(Prefix::U16, false)?;
            let message = err_reader.read_string_with_prefix(Prefix::U16, false)?;
            anyhow::bail!("login failed: {}:{}", title, message);
        };

        if let Some(tgtgt) = tlvs.get(&0x119).cloned() {
            let decrypted = tea::decrypt(tgtgt, &session.wlogin_sigs.load().tgtgt_key);
            let mut tlv_reader = Reader::new(decrypted);
            let tlv119s = decode_tlv(&mut tlv_reader)?;
            for (k, v) in tlv119s {
                tlvs.insert(k, v);
            }
        };

        Ok(LoginResp {
            ret_code: state,
            state: LoginState::from_repr(state)
                .ok_or_else(|| anyhow::anyhow!("unexpected state in login response"))?,
            tlvs,
        })
    }
}

impl ServiceContext {
    pub(crate) async fn qrcode_login(&self) -> anyhow::Result<LoginResp> {
        self.send_request::<LoginService, LoginReq, LoginResp>(LoginReq::Qrcode)
            .await
    }
}

impl Bot {
    pub async fn qrcode_login(&self) -> anyhow::Result<()> {
        let mut resp = self.service.qrcode_login().await?;

        // todo 判断retcode

        let bot_info_data = resp.tlvs.remove(&0x11A);
        let login_resp_data = resp.tlvs.remove(&0x543);

        self.session.update_bot_info(|info| {
            if let Some(data) = &bot_info_data {
                let mut reader = Reader::new(data.clone());
                let _face_id = reader.read_u16()?;
                info.age = reader.read_u8()?;
                info.gender = reader.read_u8()?;
                info.name = reader.read_string_with_prefix(Prefix::U8, false)?;
            }
            if let Some(data) = &login_resp_data {
                let resp = ThirdPartyLoginResponse::decode(data.clone())?;
                info.uid = resp
                    .common_info
                    .unwrap_or_default()
                    .rsp_nt
                    .unwrap_or_default()
                    .uid
                    .unwrap_or_default()
                    .to_owned();
            };
            Ok(())
        })?;

        self.session.update_wlogin_sigs(|sigs| {
            for (code, value) in &resp.tlvs {
                match code {
                    0x103 => sigs.st_web = value.clone(),
                    0x143 => sigs.d2 = value.clone(),
                    0x108 => sigs.ksid = value.clone(),
                    0x10A => sigs.a2 = value.clone(),
                    0x10C => sigs.a1_key = value.as_ref().try_into()?,
                    0x10D => sigs.a2_key = value.as_ref().try_into()?,
                    0x10E => sigs.st_key = value.as_ref().try_into()?,
                    0x114 => sigs.st = value.clone(),
                    0x120 => sigs.s_key = value.clone(),
                    0x133 => sigs.wt_session_ticket = value.clone(),
                    0x134 => sigs.wt_session_ticket_key = value.as_ref().try_into()?,
                    0x305 => sigs.d2_key = value.as_ref().try_into()?,
                    0x106 => sigs.a1 = value.clone(),
                    0x16A => sigs.no_pic_sig = value.clone(),
                    0x16D => sigs.super_key = value.clone(),
                    0x512 => {
                        let mut reader = Reader::new(value.clone());
                        let domain_count = reader.read_i16()?;
                        for _ in 0..domain_count {
                            let domain = reader.read_string_with_prefix(Prefix::U16, false)?;
                            let key = reader.read_string_with_prefix(Prefix::U16, false)?;
                            let _pt4_token = reader.read_string_with_prefix(Prefix::U16, false)?;
                            sigs.ps_key.insert(domain, key);
                        }
                    }
                    _ => {}
                };
            }
            Ok(())
        })?;

        self.event.issue_async(SessionUpdated {
            session: self.session.clone(),
        });
        Ok(())
    }
}
