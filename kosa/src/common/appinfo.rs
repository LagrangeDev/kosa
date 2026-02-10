use bitflags::bitflags;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub os: String,
    pub vendor_os: String,
    pub kernel: String,
    pub current_version: String,
    pub pt_version: String,
    pub sso_version: i32,
    pub package_name: String,
    pub apk_signature_md5: Bytes,
    pub sdk_info: WtLoginSdkInfo,
    pub app_id: i32,
    pub sub_app_id: i32,
    pub app_client_version: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WtLoginSdkInfo {
    pub sdk_build_time: u32,
    pub sdk_version: String,
    pub misc_bitmap: u32,
    pub sub_sigmap: u32,
    pub main_sigmap: Sig,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Sig: u32 {
        const WLOGIN_A5        = 1 << 1;
        const WLOGIN_RESERVED  = 1 << 4;
        const WLOGIN_ST_WEB    = 1 << 5;
        const WLOGIN_A2        = 1 << 6;
        const WLOGIN_ST        = 1 << 7;
        const WLOGIN_LS_KEY    = 1 << 9;
        const WLOGIN_S_KEY     = 1 << 12;
        const WLOGIN_SIG64     = 1 << 13;
        const WLOGIN_OPEN_KEY  = 1 << 14;
        const WLOGIN_TOKEN     = 1 << 15;
        const WLOGIN_V_KEY     = 1 << 17;
        const WLOGIN_D2        = 1 << 18;
        const WLOGIN_SID       = 1 << 19;
        const WLOGIN_PS_KEY    = 1 << 20;
        const WLOGIN_AQ_SIG    = 1 << 21;
        const WLOGIN_LH_SIG    = 1 << 22;
        const WLOGIN_PAY_TOKEN = 1 << 23;
        const WLOGIN_PF        = 1 << 24;
        const WLOGIN_DA2       = 1 << 25;
        const WLOGIN_QR_PUSH   = 1 << 26;
        const WLOGIN_PT4_TOKEN = 1 << 27;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Protocol: u8 {
        const WINDOWS        = 0b0000_0001;
        const MACOS          = 0b0000_0010;
        const LINUX          = 0b0000_0100;
        const ANDROID_PHONE  = 0b0000_1000;
        const ANDROID_PAD    = 0b0001_0000;
        const ANDROID_WATCH  = 0b0010_0000;

        const PC      = Self::WINDOWS.bits() | Self::MACOS.bits() | Self::LINUX.bits();
        const ANDROID = Self::ANDROID_PHONE.bits() | Self::ANDROID_PAD.bits() | Self::ANDROID_WATCH.bits();
    }
}
