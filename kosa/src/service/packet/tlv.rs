use std::ops::Deref;

use ahash::AHashMap;
use byteorder::{BigEndian, ByteOrder};
use chrono::Utc;
use kosa_macros::tlv;
use kosa_proto::login::v2::{DevInfo, DeviceReport, GenInfo, QrExtInfo, ScanExtInfo};
use md5::{Digest, Md5};
use prost::{Message, bytes::Bytes};

use crate::{
    common::{AppInfo, Session},
    utils::{
        binary::{Prefix, Reader, ReaderError, Writer},
        crypto::tea,
    },
};

pub(crate) struct Tlv<'a> {
    writer: Writer,
    perfixed: bool,
    count: usize,

    app_info: &'a AppInfo,
    session: &'a Session,
}

impl<'a> Tlv<'a> {
    pub(crate) fn new(command: i16, app_info: &'a AppInfo, session: &'a Session) -> Self {
        let mut writer = Writer::with_capacity(1024);
        let mut perfixed = false;
        if command > 0 {
            writer.write_i16(command);
            perfixed = true;
        }
        writer.skip(2);

        Tlv {
            writer,
            perfixed,
            count: 0,
            app_info,
            session,
        }
    }

    pub(crate) fn pack(mut self) -> Bytes {
        let buf = self.writer.as_mut();
        let count_offset = if self.perfixed { 2 } else { 0 };
        BigEndian::write_u16(&mut buf[count_offset..count_offset + 2], self.count as u16);
        self.writer.to_bytes()
    }

    #[tlv(0x01)]
    pub(crate) fn tlv001(&mut self) -> &mut Self {
        writer
            .write_i16(0x01)
            .write_i32(rand::random())
            .write_u32(self.session.uin() as u32)
            .write_u32(Utc::now().timestamp() as u32)
            .write_u32(0)
            .write_u16(0);
    }

    #[tlv(0x08)]
    pub(crate) fn tlv008(&mut self) -> &mut Self {
        writer
            .write_u16(0u16)
            .write_u32(2052) // locale_id
            .write_u16(0u16);
    }

    #[tlv(0x18)]
    pub(crate) fn tlv018(&mut self) -> &mut Self {
        writer
            .write_u16(0)
            .write_u32(5u32)
            .write_u32(0u32)
            .write_u32(8001u32) // app client ver
            .write_u32(self.session.uin() as u32)
            .write_u16(0)
            .write_u16(0);
    }

    #[tlv(0x18)]
    pub(crate) fn tlv018_android(&mut self) -> &mut Self {
        writer
            .write_u16(0x01)
            .write_u32(0x600u32)
            .write_u32(self.app_info.app_id as u32)
            .write_u32(self.app_info.app_client_version as u32)
            .write_u32(self.session.uin() as u32)
            .write_u16(0)
            .write_u16(0);
    }

    #[tlv(0x100)]
    pub(crate) fn tlv100(&mut self) -> &mut Self {
        let app_info = self.app_info;
        writer
            .write_u16(0) // db buf ver
            .write_u32(5) // sso ver, dont over 7
            .write_u32(app_info.app_id as u32)
            .write_u32(app_info.sub_app_id as u32)
            .write_u32(app_info.app_client_version as u32)
            .write_u32(app_info.sdk_info.main_sigmap.bits());
    }

    #[tlv(0x100)]
    pub(crate) fn tlv100_android(&mut self, main_sig_map: u32) -> &mut Self {
        let app_info = self.app_info;
        writer
            .write_u16(1u16) // db buf ver
            .write_u32(app_info.sso_version as u32) // sso ver, dont over 7
            .write_u32(app_info.app_id as u32)
            .write_u32(app_info.sub_app_id as u32)
            .write_u32(app_info.app_client_version as u32) // app client ver
            .write_u32(main_sig_map);
    }

    #[tlv(0x104)]
    pub(crate) fn tlv104(&mut self, verification_token: &[u8]) -> &mut Self {
        writer.write_bytes(verification_token);
    }

    #[tlv(0x106)]
    pub(crate) fn tlv106_pwd(&mut self, password: &str) -> &mut Self {
        let app_info = self.app_info;
        let session = self.session;
        let wlogin_sigs = self.session.wlogin_sigs.deref().load();
        let password_md5 = Md5::digest(password.as_bytes());

        let mut key_data = [0u8; 16 + 4 + 4];
        key_data[..16].copy_from_slice(password_md5.as_slice());
        // key[16..20].copy_from_slice(&[0u8; 4]); // empty 4 bytes
        BigEndian::write_u32(&mut key_data[20..24], session.uin() as u32);

        let key = *Md5::digest(key_data).as_ref();

        let mut plain_data = Writer::with_capacity(100);
        plain_data
            .write_u16(4u16) // TGTGT Version
            .write_u32(rand::random())
            .write_u32(app_info.sso_version as u32)
            .write_u32(app_info.app_id as u32)
            .write_u32(app_info.app_client_version as u32)
            .write_u64(session.uin() as u64)
            .write_u32(Utc::now().timestamp() as u32)
            .write_u32(0) // dummy IP Address
            .write_u8(1u8)
            .write_bytes(password_md5.as_slice())
            .write_bytes(wlogin_sigs.tgtgt_key.as_slice())
            .write_u32(0) // unknown
            .write_u8(1) // guidAvailable
            .write_bytes(session.guid.as_ref())
            .write_u32(app_info.sub_app_id as u32)
            .write_u32(1) // flag
            .write_str_with_prefix(Prefix::U16, false, session.uin().to_string())
            .write_u16(0);

        writer.write_bytes(tea::encrypt(plain_data.bytes(), &key));
    }

    #[tlv(0x106)]
    pub(crate) fn tlv106_encrypted_a1(&mut self) -> &mut Self {
        writer.write_bytes(self.session.wlogin_sigs.deref().load().a1.as_ref());
    }

    #[tlv(0x107)]
    pub(crate) fn tlv107(&mut self) -> &mut Self {
        writer
            .write_u16(1u16) // pic type
            .write_u8(0x0du8) // captcha type
            .write_u16(0u16) // pic size
            .write_u8(1u8); // ret type
    }

    #[tlv(0x107)]
    pub(crate) fn tlv107_android(&mut self) -> &mut Self {
        writer
            .write_u16(0u16) // pic type
            .write_u8(0u8) // captcha type
            .write_u16(0u16) // pic size
            .write_u8(1u8); // ret type
    }

    #[tlv(0x109)]
    pub(crate) fn tlv109(&mut self) -> &mut Self {
        writer.write_bytes(Md5::digest(self.session.android_id.as_bytes()));
    }

    #[tlv(0x112)]
    pub(crate) fn tlv112(&mut self, qid: &str) -> &mut Self {
        writer.write_bytes(qid.as_bytes());
    }

    #[tlv(0x116)]
    pub(crate) fn tlv116(&mut self) -> &mut Self {
        let app_info = self.app_info;
        writer
            .write_u8(0u8) // version
            .write_u32(app_info.sdk_info.misc_bitmap) // miscBitMap
            .write_u32(app_info.sdk_info.sub_sigmap)
            .write_u8(0u8); // length of subAppId
    }

    #[tlv(0x11b)]
    pub(crate) fn tlv11b(&mut self) -> &mut Self {
        writer.write_u8(2u8);
    }

    #[tlv(0x124)]
    pub(crate) fn tlv124(&mut self) -> &mut Self {
        writer.write_bytes([0u8; 12]);
    }

    #[tlv(0x124)]
    pub(crate) fn tlv124_android(&mut self) -> &mut Self {
        writer
            .write_str_with_prefix(Prefix::U16, false, "android")
            .write_str_with_prefix(Prefix::U16, false, "13") // os version
            .write_u16(0x02u16)
            .write_str_with_prefix(Prefix::U16, false, "") // sim info
            .write_str_with_prefix(Prefix::U32, false, "wifi"); // apn
    }

    #[tlv(0x128)]
    pub(crate) fn tlv128(&mut self) -> &mut Self {
        writer
            .write_u16(0u16)
            .write_u8(0u8) // guid new
            .write_u8(0u8) // guid available
            .write_u8(0u8) // guid changed
            .write_u32(0u32) // guid flag
            .write_str_with_prefix(Prefix::U16, false, self.app_info.os.as_str())
            .write_bytes_with_prefix(Prefix::U16, false, self.session.guid.as_ref())
            .write_str_with_prefix(Prefix::U16, false, ""); // brand
    }

    #[tlv(0x141)]
    pub(crate) fn tlv141(&mut self) -> &mut Self {
        writer
            .write_u16(0u16)
            .write_str_with_prefix(Prefix::U16, false, "Unknown")
            .write_u32(0u32);
    }

    #[tlv(0x141)]
    pub(crate) fn tlv141_android(&mut self) -> &mut Self {
        writer
            .write_u16(1u16)
            .write_str_with_prefix(Prefix::U16, false, "")
            .write_str_with_prefix(Prefix::U16, false, "")
            .write_str_with_prefix(Prefix::U16, false, "wifi");
    }

    #[tlv(0x142)]
    pub(crate) fn tlv142(&mut self) -> &mut Self {
        writer.write_u16(0u16).write_str_with_prefix(
            Prefix::U16,
            false,
            self.app_info.package_name.as_str(),
        );
    }

    #[tlv(0x144)]
    pub(crate) fn tlv144(&mut self) -> &mut Self {
        let mut tlv = Tlv::new(-1, self.app_info, self.session);
        tlv.tlv16e().tlv147().tlv128().tlv124();

        let encrypted = tea::encrypt(
            tlv.pack(),
            &self.session.wlogin_sigs.deref().load().tgtgt_key,
        );
        writer.write_bytes(encrypted.as_ref());
    }

    #[tlv(0x144)]
    pub(crate) fn tlv144_report(&mut self, use_a1_key: bool) -> &mut Self {
        let wlogin_sigs = self.session.wlogin_sigs.deref().load();
        let mut tlv = Tlv::new(-1, self.app_info, self.session);
        tlv.tlv109().tlv52d().tlv124_android().tlv128().tlv16e();
        let tlv_data = tlv.pack();

        let key = if use_a1_key {
            &wlogin_sigs.a1_key
        } else {
            &wlogin_sigs.tgtgt_key
        };

        let encrypted = tea::encrypt(tlv_data, key);
        writer.write_bytes(&encrypted);
    }

    #[tlv(0x145)]
    pub(crate) fn tlv145(&mut self) -> &mut Self {
        writer.write_bytes(self.session.guid.as_ref());
    }

    #[tlv(0x147)]
    pub(crate) fn tlv147(&mut self) -> &mut Self {
        let app_info = self.app_info;
        writer
            .write_u32(app_info.app_id as u32)
            .write_str_with_prefix(Prefix::U16, false, app_info.pt_version.as_str())
            .write_bytes_with_prefix(Prefix::U16, false, app_info.apk_signature_md5.as_ref());
    }

    #[tlv(0x154)]
    pub(crate) fn tlv154(&mut self) -> &mut Self {
        writer.write_u32(0); //seq
    }

    #[tlv(0x166)]
    pub(crate) fn tlv166(&mut self) -> &mut Self {
        writer.write_u8(5u8);
    }

    #[tlv(0x16a)]
    pub(crate) fn tlv16a(&mut self) -> &mut Self {
        writer.write_bytes(self.session.wlogin_sigs.as_ref().load().no_pic_sig.as_ref());
    }

    #[tlv(0x16e)]
    pub(crate) fn tlv16e(&mut self) -> &mut Self {
        writer.write_str(self.session.device_name.as_str());
    }

    #[tlv(0x174)]
    pub(crate) fn tlv174(&mut self, session: &[u8]) -> &mut Self {
        writer.write_bytes(session);
    }

    #[tlv(0x177)]
    pub(crate) fn tlv177(&mut self) -> &mut Self {
        writer
            .write_u8(1u8)
            .write_u32(self.app_info.sdk_info.sdk_build_time); // sdk build time
        writer.write_str_with_prefix(
            Prefix::U16,
            false,
            self.app_info.sdk_info.sdk_version.as_str(),
        );
    }

    #[tlv(0x17a)]
    pub(crate) fn tlv17a(&mut self) -> &mut Self {
        writer.write_u32(9);
    }

    #[tlv(0x17c)]
    pub(crate) fn tlv17c(&mut self, code: &str) -> &mut Self {
        writer.write_str_with_prefix(Prefix::U16, false, code);
    }

    #[tlv(0x187)]
    pub(crate) fn tlv187(&mut self) -> &mut Self {
        writer.write_bytes(Md5::digest([0x02, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }

    #[tlv(0x188)]
    pub(crate) fn tlv188(&mut self) -> &mut Self {
        writer.write_bytes(Md5::digest(self.session.android_id.as_bytes()));
    }

    #[tlv(0x191)]
    pub(crate) fn tlv191(&mut self, k: u8) -> &mut Self {
        writer.write_u8(k);
    }

    #[tlv(193)]
    pub(crate) fn tlv193(&mut self, ticket: &[u8]) -> &mut Self {
        writer.write_bytes(ticket);
    }

    #[tlv(0x197)]
    pub(crate) fn tlv197(&mut self) -> &mut Self {
        writer.write_u8(0u8);
    }

    #[tlv(0x198)]
    pub(crate) fn tlv198(&mut self) -> &mut Self {
        writer.write_u8(0u8);
    }

    #[tlv(0x318)]
    pub(crate) fn tlv318(&mut self) -> &mut Self {}

    #[tlv(0x400)]
    pub(crate) fn tlv400(&mut self) -> &mut Self {
        let session = self.session;
        let random_key: [u8; 16] = rand::random();
        let rand_seed: [u8; 8] = rand::random();

        let mut data = Writer::with_capacity(100);
        data.write_u16(1)
            .write_u64(session.uin() as u64)
            .write_bytes(session.guid.as_ref())
            .write_bytes(random_key)
            .write_u32(16)
            .write_u32(1)
            .write_u32(Utc::now().timestamp() as u32)
            .write_bytes(rand_seed);

        let encrypted = tea::encrypt(data.to_bytes(), &session.guid);
        writer.write_bytes(encrypted);
    }

    #[tlv(0x401)]
    pub(crate) fn tlv401(&mut self) -> &mut Self {
        let random: [u8; 16] = rand::random();
        writer.write_bytes(random);
    }

    #[tlv(0x511)]
    pub(crate) fn tlv511(&mut self) -> &mut Self {
        let domains = [
            "office.qq.com",
            "qun.qq.com",
            "gamecenter.qq.com",
            "docs.qq.com",
            "mail.qq.com",
            "tim.qq.com",
            "ti.qq.com",
            "vip.qq.com",
            "tenpay.com",
            "qqweb.qq.com",
            "qzone.qq.com",
            "mma.qq.com",
            "game.qq.com",
            "openmobile.qq.com",
            "connect.qq.com",
        ];

        writer.write_u16(domains.len() as u16);
        for domain in domains {
            writer
                .write_u8(1u8)
                .write_str_with_prefix(Prefix::U16, false, domain);
        }
    }

    #[tlv(0x516)]
    pub(crate) fn tlv516(&mut self) -> &mut Self {
        writer.write_u32(0);
    }

    #[tlv(0x521)]
    pub(crate) fn tlv521(&mut self) -> &mut Self {
        writer
            .write_u32(0x13)
            .write_str_with_prefix(Prefix::U16, false, "basicim");
    }

    #[tlv(0x521)]
    pub(crate) fn tlv521_android(&mut self) -> &mut Self {
        writer
            .write_u32(0)
            .write_str_with_prefix(Prefix::U16, false, "");
    }

    #[tlv(0x525)]
    pub(crate) fn tlv525(&mut self) -> &mut Self {
        writer
            .write_u16(1) // tlvCount
            .write_u16(0x536) // tlv536
            .write_bytes_with_prefix(Prefix::U16, false, [0x02, 0x01, 0x00]);
    }

    #[tlv(0x52d)]
    pub(crate) fn tlv52d(&mut self) -> &mut Self {
        let report = DeviceReport {
            bootloader:  "V816.0.6.0.TKHCNXM".to_string(),
            proc_version:  "Linux version 4.19.157-perf-g92c089fc2d37 (builder@pangu-build-component-vendor-272092-qncbv-vttl3-61r9m) (clang version 10.0.7 for Android NDK, GNU ld (binutils-2.27-bd24d23f) 2.27.0.20170315) #1 SMP PREEMPT Wed Jun 5 13:27:08 UTC 2024".to_string(),
            code_name:  "REL".to_string(),
            fingerprint:  "Redmi/alioth/alioth:13/TKQ1.221114.001/V816.0.6.0.TKHCNXM:user/release-keys".to_string(),
            boot_id:  "unknown".to_string(),
            base_band:  "".to_string(),
            inner_version: "V816.0.6.0.TKHCNXM".to_string(),
            ..Default::default()
        };

        let encoded = report.encode_to_vec();
        writer.write_bytes(encoded.as_slice());
    }

    #[tlv(0x544)]
    pub(crate) fn tlv544(&mut self, energy: &[u8]) -> &mut Self {
        writer.write_bytes(energy);
    }

    #[tlv(0x545)]
    pub(crate) fn tlv545(&mut self) -> &mut Self {
        writer.write_str(self.session.qimei.as_str());
    }

    #[tlv(0x547)]
    pub(crate) fn tlv547(&mut self, clint_pow: &[u8]) -> &mut Self {
        writer.write_bytes(clint_pow);
    }

    #[tlv(0x548)]
    pub(crate) fn tlv548(&mut self, native_get_test_data: &[u8]) -> &mut Self {
        writer.write_bytes(native_get_test_data);
    }

    #[tlv(0x553)]
    pub(crate) fn tlv553(&mut self, fekit_attach: &[u8]) -> &mut Self {
        writer.write_bytes(fekit_attach);
    }
}

pub(crate) struct TlvQrCode<'a> {
    writer: Writer,
    count: usize,
    app_info: &'a AppInfo,
    session: &'a Session,
}

impl<'a> TlvQrCode<'a> {
    pub(crate) fn new(app_info: &'a AppInfo, session: &'a Session) -> Self {
        let mut writer = Writer::with_capacity(300);
        writer.skip(2);
        Self {
            writer,
            count: 0,
            app_info,
            session,
        }
    }

    pub(crate) fn pack(mut self) -> Bytes {
        let buf = self.writer.as_mut();
        BigEndian::write_u16(&mut buf[0..2], self.count as u16);
        self.writer.to_bytes()
    }

    #[tlv(0x02)]
    pub(crate) fn tlv02(&mut self) -> &mut Self {
        writer.write_u32(0).write_u32(0x0b);
    }

    #[tlv(0x04)]
    pub(crate) fn tlv04(&mut self) -> &mut Self {
        writer.write_u16(0).write_str_with_prefix(
            Prefix::U16,
            false,
            self.session.uin().to_string(),
        );
    }

    #[tlv(0x09)]
    pub(crate) fn tlv09(&mut self) -> &mut Self {
        writer.write_bytes(self.app_info.package_name.as_bytes());
    }

    #[tlv(0x11)]
    pub(crate) fn tlv11(&mut self, unusual_sig: &[u8]) -> &mut Self {
        writer.write_bytes(unusual_sig);
    }

    #[tlv(0x15)]
    pub(crate) fn tlv15(&mut self) -> &mut Self {
        writer.write_u32(0);
    }

    #[tlv(0x16)]
    pub(crate) fn tlv16(&mut self) -> &mut Self {
        let app_info = self.app_info;
        writer
            .write_u32(0u32)
            .write_u32(app_info.app_id as u32)
            .write_u32(app_info.sub_app_id as u32)
            .write_bytes(self.session.guid.as_slice())
            .write_str_with_prefix(Prefix::U16, false, app_info.package_name.as_str())
            .write_str_with_prefix(Prefix::U16, false, app_info.pt_version.as_str())
            .write_str_with_prefix(Prefix::U16, false, app_info.package_name.as_str());
    }

    #[tlv(0x18)]
    pub(crate) fn tlv18(&mut self) -> &mut Self {
        writer.write_bytes(self.session.wlogin_sigs.deref().load().a1.as_ref());
    }

    #[tlv(0x19)]
    pub(crate) fn tlv19(&mut self) -> &mut Self {
        writer.write_bytes(self.session.wlogin_sigs.deref().load().no_pic_sig.as_ref());
    }

    #[tlv(0x1b)]
    pub(crate) fn tlv1b(&mut self, size: u32) -> &mut Self {
        writer
            .write_u32(0u32) // micro
            .write_u32(0u32) // version
            .write_u32(size) // size default 3
            .write_u32(4u32) // margin
            .write_u32(72u32) // dpi
            .write_u32(2u32) // eclevel
            .write_u32(2u32) // hint
            .write_u16(0u16); // unknown
    }

    #[tlv(0x1d)]
    pub(crate) fn tlv1d(&mut self) -> &mut Self {
        writer
            .write_u8(1)
            .write_u32(self.app_info.sdk_info.misc_bitmap)
            .write_u32(0u32)
            .write_u8(0u8);
    }

    #[tlv(0x33)]
    pub(crate) fn tlv33(&mut self) -> &mut Self {
        writer.write_bytes(self.session.guid.as_slice());
    }

    #[tlv(0x35)]
    pub(crate) fn tlv35(&mut self) -> &mut Self {
        writer.write_u32(self.app_info.sso_version as u32);
    }

    #[tlv(0x39)]
    pub(crate) fn tlv39(&mut self) -> &mut Self {
        writer.write_u32(0x01);
    }

    #[tlv(0x66)]
    pub(crate) fn tlv66(&mut self) -> &mut Self {
        writer.write_u32(self.app_info.sso_version as u32);
    }

    #[tlv(0x68)]
    pub(crate) fn tlv68(&mut self) -> &mut Self {
        writer.write_bytes(self.session.guid.as_slice());
    }

    #[tlv(0xd1)]
    pub(crate) fn tlvd1(&mut self) -> &mut Self {
        let obj = QrExtInfo {
            dev_info: Some(DevInfo {
                dev_type: self.app_info.os.to_owned(),
                dev_name: self.session.device_name.clone(),
            }),
            gen_info: Some(GenInfo {
                field6: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        writer.write_bytes(obj.encode_to_vec());
    }

    #[tlv(0x12c)]
    pub(crate) fn tlv12c(&mut self) -> &mut Self {
        let session = self.session;
        let obj = ScanExtInfo {
            guid: Bytes::from(session.guid.to_vec()),
            imei: session.qimei.to_owned(),
            scan_scene: 1,
            allow_auto_renew_ticket: true,
            ..Default::default()
        };
        writer.write_bytes(obj.encode_to_vec().as_slice());
    }
}

pub(crate) fn decode_tlv(reader: &mut Reader) -> Result<AHashMap<u16, Bytes>, ReaderError> {
    let count = reader.read_u16()?;
    let mut tlvs = AHashMap::with_capacity(count as usize);

    for _ in 0..count {
        let tag = reader.read_u16()?;
        let length = reader.read_u16()?;
        let data = reader.read_bytes(length as usize)?;
        tlvs.insert(tag, data);
    }
    Ok(tlvs)
}
