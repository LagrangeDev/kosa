use std::fmt::Debug;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::FromRepr;

use crate::common::entity::Identity;

#[derive(Debug, Default, Clone, Copy, FromRepr, Serialize, Deserialize)]
#[repr(i32)]
pub enum Gender {
    None = 0,
    Male = 1,
    Female = 2,
    #[default]
    Unknown = 3,
}

/// 群
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Group {
    /// 群号
    pub uin: i64,
    /// 群名
    pub name: String,
    /// 群成员数量
    pub member_count: i32,
    /// 群成员数量上限
    pub max_member_count: i32,
    /// 群创建时间
    pub create_time: i64,
    /// 群描述
    pub description: String,
    /// 进群验证问题
    pub question: String,
    /// 群公告
    pub announcement: String,
}

impl Identity for Group {
    fn uin(&self) -> i64 {
        self.uin
    }

    fn uid(&self) -> String {
        unimplemented!()
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

/// 好友
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Friend {
    /// QQ号
    pub uin: i64,
    /// uid
    pub uid: String,
    /// 昵称
    pub nick_name: String,
    /// 备注
    pub remark: String,
    /// 个性签名
    pub personal_sign: String,
    /// QID
    pub qid: String,
    /// 年龄
    pub age: i32,
    /// 性别
    pub gender: Gender,
}

impl Identity for Friend {
    fn uin(&self) -> i64 {
        self.uin
    }

    fn uid(&self) -> String {
        self.uid.clone()
    }

    fn name(&self) -> String {
        self.nick_name.clone()
    }
}

/// 好友分类
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FriendCategory {
    pub id: i32,
    pub name: String,
    pub member_count: i32,
    pub sort_id: i32,
}

/// 陌生人
#[derive(Debug, Clone)]
pub struct Stranger {
    /// QQ号
    pub uin: i64,
    /// uid
    pub uid: String,
    /// 昵称
    pub nick_name: String,
    /// 备注
    pub remark: String,
    /// 个性签名
    pub personal_sign: String,
    /// QID
    pub qid: String,
    /// 年龄
    pub age: i32,
    /// 性别
    pub gender: Gender,
    /// 注册时间
    pub registration_time: DateTime<Utc>,
    /// 生日
    pub birthday: DateTime<Utc>,
    pub source: i64,
    pub country: Option<String>,
    pub city: Option<String>,
    pub school: Option<String>,
}

impl Identity for Stranger {
    fn uin(&self) -> i64 {
        self.uin
    }

    fn uid(&self) -> String {
        self.uid.clone()
    }

    fn name(&self) -> String {
        self.nick_name.clone()
    }
}

/// 群成员
#[derive(Debug, Clone)]
pub struct GroupMember {
    pub group: Group,
    pub uin: i64,
    pub uid: String,
    /// 昵称
    pub nick_name: String,
    /// 群名片
    pub member_card: String,
    /// 特殊头衔
    pub special_title: String,
    pub age: i32,
    pub gender: Gender,
    /// 群内等级
    pub level: i32,
    /// 权限
    pub permission: GroupPermission,
    /// 加群时间
    pub join_time: DateTime<Utc>,
    /// 上一次发言时间
    pub last_msg_time: DateTime<Utc>,
    /// 禁言结束时间
    pub shutup_time: DateTime<Utc>,
}

impl Identity for GroupMember {
    fn uin(&self) -> i64 {
        self.uin
    }

    fn uid(&self) -> String {
        self.uid.clone()
    }

    fn name(&self) -> String {
        // 群成员一般取群卡片作为昵称
        self.member_card.clone()
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[repr(i32)]
pub enum GroupPermission {
    #[default]
    Member = 0,
    Owner = 1,
    Admin = 2,
}
