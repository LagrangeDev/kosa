use std::fmt::Debug;

use arcstr::ArcStr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::FromRepr;

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

/// 好友
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Friend {
    /// QQ号
    pub uin: i64,
    /// uid
    pub uid: ArcStr,
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

/// 好友分类
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FriendCategory {
    pub id: i32,
    pub name: ArcStr,
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

/// 群成员
#[derive(Debug, Clone)]
pub struct GroupMember {
    pub uin: i64,
    pub uid: ArcStr,
    /// 昵称
    pub nick_name: ArcStr,
    /// 群名片
    pub member_card: String,
    /// 特殊头衔
    pub special_title: String,
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

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, FromRepr)]
#[repr(i32)]
pub enum GroupPermission {
    #[default]
    Member = 0,
    Owner = 1,
    Admin = 2,
}

impl From<i32> for GroupPermission {
    fn from(val: i32) -> Self {
        match val {
            1 => GroupPermission::Owner,
            2 => GroupPermission::Admin,
            _ => GroupPermission::default(),
        }
    }
}
