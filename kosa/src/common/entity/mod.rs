use std::fmt::Debug;

use enum_dispatch::enum_dispatch;

pub use crate::common::entity::contact::{
    Friend, FriendCategory, Gender, Group, GroupMember, GroupPermission, Stranger,
};

mod contact;

#[enum_dispatch]
pub trait Identity: Debug {
    fn uin(&self) -> i64;

    fn uid(&self) -> String;

    fn name(&self) -> String;
}

#[enum_dispatch(Identity)]
#[derive(Debug, Clone)]
pub enum Contact {
    Stranger,
    Friend,
    Group,
    GroupMember,
}

#[derive(Debug, Clone)]
pub enum Scene {
    // 私聊
    Private(i64, String),
    // 群聊
    Group(i64),
}

impl Scene {
    pub fn business_type(&self) -> u32 {
        match self {
            Scene::Private(_, _) => 1,
            Scene::Group(_) => 2,
        }
    }
}
