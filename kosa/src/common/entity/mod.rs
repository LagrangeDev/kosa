mod contact;

use std::fmt::Debug;

pub use crate::common::entity::contact::{
    Friend, FriendCategory, Gender, Group, GroupMember, GroupPermission, Stranger,
};

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
