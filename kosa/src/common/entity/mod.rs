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
    Friend,
    Group,
    GroupMember,
}
