use std::sync::Arc;

use dashmap::DashMap;

use crate::{
    common::entity::{Friend, FriendCategory, Group, GroupMember, Stranger},
    service::ServiceContext,
};

#[derive(Debug)]
pub struct Cache {
    service: Arc<ServiceContext>,

    uin2uid: DashMap<i64, String>,
    uid2uin: DashMap<String, i64>,

    friends: DashMap<i64, Friend>,
    categories: DashMap<i32, FriendCategory>,
    groups: DashMap<i64, Group>,
    members: DashMap<i64, DashMap<i64, GroupMember>>,
    strangers: DashMap<i64, Stranger>,
}

impl Cache {
    pub(crate) fn new(service: Arc<ServiceContext>) -> Self {
        Self {
            service,
            uin2uid: DashMap::default(),
            uid2uin: DashMap::default(),
            friends: DashMap::default(),
            categories: DashMap::default(),
            groups: DashMap::default(),
            members: DashMap::default(),
            strangers: DashMap::default(),
        }
    }

    /// 获取好友uid
    pub fn get_uid(&self, uin: i64) -> Option<String> {
        self.uin2uid.get(&uin).as_deref().cloned()
    }

    /// 获取好友信息
    pub async fn get_friend_info(&self, uin: i64, refresh: bool) -> anyhow::Result<Option<Friend>> {
        if !refresh {
            return Ok(self.friends.get(&uin).as_deref().cloned());
        };
        self.refresh_friends().await?;
        Ok(self.friends.get(&uin).as_deref().cloned())
    }

    /// 获取群信息
    pub async fn get_group_info(&self, uin: i64, refresh: bool) -> anyhow::Result<Option<Group>> {
        if !refresh {
            return Ok(self.groups.get(&uin).as_deref().cloned());
        }
        self.refresh_groups().await?;
        Ok(self.groups.get(&uin).as_deref().cloned())
    }

    /// 刷新好友列表缓存
    pub async fn refresh_friends(&self) -> anyhow::Result<()> {
        let (friends, categories) = self.service.fetch_friends().await?;
        friends.into_iter().for_each(|friend| {
            self.uin2uid.insert(friend.uin, friend.uid.clone());
            self.uid2uin.insert(friend.uid.clone(), friend.uin);
            self.friends.insert(friend.uin, friend);
        });
        categories.into_iter().for_each(|category| {
            self.categories.insert(category.id, category);
        });
        Ok(())
    }

    /// 刷新群列表缓存
    pub async fn refresh_groups(&self) -> anyhow::Result<()> {
        let groups = self.service.fetch_groups().await?;
        groups.into_iter().for_each(|group| {
            self.groups.insert(group.uin, group);
        });
        Ok(())
    }
}
