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

    pub async fn get_uid(&self, uin: i64) -> Option<String> {
        self.uin2uid.get(&uin).as_deref().cloned()
    }

    pub async fn get_friend_info(&self, uin: i64, refresh: bool) -> anyhow::Result<Option<Friend>> {
        if !refresh {
            return Ok(self.friends.get(&uin).as_deref().cloned());
        };
        self.refresh_friends().await?;
        Ok(self.friends.get(&uin).as_deref().cloned())
    }

    pub async fn refresh_friends(&self) -> anyhow::Result<()> {
        let (friends, categories) = self.service.fetch_friends().await?;
        friends.into_iter().for_each(|(uin, friend)| {
            self.uin2uid.insert(uin, friend.uid.clone());
            self.uid2uin.insert(friend.uid.clone(), uin);
            self.friends.insert(uin, friend);
        });
        categories.into_iter().for_each(|(id, category)| {
            self.categories.insert(id, category);
        });
        Ok(())
    }
}
