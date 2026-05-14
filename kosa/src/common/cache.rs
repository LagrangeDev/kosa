use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::{
    common::entity::{Friend, FriendCategory, Group, GroupMember, Stranger},
    service::ServiceContext,
};

#[derive(Debug)]
pub(crate) struct Cache {
    service: Arc<ServiceContext>,

    uin2uid: ArcSwap<DashMap<i64, String>>,
    uid2uin: ArcSwap<DashMap<String, i64>>,

    friends: ArcSwap<DashMap<i64, Friend>>,
    categories: ArcSwap<DashMap<i32, FriendCategory>>,
    groups: ArcSwap<DashMap<i64, Group>>,
    members: ArcSwap<DashMap<i64, DashMap<i64, GroupMember>>>,
    strangers: ArcSwap<DashMap<i64, Stranger>>,
}

impl Cache {
    pub(crate) fn new(service: Arc<ServiceContext>) -> Self {
        Self {
            service,
            uin2uid: Default::default(),
            uid2uin: Default::default(),
            friends: Default::default(),
            categories: Default::default(),
            groups: Default::default(),
            members: Default::default(),
            strangers: Default::default(),
        }
    }

    /// 获取好友uid
    pub fn get_uid(&self, uin: i64) -> Option<String> {
        self.uin2uid.load().get(&uin).as_deref().cloned()
    }

    /// 获取好友信息
    pub async fn get_friend_info(&self, uin: i64, refresh: bool) -> anyhow::Result<Option<Friend>> {
        if !refresh {
            return Ok(self.friends.load().get(&uin).as_deref().cloned());
        };
        self.refresh_friends().await?;
        Ok(self.friends.load().get(&uin).as_deref().cloned())
    }

    /// 获取群信息
    pub async fn get_group_info(&self, uin: i64, refresh: bool) -> anyhow::Result<Option<Group>> {
        if !refresh {
            return Ok(self.groups.load().get(&uin).as_deref().cloned());
        }
        self.refresh_groups().await?;
        Ok(self.groups.load().get(&uin).as_deref().cloned())
    }

    /// 刷新好友列表缓存
    pub async fn refresh_friends(&self) -> anyhow::Result<(usize, usize)> {
        let (friends, categories) = self.service.fetch_friends().await?;
        let (friends_count, categories_count) = (friends.len(), categories.len());
        let new_uin2uid: DashMap<i64, String> = DashMap::with_capacity(friends_count);
        let new_uid2uin: DashMap<String, i64> = DashMap::with_capacity(friends_count);
        let new_friends: DashMap<i64, Friend> = DashMap::with_capacity(friends_count);
        let new_categories: DashMap<i32, FriendCategory> = DashMap::with_capacity(categories_count);
        friends.into_iter().for_each(|friend| {
            new_uin2uid.insert(friend.uin, friend.uid.clone());
            new_uid2uin.insert(friend.uid.clone(), friend.uin);
            new_friends.insert(friend.uin, friend);
        });
        categories.into_iter().for_each(|category| {
            new_categories.insert(category.id, category);
        });
        self.uin2uid.store(Arc::new(new_uin2uid));
        self.uid2uin.store(Arc::new(new_uid2uin));
        self.friends.store(Arc::new(new_friends));
        self.categories.store(Arc::new(new_categories));
        Ok((friends_count, categories_count))
    }

    /// 刷新群列表缓存
    pub async fn refresh_groups(&self) -> anyhow::Result<usize> {
        let groups = self.service.fetch_groups().await?;
        let groups_count = groups.len();
        groups.into_iter().for_each(|group| {
            self.groups.load().insert(group.uin, group);
        });
        Ok(groups_count)
    }
}
