use std::sync::Arc;

use ahash::AHashMap;
use arc_swap::ArcSwap;
use arcstr::ArcStr;
use dashmap::DashMap;

use crate::{
    common::entity::{Friend, FriendCategory, Group, GroupMember, Stranger},
    service::ServiceContext,
};

pub(crate) struct Cache {
    service: Arc<ServiceContext>,

    friend_cache: ArcSwap<FriendCache>,
    group_cache: Arc<GroupCache>,
    #[allow(unused)]
    strangers: ArcSwap<AHashMap<i64, Stranger>>,
}

impl Cache {
    pub(crate) fn new(service: Arc<ServiceContext>) -> Self {
        Self {
            service,
            friend_cache: Default::default(),
            group_cache: Default::default(),
            strangers: Default::default(),
        }
    }

    pub(super) fn friends(&self) -> Arc<FriendCache> {
        self.friend_cache.load_full()
    }

    pub(super) fn groups(&self) -> Arc<GroupCache> {
        self.group_cache.clone()
    }

    /// 刷新好友列表缓存
    pub(super) async fn refresh_friends(&self) -> anyhow::Result<(usize, usize)> {
        let (friends, categories) = self.service.fetch_friends().await?;
        let (friends_count, categories_count) = (friends.len(), categories.len());
        let mut new_uin2uid: AHashMap<i64, ArcStr> = AHashMap::with_capacity(friends_count);
        let mut new_uid2uin: AHashMap<ArcStr, i64> = AHashMap::with_capacity(friends_count);
        let mut new_friends: AHashMap<i64, Friend> = AHashMap::with_capacity(friends_count);
        let mut new_categories: AHashMap<i32, FriendCategory> =
            AHashMap::with_capacity(categories_count);
        for friend in friends {
            new_uin2uid.insert(friend.uin, friend.uid.clone());
            new_uid2uin.insert(friend.uid.clone(), friend.uin);
            new_friends.insert(friend.uin, friend);
        }
        for category in categories {
            new_categories.insert(category.id, category);
        }
        self.friend_cache.store(Arc::new(FriendCache {
            uin2uid: new_uin2uid,
            uid2uin: new_uid2uin,
            friends: new_friends,
            categories: new_categories,
        }));
        Ok((friends_count, categories_count))
    }

    /// 刷新群列表缓存
    pub(super) async fn refresh_group_info(&self) -> anyhow::Result<usize> {
        let groups = self.service.fetch_groups().await?;
        let groups_count = groups.len();
        let mut new_groups: AHashMap<i64, Group> = AHashMap::with_capacity(groups_count);
        for group in groups {
            new_groups.insert(group.uin, group);
        }
        self.group_cache.groups.store(Arc::new(new_groups));
        Ok(groups_count)
    }

    /// 刷新群成员缓存
    pub(super) async fn refresh_members(&self, group: i64) -> anyhow::Result<usize> {
        let members = self.service.fetch_members(group).await?;
        let members_count = members.len();
        let new_members: DashMap<i64, Arc<GroupMember>> = DashMap::with_capacity(members_count);
        for member in members {
            new_members.insert(member.uin, Arc::new(member));
        }
        self.group_cache
            .members
            .insert(group, Arc::new(new_members));
        Ok(members_count)
    }
}

#[derive(Default)]
pub struct FriendCache {
    uin2uid: AHashMap<i64, ArcStr>,
    uid2uin: AHashMap<ArcStr, i64>,
    friends: AHashMap<i64, Friend>,
    #[allow(unused)]
    categories: AHashMap<i32, FriendCategory>,
}

impl FriendCache {
    /// 通过uid获取uin
    pub fn get_uin(&self, uid: impl AsRef<str>) -> Option<i64> {
        self.uid2uin.get(uid.as_ref()).copied()
    }

    pub fn get_uin_required(&self, uid: impl AsRef<str>) -> anyhow::Result<i64> {
        let uid = uid.as_ref();
        self.get_uin(uid)
            .ok_or_else(|| anyhow::anyhow!("not found uin for {}", uid))
    }

    /// 获取好友uid
    pub fn get_uid(&self, uin: i64) -> Option<ArcStr> {
        self.uin2uid.get(&uin).cloned()
    }

    pub fn get_uid_required(&self, uin: i64) -> anyhow::Result<ArcStr> {
        self.get_uid(uin)
            .ok_or_else(|| anyhow::anyhow!("not found uid for {}", uin))
    }

    /// 获取好友信息
    pub async fn get(&self, uin: i64) -> anyhow::Result<Option<Friend>> {
        Ok(self.friends.get(&uin).cloned())
    }
}

#[derive(Default)]
pub struct GroupCache {
    /// 群信息
    groups: ArcSwap<AHashMap<i64, Group>>,
    /// 群成员
    members: DashMap<i64, Arc<DashMap<i64, Arc<GroupMember>>>>,
}

impl GroupCache {
    pub fn get(&self, group: i64) -> Option<Group> {
        self.groups.load().get(&group).cloned()
    }

    pub fn get_member(&self, group: i64, uin: i64) -> Option<Arc<GroupMember>> {
        self.members
            .get(&group)
            .and_then(|t| t.get(&uin).map(|u| u.clone()))
    }
}
