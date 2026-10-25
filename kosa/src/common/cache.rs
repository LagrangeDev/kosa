use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    sync::Arc,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::{
    common::entity::{Friend, FriendCategory, Group, GroupMember, Stranger},
    service::ServiceContext,
    utils::InternedStr,
};

#[derive(Clone, PartialEq, Eq)]
struct UidKey(InternedStr);

impl From<InternedStr> for UidKey {
    fn from(id: InternedStr) -> Self {
        UidKey(id)
    }
}

impl Borrow<str> for UidKey {
    fn borrow(&self) -> &str {
        self.0.as_str()
    }
}

impl Hash for UidKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

pub(crate) struct Cache {
    service: Arc<ServiceContext>,

    friend_lock: Mutex<()>,
    group_lock: DashMap<i64, Arc<Mutex<()>>>,
    group_info_lock: Mutex<()>,

    friend_cache: ArcSwap<FriendCache>,
    group_cache: Arc<GroupCache>,
    #[allow(unused)]
    strangers: ArcSwap<AHashMap<i64, Stranger>>,
}

impl Cache {
    pub(crate) fn new(service: Arc<ServiceContext>) -> Self {
        Self {
            service,
            friend_lock: Default::default(),
            group_lock: Default::default(),
            group_info_lock: Default::default(),
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
        let _guard = self.friend_lock.lock().await;
        let (friends, categories) = self.service.fetch_friends().await?;
        let (friends_count, categories_count) = (friends.len(), categories.len());
        let mut new_uid2uin: AHashMap<UidKey, i64> = AHashMap::with_capacity(friends_count);
        let mut new_friends: AHashMap<i64, Friend> = AHashMap::with_capacity(friends_count);
        let mut new_categories: AHashMap<i32, FriendCategory> =
            AHashMap::with_capacity(categories_count);
        for friend in friends {
            new_uid2uin.insert(friend.uid.clone().into(), friend.uin);
            new_friends.insert(friend.uin, friend);
        }
        for category in categories {
            new_categories.insert(category.id, category);
        }
        self.friend_cache.store(Arc::new(FriendCache {
            uid2uin: new_uid2uin,
            friends: new_friends,
            categories: new_categories,
        }));
        Ok((friends_count, categories_count))
    }

    /// 刷新群列表缓存
    pub(super) async fn refresh_group_info(&self) -> anyhow::Result<usize> {
        let _guard = self.group_info_lock.lock().await;
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
    pub(super) async fn refresh_group_members(&self, group: i64) -> anyhow::Result<usize> {
        let lock = self
            .group_lock
            .entry(group)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        let members = self.service.fetch_members(group).await?;
        let members_count = members.len();
        let mut new_members: AHashMap<i64, Arc<GroupMember>> =
            AHashMap::with_capacity(members_count);
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
    uid2uin: AHashMap<UidKey, i64>,
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
    pub fn get_uid(&self, uin: i64) -> Option<InternedStr> {
        self.friends.get(&uin).map(|f| f.uid.clone())
    }

    pub fn get_uid_required(&self, uin: i64) -> anyhow::Result<InternedStr> {
        self.get_uid(uin)
            .ok_or_else(|| anyhow::anyhow!("not found uid for {}", uin))
    }

    /// 获取好友信息
    pub fn get(&self, uin: i64) -> anyhow::Result<Option<Friend>> {
        Ok(self.friends.get(&uin).cloned())
    }
}

#[derive(Default)]
pub struct GroupCache {
    /// 群信息
    groups: ArcSwap<AHashMap<i64, Group>>,
    /// 群成员
    members: DashMap<i64, Arc<AHashMap<i64, Arc<GroupMember>>>>,
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
