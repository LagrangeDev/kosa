use ahash::AHashMap;
use bytes::Bytes;
use kosa_macros::{ServiceState, oidb_command, register_oidb_service};
use kosa_proto::common::v2::{
    IncPullRequest, IncPullRequestBiz, IncPullRequestBizBusi, IncPullResponse,
};
use prost::Message;

use crate::{
    common::{
        AppInfo, Bot, Protocol, Session,
        entity::{Friend, FriendCategory, Gender},
    },
    service::{OidbService, ServiceContext},
};

#[oidb_command(0xfd4, 1)]
#[derive(Debug, Default, ServiceState)]
pub(crate) struct FetchFriendService;

pub(crate) struct FetchFriendReq {
    pub(crate) cookie: Bytes,
}

pub(crate) struct FetchFriendResp {
    pub(crate) friends: AHashMap<i64, Friend>,
    pub(crate) categories: AHashMap<i32, FriendCategory>,
    pub(crate) cookie: Bytes,
}

#[register_oidb_service]
impl OidbService<FetchFriendReq, FetchFriendResp> for FetchFriendService {
    const SUPPORT_PROTOCOLS: Protocol = Protocol::all();

    fn build(
        _state: &Self,
        req: FetchFriendReq,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<Bytes> {
        let req = IncPullRequest {
            req_count: 300,
            local_seq: 13,
            cookie: req.cookie,
            flag: 1,
            proxy_seq: i32::MAX as u32,
            request_biz: vec![
                IncPullRequestBiz {
                    biz_type: 1,
                    biz_data: Some(IncPullRequestBizBusi {
                        /*
                         * 102：个性签名
                         * 103：备注
                         * 20002：昵称
                         */
                        ext_busi: vec![103, 102, 20002, 27394, 20009, 20037],
                    }),
                },
                IncPullRequestBiz {
                    biz_type: 4,
                    biz_data: Some(IncPullRequestBizBusi {
                        ext_busi: vec![100, 101, 102],
                    }),
                },
            ],
            ext_sns_flag_key: vec![13578, 13579, 13573, 13572, 13568],
            ext_private_id_list_key: vec![4051],
            ..Default::default()
        };
        Ok(req.encode_to_vec().into())
    }

    fn parse(
        _state: &Self,
        data: Bytes,
        _app_info: &AppInfo,
        _session: &Session,
    ) -> anyhow::Result<FetchFriendResp> {
        let resp = IncPullResponse::decode(data.as_ref())?;

        let mut categories: AHashMap<i32, FriendCategory> =
            AHashMap::with_capacity(resp.category.len());
        for category in resp.category {
            categories.insert(
                category.category_id,
                FriendCategory {
                    id: category.category_id,
                    name: category.category_name,
                    member_count: category.category_member_count,
                    sort_id: category.catogory_sort_id,
                },
            );
        }

        let mut friends: AHashMap<i64, Friend> = AHashMap::with_capacity(resp.friend_list.len());
        for mut friend in resp.friend_list {
            if let Some(mut sub_biz) = friend.sub_biz.remove(&1) {
                let nick_name = sub_biz.data.remove(&20002).unwrap_or_default();
                let personal_sign = sub_biz.data.remove(&102).unwrap_or_default();
                let remark = sub_biz.data.remove(&103).unwrap_or_default();
                let qid = sub_biz.data.remove(&27394).unwrap_or_default();
                let age = sub_biz.num_data.remove(&20037).unwrap_or_default();
                let gender = sub_biz.num_data.remove(&20009).unwrap_or_default();
                friends.insert(
                    friend.uin,
                    Friend {
                        uin: friend.uin,
                        uid: friend.uid,
                        nick_name,
                        personal_sign,
                        remark,
                        qid,
                        age,
                        gender: Gender::from_repr(gender).unwrap_or_default(),
                    },
                );
            }
        }

        Ok(FetchFriendResp {
            friends,
            categories,
            cookie: resp.cookie,
        })
    }
}

impl ServiceContext {
    pub async fn fetch_friends(
        &self,
    ) -> anyhow::Result<(AHashMap<i64, Friend>, AHashMap<i32, FriendCategory>)> {
        let mut friends = AHashMap::new();
        let mut categories = AHashMap::new();
        let mut cookie: Bytes = Bytes::default();
        loop {
            let resp = self
                .send_request::<FetchFriendService, FetchFriendReq, FetchFriendResp>(
                    FetchFriendReq {
                        cookie: cookie.clone(),
                    },
                )
                .await?;
            cookie = resp.cookie;
            friends.extend(resp.friends);
            categories.extend(resp.categories);
            if cookie.is_empty() {
                break;
            }
        }
        Ok((friends, categories))
    }
}

impl Bot {
    pub async fn fetch_friends(
        &self,
    ) -> anyhow::Result<(AHashMap<i64, Friend>, AHashMap<i32, FriendCategory>)> {
        self.service.fetch_friends().await
    }
}
