use std::vec;

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
    pub(crate) friends: Vec<Friend>,
    pub(crate) categories: Vec<FriendCategory>,
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
            req_count: Some(300),
            local_seq: Some(13),
            cookie: Some(req.cookie),
            flag: Some(1),
            proxy_seq: Some(i32::MAX as u32),
            request_biz: vec![
                IncPullRequestBiz {
                    biz_type: Some(1),
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
                    biz_type: Some(4),
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

        let categories: Vec<FriendCategory> = resp
            .category
            .into_iter()
            .map(|category| FriendCategory {
                id: category.category_id.unwrap_or_default(),
                name: category.category_name.unwrap_or_default(),
                member_count: category.category_member_count.unwrap_or_default(),
                sort_id: category.catogory_sort_id.unwrap_or_default(),
            })
            .collect();

        let friends: Vec<Friend> = resp
            .friend_list
            .into_iter()
            .filter_map(|mut friend| {
                let mut sub_biz = friend.sub_biz.remove(&1)?;

                let nick_name = sub_biz.data.remove(&20002).unwrap_or_default();
                let personal_sign = sub_biz.data.remove(&102).unwrap_or_default();
                let remark = sub_biz.data.remove(&103).unwrap_or_default();
                let qid = sub_biz.data.remove(&27394).unwrap_or_default();
                let age = sub_biz.num_data.remove(&20037).unwrap_or_default();
                let gender = sub_biz.num_data.remove(&20009).unwrap_or_default();

                Some(Friend {
                    uin: friend.uin.unwrap_or_default(),
                    uid: friend.uid.unwrap_or_default(),
                    nick_name,
                    personal_sign,
                    remark,
                    qid,
                    age,
                    gender: Gender::from_repr(gender).unwrap_or_default(),
                })
            })
            .collect();

        Ok(FetchFriendResp {
            friends,
            categories,
            cookie: resp.cookie.unwrap_or_default(),
        })
    }
}

impl ServiceContext {
    pub async fn fetch_friends(&self) -> anyhow::Result<(Vec<Friend>, Vec<FriendCategory>)> {
        let mut friends = Vec::new();
        let mut categories = Vec::new();
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
    /// 获取好友列表
    pub async fn fetch_friends(&self) -> anyhow::Result<(Vec<Friend>, Vec<FriendCategory>)> {
        self.service.fetch_friends().await
    }
}
