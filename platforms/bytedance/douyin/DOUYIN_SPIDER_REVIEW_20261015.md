# DouYin_Spider 接口与现有七神研究对照

分析日期：2026-10-15 Asia/Shanghai。对象为
[`cv-cat/DouYin_Spider`，提交 `fc8b9c2490a9561265425c26058290f01c064eda`](https://github.com/cv-cat/DouYin_Spider/tree/fc8b9c2490a9561265425c26058290f01c064eda)。
本次读取22个相关源码/说明文件，检查接口、签名调用和会话依赖；未运行其登录、
采集或写操作，未进行线上接口验收。下文的“有实现”只描述该提交源码。

## 结论

该项目主要实现**抖音浏览器端接口和会话流程**。我们的七神研究主要围绕
Android App 的请求头和番茄 native SDK。现有成果没有验证该项目的抖音 Web
接口，也不能由它的 `a_bogus` 实现推导当前 App Medusa 已经完成。

我们已验证番茄 Java/Unidbg 桥接的目录、正文和章节解密，恢复了 Helios 等组件；
当前 Medusa 独立 fresh-input Python signer 仍在开发。抖音 App 目录中的传统
四头材料仍属于社区源码证据，缺少当前版本线上矩阵。详见
[番茄完成度](../tomato/COMPLETE_ANALYSIS_AND_USAGE.md#1-完成度结论)、
[签名模块边界](../tomato/COMPLETE_ANALYSIS_AND_USAGE.md#3-签名与解密模块)和
[抖音材料边界](REPORT.md#confidence-boundary)。

## 源码中的接口范围

| 范围 | 源码中的代表接口/流程 | 我们已有对应线上证据 |
| --- | --- | --- |
| 作品/用户 | `/aweme/v1/web/aweme/detail/`、`aweme/post/`、`user/profile/other/` | 无抖音 Web 验收 |
| 评论 | `/aweme/v1/web/comment/list/`、`comment/list/reply/` | 无 |
| 搜索 | `/aweme/v1/web/general/search/single/`、`search/item/`、`discover/search/`、`live/search/` | 无；番茄搜索记录属于另一产品 |
| 社交/信息流 | `user/follower/list/`、`user/following/list/`、`notice/`、`module/feed/`、收藏列表 | 无 |
| 直播 REST | `/webcast/room/web/enter/`、`linkmic/list/`、`ranklist/audience/`、PK榜 | 无 |
| 直播 WebSocket | `webcast100-ws-web-hl.douyin.com/webcast/im/push/v2/`，protobuf事件 | 无 |
| 私信 | `imapi.douyin.com` 会话创建/查询、消息发送；`frontier-im.douyin.com/ws/v2` 接收 | 无 |
| 账号登录 | `ttwid` 注册、Passport二维码、手机号验证码、challenge和ticket证书 | 无 |
| 互动写接口 | 评论发布、点赞、收藏/移动，以及直播聊天/点赞 | 无；本次未调用 |
| 创作者中心 | 上传授权、封面任务、图集/视频上传及发布 | 无；本次未调用 |
| ImageX/VOD | `imagex.bytedanceapi.com`、`vod.bytedanceapi.com` 上传申请/提交 | 无 |

主要定位：[作品/搜索/直播/私信 API](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/dy_apis/douyin_api.py)、
[创作者 API](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/dy_apis/douyin_creator_api.py)、
[登录 API](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/dy_apis/login_api.py)、
[直播 WebSocket](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/dy_live/server.py#L178)、
[私信 WebSocket](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/dy_apis/douyin_recv_msg.py#L42)。

## 签名和会话分别由什么负责

| 机制 | 该项目的源码职责 | 与我们七神工作的关系 |
| --- | --- | --- |
| `a_bogus` | Python处理query/body，按www/live/creator选择host常量；含时间、随机数等输入 | Web签名；没有关闭App Medusa边界 |
| X-Bogus | 直播连接参数签名辅助 | 无本项目同接口对照 |
| `x-secsdk-web-signature` | 对策略覆盖路径追加时间和签名；保留规范化query顺序 | Web请求组装经验可参考 |
| `msToken`、`ttwid`、`UIFID` | token获取/刷新、Cookie与设备会话 | 签名之外仍需会话状态 |
| `bd-ticket-guard` | ECDSA/HMAC、证书和请求client-data | 会话/证书流程，非七神替代实现 |
| `x-tt-session-dtrait` | 依赖设备profile，按路径/时间生成写接口头 | 尚未在我们项目验证 |
| acrawler/challenge | 页面挑战与登录辅助；部分场景调用Node | 源码宣称主签名纯Python，不等于所有场景无外部运行时 |
| ImageX/VOD签名 | 临时上传凭证上的AWS4-HMAC-SHA256形式签名 | 上传网关认证，与App七神分开验收 |

关键源码：
[a_bogus输入](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/utils/ab_pure.py#L285)、
[参数顺序与host](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/builder/params.py#L163)、
[签名URL编码](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/builder/params.py#L181)、
[持久会话和Cookie scope](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/builder/auth.py#L484)、
[上传签名](https://github.com/cv-cat/DouYin_Spider/blob/fc8b9c2490a9561265425c26058290f01c064eda/utils/imagex_sign.py#L1)。

检查的22个文件中，没有发现 `X-Gorgon`、`X-Khronos`、`X-Ladon`、`X-Argus`、
`X-Helios`、`X-Medusa`、`X-Neptune`、`X-Perseus` 名称。这个结果仅限所读文件；
可直接观察到的请求签名链是上述Web机制。代码注释中的 `ArgusSecurityPlugin`
名称本身不能证明生成了App的 `X-Argus`。

## 对继续开发的实际帮助

1. 以后单独扩展抖音Web能力时，可以按接口拆分只读验收，复核query/body编码、
   签名前后追加字段、不同子域常量及Cookie scope。
2. 直播/IM需同时处理握手签名、protobuf和会话恢复；REST成功不能代替WebSocket验收。
3. 当前主线继续恢复番茄JNI/VM请求链和独立Medusa。该项目没有提供可直接接入的
   当前App七神实现，本次不据其源码增加“已验证线上接口”数量。

## 2026-10-24 上游 HEAD 复核

为避免把旧快照当成当前接口，本次又读取了上游 HEAD
`d151f9c2980abc304c1ae4918c2272675cd9e4c2`（相对本报告记录的
`fc8b9c2490a9561265425c26058290f01c064eda` 前进两个提交）。这仍是
**Static only**：只读取公开源码，未使用账号、Cookie、原始响应或线上写接口。

上游新增内容分成两组：

| 上游变化 | 可确认的接口边界 | 对七神主线的结论 |
| --- | --- | --- |
| 浏览器指纹/dtrait 与 Cookie wire 顺序 | `x-tt-session-dtrait` 按 path 重算；`UIFID`、`ttwid`、`msToken`、`web_sign_token` 和 passport Cookie 分阶段维护；creator 域使用独立 `ms_appid=2906` 的 `msToken` | 这是 Web 会话与风控输入，不能替换 App 的 `X-Helios/X-Medusa`；可参考“签名之外的会话状态”建模 |
| 直播 protobuf 与运行入口 | `webcast100-ws-web-hl.douyin.com/webcast/im/push/v2/`，`PushFrame/Response`、gzip、ack、心跳和约 2900 个 protobuf message 定义 | 这是 WebSocket 传输/解码层；与 Tomato 的 HTTP 阅读矩阵和 VM9 signer 没有可直接复用的算法证据 |
| 登录与发布二次验证 | `passport/web/*`、`ticket_guard/get_client_cert`、`x-tt-verify-passport-decision`，发布链可进入扫码二次验证 | 说明会话、设备指纹、证书和签名是分层依赖；没有证明 App 七神头已经完成 |
| creator 与媒体上传 | ImageX `ApplyImageUpload/CommitImageUpload`、VOD `ApplyUploadInner/CommitUploadInner`，AWS V4 网关签名 | 属于上传网关认证；不应并入 Tomato `X-Argus/X-Helios/X-Medusa` 结论 |

当前 HEAD 的源码检索仍找不到 `X-Gorgon`、`X-Khronos`、`X-Ladon`、`X-Argus`、
`X-Helios`、`X-Medusa`、`X-Neptune` 或 `X-Perseus` 生成逻辑；能直接看到的是
`a_bogus`、直播 `X-Bogus`、`x-secsdk-web-signature` 和 `x-tt-session-dtrait`。
因此本次复核没有改变现有证据等级：Douyin 目录仍是 **Static only**，
`verified_live_requests` 仍为空；Tomato 目录已测得的 `X-Helios + X-Medusa`
阅读请求仍只属于 Tomato 产品和对应版本，不能外推到 Douyin App。

上游差异还揭示了一个可复用的研究方向：以后若取得 Douyin App 的一组完整抓包，
应把 `query/body canonicalization`、设备/会话 Cookie、dtrait、WebSocket 或 REST
传输和六/七神头分开做一变量矩阵；不能把浏览器 `a_bogus` 的成功或 HTTP 200
当作 App Medusa 的验收。

“七神”指历史请求头命名：传统六名为Gorgon、Ladon、Argus、Khronos、Helios、
Medusa，Neptune常被列为第七个软字段；Perseus另行跟踪。16个selector空间也不
代表16套算法已经全部完成。详见
[命名与完成度说明](../tomato/COMPLETE_ANALYSIS_AND_USAGE.md#对六神七神1624-神的准确结论)。
