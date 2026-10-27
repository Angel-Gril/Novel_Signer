# DouYin_Spider 字节系接口对照（2026-10-28）

本记录只做接口和签名链路对照，不把第三方项目的请求成功当作七神 signer 已恢复。
分析对象是本地参考副本 `C:\AI\6\_external_DouYin_Spider`，其上游为
`cv-cat/DouYin_Spider`，当前副本 HEAD 为 `d151f9c`。

## 项目实际覆盖的接口面

主站 `dy_apis/douyin_api.py` 主要使用 `www.douyin.com/aweme/v1/web/`：作品详情、
用户资料、评论、搜索、收藏、关注、通知和 feed；另有 `/aweme/v2/shop/` 电商、
`/webcast/` 直播和 `/passport/` 登录/身份安全接口。创作者模块
`douyin_creator_api.py` 使用 `creator.douyin.com/web/api/`、上传授权、ImageX/TOS
上传和发布接口。直播 IM 使用 protobuf/WebSocket，而不是七神 header 返回链。

## 主站请求的签名组合

`builder/params.py` 的主站公共 query 以 `device_platform=webapp`、`aid=6383`、浏览器
指纹、`webid`、`UIFID`、`verifyFp/fp` 和惰性 `msToken` 为核心；`a_bogus` 由
`utils/ab_pure.py` 纯算生成，签名输入是实际编码后的 query/body，且 host 会影响
内嵌的 aid/page-id。部分接口对 `verifyFp/fp` 相对 `a_bogus` 的顺序不同，代码按端点
逐一处理。

写接口和部分受保护接口再叠加 `builder/header.py` 的 `bd-ticket-guard`：

- 会话材料来自登录响应的 `ticket`、`ts_sign`、`client_cert` 和私钥；
- `bd-ticket-guard-client-data` 绑定 pathname、ticket、时间戳和 ECDH/HKDF 材料；
- `bd-ticket-guard-ree-public-key`、version、web-version、web-sign-type 描述当前证书；
- 高风控/发布接口还要求按 pathname 与时间戳重算的 `x-tt-session-dtrait`。

只读接口使用的 `with_bd_readonly()` 有意省略 `client-data`，不能把发布接口的头集
无条件复用到读接口。`Params.signed_url()` 还处理少数 `x-secsdk-web-signature`
保护路径；它先对规范化 query 签名，再把最终 URL 原样发送，不能交给 HTTP 客户端
二次编码。

直播路径仍保留旧的 `X-Bogus` 生成器（`utils/xbogus_pure.py`），并使用不同的
`LIVE_HOST`/aid/query 组合。参考项目中没有发现可直接生成七神六个 header 的
`X-Gorgon`、`X-Argus`、`X-Ladon`、`X-Helios`、`X-Khronos`、`X-Medusa` signer；
出现的 `X-Bogus` 是直播 web 请求链上的另一套 token。

## 与七神研究的交集

交集在请求输入和风控材料，而不是已经闭合的输出 signer：

1. `aid`、host、pathname、query 字节序、时间戳、设备指纹、UIFID、msToken 和
   dtrait 都会影响服务端验收，这与我们在 native VM 中追踪的 request 输入边界一致。
2. 参考项目把 `a_bogus`、`bd-ticket-guard`、`x-tt-session-dtrait` 分成独立 owner；
   我们当前 ELF 证据只闭合了 native request VM 的 formatter/树返回路径，尚未把
   这些 web 层材料送入真实 Android JVM/native signer。
3. 本项目的 URL/API 成功不能证明 `libmetasec_ml` 已生成六个七神 header；现有
   `vm9_native_outer_facade_actual_child_20261027.json` 仍明确标记
   `fresh_standalone_signer_verified=false` 和 `online_header_acceptance_verified=false`。

## 对当前研究的可执行结论

- 可以把该项目作为 **web API 输入/头部顺序和端点清单参考**，尤其是
  `a_bogus` 输入规范化、`bd-ticket-guard` 会话绑定和 dtrait 的 pathname 绑定。
- 不能把其纯 Python `a_bogus`/`X-Bogus` 当作七神 native signer 的替代实现，也不能
  用随机 `msToken`、静态 dtrait 或跨 host 的证书材料宣称线上可用。
- 当前 native differential 的下一项仍应是：在真实 facade/JNI 输入下记录同一请求的
  URL/header vector、时间戳和会话材料，然后对照 web 端最终请求；不要把 `-11`、`-5`
  或 `0x101` 解释成六个 header 的业务状态码。

## 证据边界

本报告来自本地源代码静态检查；未执行登录、未读取用户 Cookie/私钥、未向抖音发起
线上请求，也未宣称任何接口绕过风控。native 入口 ABI 的动态/静态证据见
[`vm9_request_entry_abi_provenance_20261027.json`](evidence/vm9_request_entry_abi_provenance_20261027.json)。
