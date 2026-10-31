# DouYin_Spider 与 Tomato 移动端签名边界

外部对照仓库：[`cv-cat/DouYin_Spider`](https://github.com/cv-cat/DouYin_Spider)，
审阅固定在提交 `d151f9c`（2026-10-31）。这里只记录协议和调用边界，不把外部仓库
当作本项目的运行时证据，也不复制其账号、Cookie 或设备档案。

## 外部项目实际实现的接口

| 入口/域 | 代码位置 | 作用 |
| --- | --- | --- |
| `www.douyin.com` Web XHR | `utils/ab_pure.py`、`utils/secsdk_web_sign.py` | `a_bogus` 与 `x-secsdk-web-signature`；前者是带站点 `aid/page_id` 的自定义 VM 算法，后者是对规范化 query 加 `uifid/timestamp/固定盐` 后做 MD5。 |
| Web/直播参数 | `utils/xbogus_pure.py`、`utils/dy_util.py` | `X-Bogus`，使用请求摘要、计数器、浏览器环境位和 RC4/自定义 Base64。 |
| 登录/写接口 | `utils/bd_ticket.py`、`builder/header.py` | `bd-ticket-guard-*`，包含客户端数据、服务端公钥、版本和 ECDSA/HMAC 分支；凭证与 Cookie 会话绑定。 |
| 评论/私信等高风控写接口 | `utils/dtrait.py`、`utils/dtrait_features.py` | `x-tt-session-dtrait`，设备特征内层加 AES-CBC，外层 RSA PKCS#1 v1.5；payload 按 pathname 和时间重建。 |
| `mssdk.bytedance.com` | `utils/strdata_pure.py`、`utils/mstoken.py` | `strData`/`msToken` 上报；设备档案字段与随机 nonce、时间戳参与编码。 |
| 直播/私信 WebSocket | `dy_live/`、`dy_apis/douyin_recv_msg.py` | Webcast/IM protobuf 与 websocket 传输，不是移动端 Cronet signer。 |

这些接口依赖 Web Cookie、`UIFID`、`s_v_web_id`、`ttwid`、浏览器环境档案或登录域证书。
“纯 Python”只表示算法实现移除了 Node 运行时，并不等于脱离会话凭证即可在线通过。

## 与当前七神研究的对应关系

Tomato 当前移动端普通请求的静态/运行时边界是：

```text
ms.bd.c.r4.onCallToAddSecurityFactor
    -> native tag 0x3000001
    -> X-Argus / X-Gorgon / X-Helios / X-Khronos / X-Ladon / X-Medusa
```

独立的 Java API 是 `MSManager.frameSign(String,int)`，对应 native tag
`0x200000A`，返回 `frametype/lid/signinfo/signvalue/signversion` 五组键值。
官方 APK 的 Cronet 方法还存在 native JNI 间接分发边界，但在已完成的 arm64
Gadget 业务窗口中没有观察到 Cronet Java 方法被调用。

固定提交的 `DouYin_Spider` 中没有以下移动端入口或字段：

* `X-Argus`、`X-Gorgon`、`X-Helios`、`X-Khronos`、`X-Ladon`、`X-Medusa`
* `frameSign`、`addSecurityFactor`、`CronetUrlRequest`
* Tomato 的 native tag `0x3000001`/`0x200000A`

因此外部项目没有直接恢复当前移动端七神 signer，也不能作为 whole-request native/Python
差分、独立 signer 或线上六头接受证据。可复用的部分是 Web 侧的域/路径分层、参数规范化、
会话绑定和“外层头必须按实际发送字节重算”的方法论；这些不能替换 Tomato 的 native
JNI/provider 与 Android 运行时边界。

## 当前结论

我们在七神研究中已经闭合了官方 7.2.5.32 APK 的六头 callback、native tag 归属、
Cronet 静态调用边界和 native JNI 间接边界；`DouYin_Spider` 对照没有新增移动端
signer 实现。完整 standalone signer、整请求 native/Python 差分、Cronet 真实业务分支
和线上验签仍需独立证据，不能用 Web 项目的 `a_bogus/X-Bogus` 结果替代。

