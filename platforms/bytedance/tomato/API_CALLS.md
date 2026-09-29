# Tomato API call report

All paths below are relative to the current normal Tomato API host. Query strings in the public report are described by field name only; the original values are intentionally omitted.

## 1. Device registration

`POST /service/2/device_register/`

This request is sent to the ByteDance logging registration service and does not use the Tomato reading Medusa header. The body contains the application profile and a generated device fingerprint. The response supplies identifiers consumed by later requests. Raw identifiers are not published.

## 2. Register the chapter key

`POST /reading/crypt/registerkey`

The body contains a JSON `content` field and a key-version field. The content is an AES-CBC envelope: the first 16 bytes are the IV text and the remaining bytes encrypt little-endian device/user values. The returned `data.key` is another AES-CBC envelope under the application register key. The decoded result is a per-session chapter key.

Observed public summary:

| Property | Result |
| --- | --- |
| HTTP status | 200 |
| response body | JSON, non-empty in the successful trial |
| key version | 598113575 |
| per-session key | intentionally omitted |

## 3. Chapter directory

`GET /reading/directory/detail`

The current signer supplies `X-Helios`, `X-Medusa`, and `X-Khronos`. The accepted response contained 611 chapter entries.

## 4. Chapter body

`GET /reading/reader/full/v1/` (the batch/full family uses the same content key path)

The response is a JSON envelope containing a base64 chapter payload. In the fresh trial, `crypt_status=0`, the payload decrypted to 6,496 bytes of HTML, and the plaintext SHA-256 is:

```text
13e2415e7bef414a197a62aca08ccb11bf9cf436bc3f955b676fa03fac2fa2f7
```

## 5. Header matrix

The fresh single-variable matrix was repeated for detail, directory, and reader/full:

| Case | Result |
| --- | --- |
| Helios + Medusa + Khronos | HTTP 200 with a non-empty response |
| add Gorgon/Ladon/Argus | HTTP 200 with a non-empty response |
| add Perseus | HTTP 200 with a non-empty response |
| remove Perseus | HTTP 200 with a non-empty response |
| remove Medusa | HTTP 200, zero-length response |

The zero-length body is an application failure even though the transport status is 200. The matrix is valid only while the timestamp is inside the server acceptance window.

## 6. Search

The decompiled search feed calls `u15.c.i0(GetSearchPageRequest)` after building
the request in `uf3.c`. The observed paths are:

```text
GET /reading/bookapi/search/tab/v
GET /reading/bookapi/search/page/v/
```

The page request always sets `bookshelfSearchPlan=4` in the feed path. It carries
`query`, `searchId`, `passback`, `correctedQuery`, `useCorrect`, `offset`,
`searchSource`, `tabType`, `tabName`, and `targetMainId`; an optional context
adds login, bookstore, click, source-book, source-id, and client-ab fields.
`PlaceUtils.addPlaceColumnParams` may add further fields. A current signed probe
to the page path returned HTTP 200 with an empty body, so the endpoint shape is
static/runtime verified but a usable search response is not yet live verified.
