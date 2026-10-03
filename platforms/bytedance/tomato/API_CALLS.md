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

For the current `7.1.3.32` profile, the 2026-10-03 first-stage probes with
numeric `is_first_enter_search=1`, one session pair, offset/passback 0 and
`tab_type=3` still return an empty body on b/c hosts. No current search ID or
page 2 is verified. A separate external Java service configured with
`6.8.1.32` returned 9/10 books across two pages, reusing its search ID. Its
controller maps `offset=(page-1)*size`; the source first obtains an ID, then
continues with `is_first_enter_search=0`. Its cache and normalized responses
are not raw upstream evidence. Versioned details are in [SEARCH.md](SEARCH.md).

After correcting `MSC.GetABSwitch()` to APK default `2`, an unrounded fresh
detail request returned HTTP 200, code 0 and 24,341 bytes. Retesting current
first-stage search on both hosts still returned zero bytes and no search ID.
The correction fixes the observed bridge initialization failure and does
not establish current search availability. See `BRIDGE_INITIALIZATION.md`
and `evidence/search_current_ab_corrected_20261003.json`.

The fresh 2026-09-29 probe repeated this against `tab/v`, `tab/v/`, `page/v1/`,
and `page/v/` with synchronized request timestamp fields. Every request was
HTTP 200 with a zero-byte body and the empty-stream SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. This
confirms the current signer can reach all four route shapes; it does not prove
that the search query is accepted or that a result payload is available. See
`evidence/search_current_probe_20260929.json` for the redacted per-route
summary.

The APK native request hook separately exposed the first page shape as the
`sinfonlineb` host with `query`, `offset=0`, and `aid=1967`. A fresh replay of
that exact visible shape also returned HTTP 200 with zero bytes. Its redacted
record is `evidence/search_exact_app_probe_20260929.json`; the result keeps
search availability open while confirming that the app-observed host is
reachable with a current signed request.
