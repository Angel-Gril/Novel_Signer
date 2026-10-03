# Tomato search interface report

## Static request model and endpoint

The decompiled search feed constructs `GetSearchPageRequest` in `uf3.c` and
dispatches it through `u15.c.i0(request)`. The observed field model is:

```text
query, searchId, passback, correctedQuery, useCorrect, offset,
bookshelfSearchPlan, searchSource, tabType, tabName, targetMainId,
userIsLogin, bookstoreTab, clickedContent, searchSourceId, sourceBookId,
clientAbInfo, isFirstEnterSearch, fromHalfScreen, reportInfo, clientExtra
```

The feed sets `bookshelfSearchPlan = 4`, assigns the first ten fields directly,
then overlays optional `xc3.a` context fields (`userIsLogin`, `bookstoreTab`,
`clickedContent`, `searchSourceId`, `sourceBookId`, `clientAbInfo`, and the
context `searchSource`). It calls `PlaceUtils.addPlaceColumnParams` before
dispatch. The optional fields added by `PlaceUtils` are not fully verified.

The runtime URL observed in the HTTP hook is:

```text
GET /reading/bookapi/search/page/v/?query=...&offset=0&aid=1967
```

The tab request used by the same feed is `/reading/bookapi/search/tab/v`.

The APK's first page request was also observed in the native request hook as
`api5-normal-sinfonlineb.fqnovel.com/reading/bookapi/search/page/v/` with only
the serialized query, `offset=0`, and `aid=1967` visible at that boundary. This
is evidence against assuming that the earlier `sinfonlinec` host and a large
hand-written query are the app's first request. The app's request layer can
still add headers, context, and serialized defaults before the network call.

## Live probes

Freshly signed probes used the current Helios/Medusa bridge and a current
timestamp. The following paths returned transport HTTP 200 with an empty body:

| Path | Body length | Interpretation |
| --- | ---: | --- |
| `/reading/bookapi/search/tab/v` | 0 | not confirmed |
| `/reading/bookapi/search/tab/v/` | 0 | not confirmed |
| `/reading/bookapi/search/page/v/` | 0 | endpoint shape confirmed, application result not confirmed |
| core-parameter variant with `bookshelf_search_plan`, `tab_type`, and `search_source` | 0 | not confirmed |

The empty-body SHA-256 is the standard empty stream hash
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. A
complete parameter combination caused the current signer to time out in one
probe, so it was not promoted to a success claim.

## Fresh online probe (2026-09-29)

The current Java/Unidbg bridge was rerun with a synchronized `_rticket` and
frozen timestamp grid (`1790684200000`) before each request. Four endpoint
shapes were signed and sent with the application-style query model:

| Path | HTTP | Body | SHA-256 |
| --- | ---: | ---: | --- |
| `/reading/bookapi/search/tab/v` | 200 | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `/reading/bookapi/search/tab/v/` | 200 | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `/reading/bookapi/search/page/v1/` | 200 | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `/reading/bookapi/search/page/v/` | 200 | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

These are fresh negative results: signing and transport succeeded, but the
application returned no JSON object or book list. The endpoint model remains
runtime-confirmed while the non-empty search response remains unverified. The
redacted machine-readable record is
`evidence/search_current_probe_20260929.json`.

A separate exact-shape replay used the APK-observed `sinfonlineb` host and
`query=三体&offset=0&aid=1967`. The current bridge generated a complete
`X-Medusa` sample and the server returned HTTP 200 with a zero-byte body. The
redacted result is `evidence/search_exact_app_probe_20260929.json`; it is a
negative result, so request reachability is separated from the remaining
search-context or server-gating problem.

## Older-profile service pagination (2026-10-03)

An external Java service configured with request profile `6.8.1.32`
(`version_code=68132`, oversea package UA) returned two non-empty responses
from its local `/search` endpoint. The measured jar and its embedded native
library are pinned by SHA-256; the native artifact's app-version association
and the exact on-wire profile were not independently captured.

| Local request | HTTP / code | Books | Pagination |
| --- | --- | ---: | --- |
| `key=三体&page=1&size=10&tabType=3` | 200 / 0 | 9 | `hasMore=true`, search ID present |
| page 2, same keyword/size/tab and returned search ID | 200 / 0 | 10 | same search ID, `hasMore=true` |

All returned book IDs are present and unique within each page. The second
page contains ten new books with no overlap with page 1. Search ID values,
device data, headers and raw responses remain private. The sanitized record
is [search_legacy_pagination_20261003.json](evidence/search_legacy_pagination_20261003.json).

The service uses cache, retries, a device pool and response normalization;
cache bypass and a raw upstream capture are unverified. This proves the
measured service returned a usable two-page result under its older configured
profile. It does not prove current `7.1.3.32` search or no-JVM operation.

The source-derived flow uses `/reading/bookapi/search/tab/v`. Its configured
base host is `sinfonlineb`, but `getSearchApiBaseUrl()` rewrites search requests
to `sinfonlinec`. Without a search ID it first requests
`is_first_enter_search=1`, then reuses the returned ID and session pair with
`is_first_enter_search=0` and a page interval. Page numbers start at 1;
`offset=(page-1)*size` and `passback=offset`. This source serializes booleans
as `1/0`.

## Current first-stage session probe (2026-10-03)

The current bridge was tested with the registered device/profile used by a
successful detail control, one session pair, numeric first-enter flags,
`tab_type=3`, count 10, offset/passback 0, and source-derived behavior/runtime
fields. The two requests changed only the b/c host, used the same frozen
timestamp, and both generated 801-byte Medusa outputs.

Both returned HTTP 200 with **zero bytes** and no search ID in the body or
checked search-ID headers. Phase 2 and pagination therefore did not run;
a search ID from the older service was not substituted. Full APK request-header
equivalence remains unverified. See
[search_current_phase1_20261003.json](evidence/search_current_phase1_20261003.json).

These results leave current native/profile and request-context differences
open; two-stage pagination is a verified older-service flow, not a current
search fix.

## Rust implication

`api.rs::search_params` remains a parameter-model scaffold. The downloader should report
“current search unverified” and allow a caller to supply a known book ID until a
non-empty live search response is reproduced with the same evidence standard as
directory and reader/full.
