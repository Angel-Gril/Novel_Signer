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

## Rust implication

`search.rs` remains a parameter-model scaffold. The downloader should report
“search unverified” and allow a caller to supply a known book ID until a
non-empty live search response is reproduced with the same evidence standard as
directory and reader/full.
