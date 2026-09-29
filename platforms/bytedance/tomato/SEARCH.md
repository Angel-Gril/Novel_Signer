# Tomato search interface report

## Static request model

The decompiled app constructs `GetSearchPageRequest`. The observed field model is:

```text
query, searchId, passback, correctedQuery, useCorrect, offset,
bookshelfSearchPlan, searchSource, tabType, tabName, targetMainId,
userIsLogin, bookstoreTab, clickedContent, searchSourceId, sourceBookId,
clientAbInfo, isFirstEnterSearch, fromHalfScreen, reportInfo, clientExtra
```

The existing Rust client had only a subset of these fields. The additional fields are now documented here rather than silently treated as optional proof of a working API.

## Live probes

Freshly signed probes used the current Helios/Medusa bridge and a current timestamp. The following paths all returned transport HTTP 200 with an empty body:

| Path | Body length | Interpretation |
| --- | ---: | --- |
| `/reading/bookapi/search/tab/v` | 0 | not confirmed |
| `/reading/bookapi/search/tab/v/` | 0 | not confirmed |
| `/reading/bookapi/search/page/v1/` | 0 | not confirmed |
| core-parameter variant with `bookshelf_search_plan`, `tab_type`, and `search_source` | 0 | not confirmed |

The empty-body SHA-256 is the standard empty stream hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. A complete parameter combination caused the current signer to time out in one probe, so it was not promoted to a success claim.

## Rust implication

`search.rs` remains a parameter-model scaffold. The downloader should report “search unverified” and allow a caller to supply a known book ID until a non-empty live search response is reproduced with the same evidence standard as directory and reader/full.
