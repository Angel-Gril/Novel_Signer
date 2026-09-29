use std::collections::BTreeMap;

pub const DIRECTORY_PATH: &str = "/reading/directory/detail";
pub const READER_FULL_PATH: &str = "/reading/reader/full/v1/";
pub const REGISTERKEY_PATH: &str = "/reading/crypt/registerkey";
pub const SEARCH_TAB_PATH: &str = "/reading/bookapi/search/tab/v";
pub const SEARCH_PAGE_PATH: &str = "/reading/bookapi/search/page/v/";

/// Static model extracted from `GetSearchPageRequest`.
///
/// The current live probes still return HTTP 200 with an empty body, so this
/// builder is intentionally just a parameter model and does not claim search
/// success.
pub fn search_params(query: &str, offset: u32) -> BTreeMap<String, String> {
    let mut p = BTreeMap::new();
    p.insert("query".into(), query.into());
    p.insert("offset".into(), offset.to_string());
    p.insert("use_correct".into(), "false".into());
    p.insert("bookshelf_search_plan".into(), "4".into());
    p.insert("search_source".into(), "1".into());
    p.insert("tab_type".into(), "0".into());
    p.insert("is_first_enter_search".into(), "true".into());
    p.insert("from_half_screen".into(), "false".into());
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_model_contains_current_fields() {
        let p = search_params("三体", 0);
        assert_eq!(p.get("bookshelf_search_plan"), Some(&"4".to_string()));
        assert_eq!(p.get("query"), Some(&"三体".to_string()));
        assert_eq!(SEARCH_PAGE_PATH, "/reading/bookapi/search/page/v/");
    }
}
