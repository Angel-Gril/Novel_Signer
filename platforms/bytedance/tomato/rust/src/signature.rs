use crate::signer::{argus, gorgon, ladon};
use crate::status::CapabilityError;
use std::collections::BTreeMap;

pub fn khronos(timestamp_seconds: u64) -> String {
    timestamp_seconds.to_string()
}

/// Verified pure-Rust legacy/auxiliary headers. These headers are not enough
/// for the current reading server; Helios + current Medusa remain required.
pub fn legacy_headers(query: &str, timestamp_seconds: u64, device_id: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert("X-Khronos".into(), khronos(timestamp_seconds));
    out.insert(
        "X-Gorgon".into(),
        gorgon::get_xgorgon(query, "", "", timestamp_seconds),
    );
    out.insert(
        "X-Ladon".into(),
        ladon::encrypt(timestamp_seconds, 1_611_921_764, 1967),
    );
    out.insert(
        "X-Argus".into(),
        argus::get_sign(query, None, timestamp_seconds, 1967, device_id, "7.1.3.32"),
    );
    out
}

pub fn current_headers(_query: &str, _timestamp_seconds: u64) -> Result<BTreeMap<String, String>, CapabilityError> {
    Err(CapabilityError {
        component: "current Tomato header set",
        reason: "X-Helios and current X-Medusa are not independently available in the default no-JVM crate",
    })
}
