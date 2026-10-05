//! What a client asks to be told about, as nostr-push2 takes it: Tenna's
//! `NappSubscription`, some filters on some relays.
//!
//! The relays are kept and handed back by `get`, and otherwise ignored:
//! every filter is matched against this relay's own new events.
//!
//! nostr-push2 takes any filter that names something. This takes only the
//! shapes Armada sends (`buildPushSubscriptions` in its
//! `src/lib/pushSubscriptions.ts`), so the service can't be turned into a
//! general watcher of the relay:
//!
//! - gift wraps (1059) to one `#p`, for NIP-17 DMs, or by `authors`, for
//!   Concord streams;
//! - NIP-04 DMs (4) to one `#p` from some `authors`;
//! - NIP-29 group messages, replies and reactions (9, 1111, 7) in some `#h`
//!   groups, optionally to one `#p`.
//!
//! Armada asks for all of them in one `set`, wherever their relays are, so
//! they're all taken; the ones for kinds this relay doesn't store are kept,
//! but never [watched](Subscription::live_filters).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Ceilings on what one client may ask for, nostr-push2's.
pub const MAX_SUBSCRIPTIONS: usize = 100;
pub const MAX_FILTERS: usize = 10;
pub const MAX_RELAYS: usize = 10;
/// The longest list a filter may carry: ids, authors, kinds, tag values.
pub const MAX_LIST: usize = 500;

/// How far back NIP-59 may date a gift wrap, so how much a filter watching
/// them has its `since` widened by when it's matched.
const GIFT_WRAP_BACKDATE: i64 = 2 * 24 * 60 * 60;

const GIFT_WRAP: i64 = 1059;
const NIP04: i64 = 4;
/// NIP-29 group messages, comments, and reactions.
const GROUP_KINDS: &[i64] = &[9, 1111, 7];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    pub filters: Vec<Map<String, Value>>,
    pub relays: Vec<String>,
}

impl Subscription {
    /// The filters to match new events with: those for kinds this relay
    /// stores, with `since` widened for gift wraps, which are backdated.
    pub fn live_filters(&self) -> impl Iterator<Item = Value> + '_ {
        let stored = |kind: &Value| kind.as_u64().and_then(|kind| u16::try_from(kind).ok()).is_some_and(crate::relay::accepts_kind);
        self.filters.iter().filter(move |filter| filter.get("kinds").and_then(Value::as_array).is_some_and(|kinds| kinds.iter().any(stored))).map(|filter| {
            let mut filter = filter.clone();
            let wraps = filter.get("kinds").and_then(Value::as_array).is_some_and(|kinds| kinds.iter().any(|kind| kind.as_i64() == Some(GIFT_WRAP)));
            if let (true, Some(since)) = (wraps, filter.get("since").and_then(Value::as_i64)) {
                filter.insert("since".into(), (since - GIFT_WRAP_BACKDATE).max(0).into());
            }
            Value::Object(filter)
        })
    }
}

/// Check and tidy what a client passed to `set`, as of `now`. Errors are
/// the message to hand back.
pub fn normalize(input: &Value, now: i64) -> Result<Vec<Subscription>, String> {
    let Some(list) = input.as_array() else { return Err("Subscriptions must be an array".into()) };
    if list.len() > MAX_SUBSCRIPTIONS {
        return Err(format!("At most {MAX_SUBSCRIPTIONS} subscriptions"));
    }
    // Every subscription's shape first, then each filter, as nostr-push2
    // reports the first problem.
    let mut shaped = Vec::with_capacity(list.len());
    for subscription in list {
        let Some(subscription) = subscription.as_object() else { return Err("Each subscription must be an object".into()) };
        let filters = match subscription.get("filters").and_then(Value::as_array) {
            Some(filters) if filters.iter().all(Value::is_object) => filters,
            _ => return Err("Each subscription needs a filters array".into()),
        };
        if filters.is_empty() {
            return Err("Each subscription needs at least one filter".into());
        }
        if filters.len() > MAX_FILTERS {
            return Err(format!("At most {MAX_FILTERS} filters per subscription"));
        }
        let Some(relays) = subscription.get("relays").and_then(Value::as_array) else { return Err("Each subscription needs a relays array".into()) };
        let mut clean = Vec::with_capacity(relays.len());
        for relay in relays {
            let relay = relay.as_str().map(str::trim).filter(|relay| is_relay_url(relay)).ok_or("Relays must be ws:// or wss:// URLs")?;
            clean.push(relay.trim_end_matches('/').to_string());
        }
        if clean.is_empty() {
            return Err("Each subscription needs at least one relay".into());
        }
        if clean.len() > MAX_RELAYS {
            return Err(format!("At most {MAX_RELAYS} relays per subscription"));
        }
        shaped.push((filters, clean));
    }

    shaped
        .into_iter()
        .enumerate()
        .map(|(index, (filters, relays))| {
            let filters = filters.iter().map(|filter| normalize_filter(filter.as_object().unwrap(), index, now)).collect::<Result<_, _>>()?;
            let mut unique = Vec::with_capacity(relays.len());
            for relay in relays {
                if !unique.contains(&relay) {
                    unique.push(relay);
                }
            }
            Ok(Subscription { filters, relays: unique })
        })
        .collect()
}

fn is_relay_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some_and(|host| !host.is_empty()))
}

/// Keep only what can be matched, and insist the filter names something.
/// `limit` is dropped and `search` refused; `since` is raised to `now`, so a
/// subscription never fires for history.
fn normalize_filter(filter: &Map<String, Value>, index: usize, now: i64) -> Result<Map<String, Value>, String> {
    let mut clean = Map::new();
    let mut named = false;
    for (key, value) in filter {
        match key.as_str() {
            "ids" | "authors" => {
                let list = string_list(value, key)?;
                if !list.iter().all(|item| crate::nostr::event::is_hex64(item)) {
                    return Err(format!("Filter {key} must be 64-character lowercase hex"));
                }
                clean.insert(key.clone(), value.clone());
                named = true;
            }
            "kinds" => {
                let kinds = value.as_array().and_then(|kinds| kinds.iter().map(integer).collect::<Option<Vec<i64>>>()).ok_or("Filter kinds must be an array of integers")?;
                if kinds.len() > MAX_LIST {
                    return Err("Filter kinds is too long".into());
                }
                clean.insert(key.clone(), kinds.into());
                named = true;
            }
            "since" | "until" => {
                let number = value.as_f64().filter(|n| n.is_finite()).ok_or_else(|| format!("Filter {key} must be a number"))?;
                clean.insert(key.clone(), (number.floor() as i64).into());
            }
            "limit" => {}
            "search" => return Err("Filter search is not supported".into()),
            _ if is_tag_key(key) => {
                string_list(value, key)?;
                clean.insert(key.clone(), value.clone());
                named = true;
            }
            _ => return Err(format!("Filter key {key} is not supported")),
        }
    }
    if !named {
        return Err(format!("A filter in subscription {index} matches everything; name ids, authors, kinds or a tag"));
    }
    check_shape(&clean).map_err(|why| format!("A filter in subscription {index} {why}"))?;
    let since = clean.get("since").and_then(Value::as_i64).filter(|&since| since > now).unwrap_or(now);
    clean.insert("since".into(), since.into());
    Ok(clean)
}

/// Whether a filter is one Armada would send; see the module docs. Errors
/// finish the sentence "A filter in subscription N …".
fn check_shape(filter: &Map<String, Value>) -> Result<(), String> {
    for key in filter.keys() {
        if !matches!(key.as_str(), "kinds" | "authors" | "#p" | "#h" | "since" | "until") {
            return Err(format!("may not have {key}"));
        }
    }
    if filter.get("#p").and_then(Value::as_array).is_some_and(|p| p.len() != 1) {
        return Err("may name only one #p".into());
    }
    let kinds: Vec<i64> = filter.get("kinds").and_then(Value::as_array).map(|kinds| kinds.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
    let has = |key: &str| filter.contains_key(key);
    if kinds.is_empty() {
        return Err("needs kinds".into());
    }
    if kinds.iter().all(|&kind| kind == GIFT_WRAP) {
        if has("#h") || has("authors") == has("#p") {
            return Err("for gift wraps has to name either authors or #p".into());
        }
    } else if kinds.iter().all(|&kind| kind == NIP04) {
        if has("#h") || !has("authors") || !has("#p") {
            return Err("for NIP-04 DMs has to name authors and #p".into());
        }
    } else if kinds.iter().all(|kind| GROUP_KINDS.contains(kind)) {
        if has("authors") || !has("#h") {
            return Err("for groups has to name #h groups, and no authors".into());
        }
    } else {
        return Err("asks for kinds this service doesn't push, or for several at once".into());
    }
    Ok(())
}

fn string_list<'a>(value: &'a Value, key: &str) -> Result<Vec<&'a str>, String> {
    let list = value.as_array().and_then(|items| items.iter().map(Value::as_str).collect::<Option<Vec<_>>>()).ok_or_else(|| format!("Filter {key} must be an array of strings"))?;
    if list.len() > MAX_LIST {
        return Err(format!("Filter {key} is too long"));
    }
    Ok(list)
}

/// A whole number, however JSON wrote it.
fn integer(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_f64().filter(|n| n.fract() == 0.0 && n.abs() < 9.0e15).map(|n| n as i64))
}

fn is_tag_key(key: &str) -> bool {
    matches!(key.as_bytes(), [b'#', letter] if letter.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn one(filter: Value) -> Result<Map<String, Value>, String> {
        normalize(&json!([{"filters": [filter], "relays": ["wss://relay.example.com"]}]), NOW).map(|mut subs| subs.remove(0).filters.remove(0))
    }

    #[test]
    fn tidies_filters() {
        let filter = one(json!({"kinds": [1059.0], "#p": [HEX], "limit": 5, "since": 12.7})).unwrap();
        assert_eq!(Value::Object(filter), json!({"kinds": [1059], "#p": [HEX], "since": NOW}));
        let filter = one(json!({"kinds": [1059], "authors": [HEX], "since": NOW + 100, "until": NOW as f64 + 200.5})).unwrap();
        assert_eq!(Value::Object(filter), json!({"kinds": [1059], "authors": [HEX], "since": NOW + 100, "until": NOW + 200}));
    }

    #[test]
    fn refuses_what_nostr_push2_refuses() {
        for (filter, error) in [
            (json!({}), "A filter in subscription 0 matches everything; name ids, authors, kinds or a tag"),
            (json!({"since": 5}), "A filter in subscription 0 matches everything; name ids, authors, kinds or a tag"),
            (json!({"kinds": [1], "search": "x"}), "Filter search is not supported"),
            (json!({"kinds": [1], "foo": 1}), "Filter key foo is not supported"),
            (json!({"#pp": ["x"]}), "Filter key #pp is not supported"),
            (json!({"authors": ["AA"]}), "Filter authors must be 64-character lowercase hex"),
            (json!({"ids": [HEX.to_uppercase()]}), "Filter ids must be 64-character lowercase hex"),
            (json!({"authors": "x"}), "Filter authors must be an array of strings"),
            (json!({"kinds": [1.5]}), "Filter kinds must be an array of integers"),
            (json!({"kinds": [1], "since": "x"}), "Filter since must be a number"),
            (json!({"#t": vec!["x"; MAX_LIST + 1]}), "Filter #t is too long"),
            (json!({"kinds": vec![1; MAX_LIST + 1]}), "Filter kinds is too long"),
        ] {
            assert_eq!(one(filter.clone()).unwrap_err(), error, "{filter}");
        }
    }

    /// Every filter `buildPushSubscriptions` makes.
    #[test]
    fn takes_armadas_filters() {
        for filter in [
            json!({"kinds": [9], "#h": ["g1", "g2"]}),
            json!({"kinds": [9], "#h": ["g1"], "#p": [HEX]}),
            json!({"kinds": [1111, 7], "#h": ["g1"], "#p": [HEX]}),
            json!({"kinds": [1059], "#p": [HEX]}),
            json!({"kinds": [4], "#p": [HEX], "authors": [HEX]}),
            json!({"kinds": [1059], "authors": [HEX, HEX]}),
        ] {
            assert!(one(filter.clone()).is_ok(), "{filter}");
        }
    }

    #[test]
    fn refuses_what_armada_wouldnt_send() {
        for (filter, why) in [
            (json!({"#p": [HEX]}), "needs kinds"),
            (json!({"authors": [HEX]}), "needs kinds"),
            (json!({"kinds": [1], "#p": [HEX]}), "asks for kinds this service doesn't push, or for several at once"),
            (json!({"kinds": [1059, 4], "#p": [HEX], "authors": [HEX]}), "asks for kinds this service doesn't push, or for several at once"),
            (json!({"kinds": [1059, 9], "#h": ["g"]}), "asks for kinds this service doesn't push, or for several at once"),
            (json!({"kinds": [1059]}), "for gift wraps has to name either authors or #p"),
            (json!({"kinds": [1059], "#p": [HEX], "authors": [HEX]}), "for gift wraps has to name either authors or #p"),
            (json!({"kinds": [1059], "#p": [HEX], "#h": ["g"]}), "for gift wraps has to name either authors or #p"),
            (json!({"kinds": [1059], "#p": [HEX, HEX]}), "may name only one #p"),
            (json!({"kinds": [1059], "#p": []}), "may name only one #p"),
            (json!({"kinds": [4], "#p": [HEX]}), "for NIP-04 DMs has to name authors and #p"),
            (json!({"kinds": [9]}), "for groups has to name #h groups, and no authors"),
            (json!({"kinds": [9], "#h": ["g"], "authors": [HEX]}), "for groups has to name #h groups, and no authors"),
            (json!({"kinds": [1059], "#p": [HEX], "#e": [HEX]}), "may not have #e"),
            (json!({"kinds": [1059], "ids": [HEX], "#p": [HEX]}), "may not have ids"),
        ] {
            assert_eq!(one(filter.clone()).unwrap_err(), format!("A filter in subscription 0 {why}"), "{filter}");
        }
    }

    #[test]
    fn checks_the_shape() {
        let filter = json!({"kinds": [1059], "#p": [HEX]});
        let relay = "wss://relay.example.com";
        for (input, error) in [
            (json!({}), "Subscriptions must be an array"),
            (json!(vec![json!({"filters": [filter], "relays": [relay]}); MAX_SUBSCRIPTIONS + 1]), "At most 100 subscriptions"),
            (json!([{"relays": [relay]}]), "Each subscription needs a filters array"),
            (json!([{"filters": [], "relays": [relay]}]), "Each subscription needs at least one filter"),
            (json!([{"filters": vec![&filter; 11], "relays": [relay]}]), "At most 10 filters per subscription"),
            (json!([{"filters": [filter]}]), "Each subscription needs a relays array"),
            (json!([{"filters": [filter], "relays": []}]), "Each subscription needs at least one relay"),
            (json!([{"filters": [filter], "relays": ["https://x.example"]}]), "Relays must be ws:// or wss:// URLs"),
            (json!([{"filters": [filter], "relays": vec![relay; 11]}]), "At most 10 relays per subscription"),
            // Shapes before filters.
            (json!([{"filters": [{}], "relays": [relay]}, {"filters": [filter]}]), "Each subscription needs a relays array"),
        ] {
            assert_eq!(normalize(&input, NOW).unwrap_err(), error, "{input}");
        }
        assert_eq!(normalize(&json!([]), NOW).unwrap(), []);
        let subs = normalize(&json!([{"filters": [filter], "relays": [" wss://a.example/ ", "wss://a.example", "ws://b.example//"]}]), NOW).unwrap();
        assert_eq!(subs[0].relays, ["wss://a.example", "ws://b.example"]);
    }

    #[test]
    fn watches_only_what_the_relay_stores() {
        let filters = json!([{"kinds": [1059], "#p": [HEX]}, {"kinds": [9], "#h": ["g"]}, {"kinds": [4], "#p": [HEX], "authors": [HEX]}, {"kinds": [1059], "authors": [HEX]}]);
        let subs = normalize(&json!([{"filters": filters, "relays": ["wss://a.example"]}]), NOW).unwrap();
        assert_eq!(subs[0].filters.len(), 4);
        // Gift wraps alone, with since widened as they're backdated.
        let live: Vec<_> = subs[0].live_filters().collect();
        assert_eq!(live, [json!({"kinds": [1059], "#p": [HEX], "since": NOW - GIFT_WRAP_BACKDATE}), json!({"kinds": [1059], "authors": [HEX], "since": NOW - GIFT_WRAP_BACKDATE})]);
    }
}
