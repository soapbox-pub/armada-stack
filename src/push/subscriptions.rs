//! What a client asks to be told about, as nostr-push2 takes it: Tenna's
//! `NappSubscription`, some filters on some relays.
//!
//! The relays are kept and handed back by `get`, and otherwise ignored:
//! every filter is matched against this relay's own new events.
//!
//! nostr-push2 takes any filter that names something. This relay only
//! stores one kind anyone would want a push for, gift wraps, so this takes
//! filters for those alone, in the shapes Armada sends
//! (`buildPushSubscriptions` in its `src/lib/pushSubscriptions.ts`): to one
//! `#p`, for NIP-17 DMs, or by `authors`, for Concord streams.
//!
//! Armada also asks, in the same `set`, for NIP-04 DMs and NIP-29 group
//! kinds on other relays. Refusing those would refuse the whole `set`, DMs
//! included, so filters only for kinds the relay doesn't take are dropped
//! instead: neither kept nor watched.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Ceilings on what one client may ask for, nostr-push2's.
pub const MAX_SUBSCRIPTIONS: usize = 100;
pub const MAX_FILTERS: usize = 10;
pub const MAX_RELAYS: usize = 10;
/// The longest list a filter may carry: ids, authors, kinds, tag values.
pub const MAX_LIST: usize = 500;
/// The most a client's subscriptions may come to as JSON, once tidied, so
/// `get`'s answer always fits in one NIP-44 message (65,535 bytes) beside
/// its id. Tidying can make them longer than the request that set them.
pub const MAX_SIZE: usize = 60_000;

/// How far back NIP-59 may date a gift wrap, so how much a filter watching
/// them has its `since` widened by when it's matched.
const GIFT_WRAP_BACKDATE: i64 = 2 * 24 * 60 * 60;

const GIFT_WRAP: i64 = 1059;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    pub filters: Vec<Map<String, Value>>,
    pub relays: Vec<String>,
}

impl Subscription {
    /// The filters to match new events with: `since` widened, as gift
    /// wraps are backdated.
    pub fn live_filters(&self) -> impl Iterator<Item = Value> + '_ {
        self.filters.iter().map(|filter| {
            let mut filter = filter.clone();
            if let Some(since) = filter.get("since").and_then(Value::as_i64) {
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

    let mut subscriptions = Vec::with_capacity(shaped.len());
    for (index, (filters, relays)) in shaped.into_iter().enumerate() {
        let filters: Vec<_> = filters.iter().map(|filter| normalize_filter(filter.as_object().unwrap(), index, now)).filter_map(Result::transpose).collect::<Result<_, _>>()?;
        // Nothing left that could match here.
        if filters.is_empty() {
            continue;
        }
        let mut unique = Vec::with_capacity(relays.len());
        for relay in relays {
            if !unique.contains(&relay) {
                unique.push(relay);
            }
        }
        subscriptions.push(Subscription { filters, relays: unique });
    }
    if serde_json::to_string(&subscriptions).expect("JSON serializes").len() > MAX_SIZE {
        return Err(format!("Subscriptions come to more than {MAX_SIZE} bytes"));
    }
    Ok(subscriptions)
}

fn is_relay_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some_and(|host| !host.is_empty()))
}

/// Keep only what can be matched, and insist the filter names something.
/// `limit` is dropped and `search` refused; `since` is raised to `now`, so a
/// subscription never fires for history. `None` for a filter only for kinds
/// the relay doesn't take.
fn normalize_filter(filter: &Map<String, Value>, index: usize, now: i64) -> Result<Option<Map<String, Value>>, String> {
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
                // Within an event's `created_at`, which also keeps it short.
                clean.insert(key.clone(), (number.floor().clamp(0.0, f64::from(u32::MAX)) as i64).into());
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
    let kinds: Vec<i64> = clean.get("kinds").and_then(Value::as_array).map(|kinds| kinds.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
    let stored = |kind: &i64| u16::try_from(*kind).is_ok_and(crate::relay::accepts_kind);
    if !kinds.is_empty() && !kinds.iter().any(stored) {
        return Ok(None);
    }
    check_shape(&clean, &kinds).map_err(|why| format!("A filter in subscription {index} {why}"))?;
    let since = clean.get("since").and_then(Value::as_i64).filter(|&since| since > now).unwrap_or(now);
    clean.insert("since".into(), since.into());
    Ok(Some(clean))
}

/// Whether a filter is one for gift wraps Armada would send; see the
/// module docs. Errors finish the sentence "A filter in subscription N …".
fn check_shape(filter: &Map<String, Value>, kinds: &[i64]) -> Result<(), String> {
    if kinds.is_empty() || kinds.iter().any(|&kind| kind != GIFT_WRAP) {
        return Err("may only ask for gift wraps (kind 1059)".into());
    }
    for key in filter.keys() {
        if !matches!(key.as_str(), "kinds" | "authors" | "#p" | "since" | "until") {
            return Err(format!("may not have {key}"));
        }
    }
    if filter.contains_key("authors") == filter.contains_key("#p") {
        return Err("has to name either authors or #p".into());
    }
    if let Some(p) = filter.get("#p").and_then(Value::as_array) {
        if p.len() != 1 {
            return Err("may name only one #p".into());
        }
        if !p[0].as_str().is_some_and(crate::nostr::event::is_hex64) {
            return Err("has to name #p as 64-character lowercase hex".into());
        }
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
        let filter = one(json!({"kinds": [1059], "#p": [HEX], "since": 1e99, "until": -1e99})).unwrap();
        assert_eq!(Value::Object(filter), json!({"kinds": [1059], "#p": [HEX], "since": u32::MAX, "until": 0}));
    }

    #[test]
    fn refuses_subscriptions_that_grow_too_large() {
        let subscription = json!({"filters": vec![json!({"kinds": [1059], "#p": [HEX]}); MAX_FILTERS], "relays": ["wss://a.example"]});
        // Each filter gains a `since` when tidied.
        let tidied = serde_json::to_string(&normalize(&json!([&subscription]), NOW).unwrap()[0]).unwrap();
        let fits = MAX_SIZE / (tidied.len() + 1);
        assert!(normalize(&json!(vec![&subscription; fits - 1]), NOW).is_ok());
        assert_eq!(normalize(&json!(vec![&subscription; fits + 1]), NOW).unwrap_err(), format!("Subscriptions come to more than {MAX_SIZE} bytes"));
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

    /// Armada's gift wrap filters are taken; the rest of what
    /// `buildPushSubscriptions` makes is dropped, without refusing the set.
    #[test]
    fn takes_armadas_gift_wrap_filters_and_drops_the_rest() {
        assert!(one(json!({"kinds": [1059], "#p": [HEX]})).is_ok());
        assert!(one(json!({"kinds": [1059], "authors": [HEX, HEX]})).is_ok());

        let relays = json!(["wss://a.example"]);
        let subs = normalize(&json!([
            {"filters": [{"kinds": [9], "#h": ["g1"]}, {"kinds": [9], "#h": ["g1"], "#p": [HEX]}, {"kinds": [1111, 7], "#h": ["g1"], "#p": [HEX]}], "relays": ["wss://groups.example"]},
            {"filters": [{"kinds": [1059], "#p": [HEX]}, {"kinds": [4], "#p": [HEX], "authors": [HEX]}], "relays": relays},
            {"filters": [{"kinds": [1059], "authors": [HEX]}], "relays": relays},
        ]), NOW)
        .unwrap();
        let filters: Vec<_> = subs.iter().map(|sub| sub.filters.iter().map(|f| Value::Object(f.clone())).collect::<Vec<_>>()).collect();
        assert_eq!(filters, [vec![json!({"kinds": [1059], "#p": [HEX], "since": NOW})], vec![json!({"kinds": [1059], "authors": [HEX], "since": NOW})]]);
    }

    #[test]
    fn refuses_anything_else() {
        for (filter, why) in [
            (json!({"#p": [HEX]}), "may only ask for gift wraps (kind 1059)"),
            (json!({"authors": [HEX]}), "may only ask for gift wraps (kind 1059)"),
            (json!({"kinds": [0], "authors": [HEX]}), "may only ask for gift wraps (kind 1059)"),
            (json!({"kinds": [1059, 4], "#p": [HEX]}), "may only ask for gift wraps (kind 1059)"),
            (json!({"kinds": [1059]}), "has to name either authors or #p"),
            (json!({"kinds": [1059], "#p": [HEX], "authors": [HEX]}), "has to name either authors or #p"),
            (json!({"kinds": [1059], "#p": [HEX, HEX]}), "may name only one #p"),
            (json!({"kinds": [1059], "#p": []}), "may name only one #p"),
            (json!({"kinds": [1059], "#p": ["x"]}), "has to name #p as 64-character lowercase hex"),
            (json!({"kinds": [1059], "#p": [HEX.to_uppercase()]}), "has to name #p as 64-character lowercase hex"),
            (json!({"kinds": [1059], "#p": [HEX], "#h": ["g"]}), "may not have #h"),
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
    fn widens_since_for_gift_wraps() {
        let subs = normalize(&json!([{"filters": [{"kinds": [1059], "#p": [HEX]}, {"kinds": [1059], "authors": [HEX], "since": NOW + 10}], "relays": ["wss://a.example"]}]), NOW).unwrap();
        let since: Vec<_> = subs[0].live_filters().map(|f| f["since"].as_i64().unwrap()).collect();
        assert_eq!(since, [NOW - GIFT_WRAP_BACKDATE, NOW + 10 - GIFT_WRAP_BACKDATE]);
    }
}
