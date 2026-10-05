//! Answering filters from the store.
//!
//! Each filter gets one index to scan. The candidates are the ones its
//! fields allow — author and kind together, author, each tag, kind — and
//! since every index key's stamps are counted by LMDB for free, the planner
//! simply adds up the counts of each candidate's keys and takes the
//! smallest. If that index pins down every field the filter has, its
//! entries need no further checking.
//!
//! A scan opens a cursor per key, each starting at `until` and walking back
//! in time, and merges them newest first until `since` or the limit.
//!
//! A REQ's filters share one budget of records to examine, and stop early
//! once nobody wants their results: the subscription was closed or
//! replaced, or its connection went away.

use std::collections::{BinaryHeap, HashSet};

use tokio_util::sync::CancellationToken;

use super::filter::Filter;
use super::lmdb::{Cursor, Db, Result, Txn};
use super::policy;
use super::record::EventView;
use super::store::{CREATED, MAX_SEQ, Stamp, Store, stamp, stamp_created_at, stamp_seq};

/// The most author × kind keys a filter may be planned over together.
const MAX_AUTHOR_KINDS: usize = 1024;

/// The most records one filter may examine. Only filters whose fields the
/// index can't pin down examine records that don't match, and this bounds
/// how long one of those can hold a reader.
const MAX_EXAMINED: usize = 100_000;

/// The most records all of one REQ's filters may examine together, so that
/// adding filters doesn't add to how long a REQ can hold a core.
const MAX_EXAMINED_PER_REQ: usize = 200_000;

/// How many records go by between looks at whether the query is cancelled.
const CANCEL_CHECK: usize = 256;

/// The most extra events read past the limit to order a tie at the boundary.
const MAX_TIES: usize = 1000;

/// The most bytes of events one REQ returns, all its filters together.
/// Results are held in memory until they're sent, and events can be big:
/// without this, 32 filters of 500 one-megabyte gift wraps each would be
/// gigabytes. Past it the REQ ends early, as if at its limits.
pub const MAX_RESULT_BYTES: usize = 16 << 20;

pub struct Results {
    /// The sequence number the next event stored after this snapshot gets.
    /// Anything below it was visible to the query.
    pub next_seq: u64,
    /// Matching events as JSON, each filter's newest first.
    pub events: Vec<String>,
}

/// Records left to examine, until they run out or `cancel` fires.
struct Budget<'a> {
    left: usize,
    spent: usize,
    cancel: &'a CancellationToken,
}

impl Budget<'_> {
    /// Spend one, or `false` if there's none left.
    fn spend(&mut self) -> bool {
        if self.left == 0 {
            return false;
        }
        self.spent += 1;
        if self.spent.is_multiple_of(CANCEL_CHECK) && self.cancel.is_cancelled() {
            self.left = 0;
            return false;
        }
        self.left -= 1;
        true
    }

    /// Spend `n` at once, or `false`, spending all that's left, if there
    /// aren't that many.
    fn spend_n(&mut self, n: usize) -> bool {
        if n > self.left {
            self.left = 0;
            return false;
        }
        self.left -= n;
        true
    }
}

/// Tags gone through in matching that cost as much as examining a record.
const TAGS_PER_RECORD: usize = 32;

/// Run a REQ's filters. Each one's limit is capped at `max_limit`. Once
/// `cancel` fires it stops soon, with whatever it found so far, which
/// nobody should send.
pub fn run(store: &Store, filters: &[Filter], max_limit: u64, now: i64, cancel: &CancellationToken) -> Result<Results> {
    run_within(store, filters, max_limit, now, Budget { left: MAX_EXAMINED_PER_REQ, spent: 0, cancel })
}

fn run_within(store: &Store, filters: &[Filter], max_limit: u64, now: i64, mut budget: Budget) -> Result<Results> {
    let txn = store.read()?;
    let next_seq = store.next_seq(&txn)?;
    let mut seen = HashSet::new();
    let mut events = Vec::new();
    let mut bytes = 0;
    'filters: for filter in filters {
        let limit = filter.limit.unwrap_or(max_limit).min(max_limit) as usize;
        if filter.never || limit == 0 {
            continue;
        }
        if budget.left == 0 || budget.cancel.is_cancelled() {
            break;
        }
        for (seq, view) in run_filter(store, &txn, filter, limit, now, &mut budget)? {
            if seen.insert(seq) {
                let json = view.to_json();
                bytes += json.len();
                events.push(json);
                if bytes >= MAX_RESULT_BYTES {
                    break 'filters;
                }
            }
        }
    }
    Ok(Results { next_seq, events })
}

fn run_filter<'t>(store: &Store, txn: &'t Txn, filter: &Filter, limit: usize, now: i64, budget: &mut Budget) -> Result<Vec<(u64, EventView<'t>)>> {
    let mut found = Vec::new();

    if let Some(ids) = &filter.ids {
        for id in ids {
            if !budget.spend() {
                break;
            }
            let Some(seq) = store.seq_of(txn, id)? else { continue };
            if let Some(view) = store.load(txn, seq)?.filter(|view| filter.matches(view) && !view.is_expired(now) && policy::visible(view, filter)) {
                found.push((seq, view));
            }
        }
    } else {
        let plan = plan(store, txn, filter)?;
        scan(store, txn, filter, &plan, limit, now, budget, &mut found)?;
    }

    // Newest first; on a tie, the lowest id first (NIP-01).
    found.sort_unstable_by(|(_, a), (_, b)| b.created_at().cmp(&a.created_at()).then_with(|| a.id().cmp(b.id())));
    found.truncate(limit);
    Ok(found)
}

#[derive(Debug)]
struct Plan {
    db: Db,
    /// Keys whose stamps to merge.
    keys: Vec<Vec<u8>>,
    /// Whether every entry found matches the filter, time aside.
    exact: bool,
}

fn plan(store: &Store, txn: &Txn, filter: &Filter) -> Result<Plan> {
    let t = store.tables;
    let mut candidates = Vec::new();
    let no_tags = filter.tags.is_empty();

    if let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds)
        && authors.len() * kinds.len() <= MAX_AUTHOR_KINDS
    {
        let keys = authors.iter().flat_map(|a| kinds.iter().map(move |k| [&a[..], &k.to_be_bytes()].concat())).collect();
        candidates.push(Plan { db: t.author_kinds, keys, exact: no_tags });
    }
    if let Some(authors) = &filter.authors {
        let keys = authors.iter().map(|a| a.to_vec()).collect();
        candidates.push(Plan { db: t.authors, keys, exact: filter.kinds.is_none() && no_tags });
    }
    for (letter, values) in &filter.tags {
        let keys = values.iter().map(|v| [&[*letter][..], v].concat()).collect();
        let exact = filter.authors.is_none() && filter.kinds.is_none() && filter.tags.len() == 1;
        candidates.push(Plan { db: t.tags, keys, exact });
    }
    if let Some(kinds) = &filter.kinds {
        let keys = kinds.iter().map(|k| k.to_be_bytes().to_vec()).collect();
        candidates.push(Plan { db: t.kinds, keys, exact: filter.authors.is_none() && no_tags });
    }

    let mut best: Option<(usize, Plan)> = None;
    for candidate in candidates {
        let bound = best.as_ref().map_or(usize::MAX, |(cost, _)| *cost);
        let cost = cost(txn, &candidate, bound)?;
        // Ties go to the earlier candidate, which pins down more fields.
        if cost < bound {
            best = Some((cost, candidate));
        }
    }
    Ok(best.map_or(Plan { db: t.created, keys: vec![CREATED.to_vec()], exact: true }, |(_, plan)| plan))
}

/// How many entries a plan would walk, at worst. Stops counting at `bound`.
fn cost(txn: &Txn, plan: &Plan, bound: usize) -> Result<usize> {
    let mut cursor = txn.cursor(plan.db)?;
    let mut total = 0usize;
    for key in &plan.keys {
        if cursor.set(key)?.is_some() {
            total = total.saturating_add(cursor.count()?);
            if total >= bound {
                break;
            }
        }
    }
    Ok(total)
}

/// One key's stamps, newest first.
struct Source<'t> {
    cursor: Cursor<'t>,
}

impl<'t> Source<'t> {
    /// Position at the newest stamp no later than `until`.
    fn start(txn: &'t Txn, db: Db, key: &[u8], until: u32) -> Result<Option<(Stamp, Source<'t>)>> {
        let mut cursor = txn.cursor(db)?;
        let entry = match cursor.get_both_range(key, &stamp(until, MAX_SEQ))? {
            Some(_) => cursor.prev_dup()?,
            None => match cursor.set(key)? {
                Some(_) => cursor.last_dup()?,
                None => None,
            },
        };
        Ok(stamp_of(entry).map(|stamp| (stamp, Source { cursor })))
    }

    fn next(&mut self) -> Result<Option<Stamp>> {
        Ok(stamp_of(self.cursor.prev_dup()?))
    }
}

fn stamp_of(entry: Option<(&[u8], &[u8])>) -> Option<Stamp> {
    entry?.1.try_into().ok()
}

#[allow(clippy::too_many_arguments)]
fn scan<'t>(store: &Store, txn: &'t Txn, filter: &Filter, plan: &Plan, limit: usize, now: i64, budget: &mut Budget, found: &mut Vec<(u64, EventView<'t>)>) -> Result<()> {
    let mut sources = Vec::new();
    let mut heap = BinaryHeap::new();
    for key in &plan.keys {
        if let Some((stamp, source)) = Source::start(txn, plan.db, key, filter.until)? {
            heap.push((stamp, sources.len()));
            sources.push(source);
        }
    }

    let mut last = None;
    let mut examined = 0;
    while let Some((stamp, i)) = heap.pop() {
        if let Some(next) = sources[i].next()? {
            heap.push((next, i));
        }
        let created_at = stamp_created_at(&stamp);
        if created_at < filter.since {
            // The newest left is too old, so all of them are.
            break;
        }
        // The same event under two keys pops twice in a row.
        if last == Some(stamp) {
            continue;
        }
        last = Some(stamp);
        // Past the limit, keep going only through a tie with the last one.
        if found.len() >= limit && (found.len() >= limit + MAX_TIES || found.last().is_some_and(|(_, v)| created_at < v.created_at())) {
            break;
        }
        examined += 1;
        if examined > MAX_EXAMINED || !budget.spend() {
            break;
        }

        let seq = stamp_seq(&stamp);
        let Some(view) = store.load(txn, seq)? else { continue };
        let matches = plan.exact || {
            let (matches, walked) = filter.matches_walking(&view);
            // An event can carry thousands of tags, each of which matching
            // may have to look at: those cost as records do.
            if !budget.spend_n(walked / TAGS_PER_RECORD) {
                break;
            }
            matches
        };
        if matches && !view.is_expired(now) && policy::visible(&view, filter) {
            found.push((seq, view));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Event;
    use crate::relay::store::tests::{ALICE, BOB, open, put, tags};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use serde_json::{Value, json};

    const CAROL: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    fn ids(store: &Store, filters: &[Value], max_limit: u64) -> Vec<String> {
        let filters: Vec<Filter> = filters.iter().map(|f| Filter::parse(f).unwrap()).collect();
        let results = run(store, &filters, max_limit, 1_000_000, &CancellationToken::new()).unwrap();
        results.events.iter().map(|json| serde_json::from_str::<Event>(json).unwrap().id).collect()
    }

    #[test]
    fn plans_by_counts() {
        let (_dir, store) = open();
        let alice = crate::nostr::event::public_key(ALICE);
        for i in 0..20 {
            put(&store, &Event::sign(ALICE, 100 + i, 1, tags(&[&["t", "common"]]), ""));
        }
        put(&store, &Event::sign(BOB, 100, 1, tags(&[&["t", "rare"]]), ""));

        let txn = store.read().unwrap();
        let plan_for = |filter: Value| plan(&store, &txn, &Filter::parse(&filter).unwrap()).unwrap();

        // The rare tag beats the author with twenty events, and needs checking.
        let p = plan_for(json!({"authors": [alice], "#t": ["rare"]}));
        assert_eq!(p.keys, vec![[&b"t"[..], &[0], b"rare"].concat()]);
        assert!(!p.exact);
        // Author and kind together, exactly.
        let p = plan_for(json!({"authors": [alice], "kinds": [1]}));
        assert_eq!(p.keys[0].len(), 34);
        assert!(p.exact);
        assert_eq!(plan_for(json!({"since": 5})).keys, [CREATED]);
    }

    #[test]
    fn pages_newest_first_breaking_ties_by_id() {
        let (_dir, store) = open();
        let mut events: Vec<Event> = (0..10).map(|i| Event::sign(ALICE, 100 + i / 2, 1, vec![], &i.to_string())).collect();
        for event in &events {
            put(&store, event);
        }
        events.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
        let expected: Vec<String> = events.iter().map(|e| e.id.clone()).collect();

        assert_eq!(ids(&store, &[json!({"kinds": [1]})], 100), expected);
        assert_eq!(ids(&store, &[json!({})], 100), expected);
        // A limit landing mid-tie still gets the lowest ids of the tie.
        assert_eq!(ids(&store, &[json!({"kinds": [1], "limit": 3})], 100), expected[..3]);
        assert_eq!(ids(&store, &[json!({"limit": 3})], 100), expected[..3]);
        // The relay's own cap.
        assert_eq!(ids(&store, &[json!({"kinds": [1]})], 4), expected[..4]);
        assert_eq!(ids(&store, &[json!({"kinds": [1], "until": 102, "since": 101})], 100), expected[4..8]);
        assert!(ids(&store, &[json!({"kinds": [1], "limit": 0})], 100).is_empty());
    }

    #[test]
    fn hides_expired_events() {
        let (_dir, store) = open();
        put(&store, &Event::sign(ALICE, 100, 1, tags(&[&["expiration", "999999"]]), ""));
        put(&store, &Event::sign(ALICE, 100, 1, tags(&[&["expiration", "1000001"]]), ""));
        assert_eq!(ids(&store, &[json!({})], 100).len(), 1);
    }

    /// Random events and filters, checked against matching every event.
    #[test]
    fn agrees_with_brute_force() {
        let (_dir, store) = open();
        let mut rng = StdRng::seed_from_u64(7);
        let secrets = [ALICE, BOB, CAROL];
        let topics = ["a", "b", "c", "d"];
        let mut all = Vec::new();
        for i in 0..300 {
            let secret = secrets[rng.random_range(0..3)];
            let kind = [1, 7, 1111][rng.random_range(0..3)];
            let mut event_tags = vec![];
            for _ in 0..rng.random_range(0..3) {
                event_tags.push(vec!["t".to_string(), topics[rng.random_range(0..4)].to_string()]);
            }
            let event = Event::sign(secret, rng.random_range(100..160), kind, event_tags, &i.to_string());
            put(&store, &event);
            all.push(event);
        }
        let pubkeys: Vec<String> = secrets.iter().map(|s| crate::nostr::event::public_key(s)).collect();

        for _ in 0..300 {
            let mut filter = serde_json::Map::new();
            if rng.random_bool(0.5) {
                filter.insert("authors".into(), json!(pubkeys[..rng.random_range(1..3)]));
            }
            if rng.random_bool(0.5) {
                let kind = [1, 7, 1111][rng.random_range(0..3)];
                filter.insert("kinds".into(), json!([kind, 9]));
            }
            if rng.random_bool(0.5) {
                filter.insert("#t".into(), json!(topics[..rng.random_range(1..4)]));
            }
            if rng.random_bool(0.3) {
                filter.insert("since".into(), json!(rng.random_range(100..160)));
            }
            if rng.random_bool(0.3) {
                filter.insert("until".into(), json!(rng.random_range(100..160)));
            }
            let limit = rng.random_range(1..40);
            filter.insert("limit".into(), json!(limit));
            let filter = Value::Object(filter);

            let parsed = Filter::parse(&filter).unwrap();
            let mut expected: Vec<&Event> = all
                .iter()
                .filter(|e| {
                    let record = crate::relay::record::encode(e);
                    parsed.matches(&EventView::new(&record).unwrap())
                })
                .collect();
            expected.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
            let expected: Vec<String> = expected.iter().take(limit).map(|e| e.id.clone()).collect();
            assert_eq!(ids(&store, std::slice::from_ref(&filter), 500), expected, "{filter}");
        }
    }

    #[test]
    fn shares_one_budget_across_a_reqs_filters() {
        let (_dir, store) = open();
        for i in 0..5 {
            put(&store, &Event::sign(ALICE, 100 + i, 1, vec![], ""));
            put(&store, &Event::sign(BOB, 100 + i, 7, vec![], ""));
        }
        let filters: Vec<Filter> = [json!({"kinds": [1]}), json!({"kinds": [7]})].iter().map(|f| Filter::parse(f).unwrap()).collect();
        let cancel = CancellationToken::new();
        let budget = |left| Budget { left, spent: 0, cancel: &cancel };
        assert_eq!(run_within(&store, &filters, 100, 1_000_000, budget(100)).unwrap().events.len(), 10);
        // The first filter spends most of it.
        assert_eq!(run_within(&store, &filters, 100, 1_000_000, budget(7)).unwrap().events.len(), 7);
        assert_eq!(run_within(&store, &filters, 100, 1_000_000, budget(3)).unwrap().events.len(), 3);
    }

    #[test]
    fn stops_once_cancelled() {
        let (_dir, store) = open();
        for i in 0..(CANCEL_CHECK as i64 * 2) {
            put(&store, &Event::sign(ALICE, 100 + i, 1, vec![], ""));
        }
        let filters = [Filter::parse(&json!({"kinds": [1]})).unwrap()];
        let cancel = CancellationToken::new();
        // Partway through, at its next look.
        let mut budget = Budget { left: usize::MAX, spent: 0, cancel: &cancel };
        for _ in 0..CANCEL_CHECK - 10 {
            assert!(budget.spend());
        }
        cancel.cancel();
        assert_eq!(std::iter::from_fn(|| budget.spend().then_some(())).count(), 9);
        assert!(!budget.spend());
        // Before it starts, at once.
        assert!(run(&store, &filters, 1000, 1_000_000, &cancel).unwrap().events.is_empty());
    }

    #[test]
    fn stops_at_its_byte_budget() {
        let (_dir, store) = open();
        let big = "x".repeat(1 << 20);
        for i in 0..20 {
            put(&store, &Event::sign(ALICE, 100 + i, 1, vec![], &big));
        }
        let filters: Vec<Filter> = (0..4).map(|i| Filter::parse(&json!({"kinds": [1], "until": 119 - i * 5, "limit": 5})).unwrap()).collect();
        let results = run(&store, &filters, 500, 1_000_000, &CancellationToken::new()).unwrap();
        // Each is a little over a megabyte: the sixteenth crosses it, and is the last.
        assert_eq!(MAX_RESULT_BYTES, 16 << 20);
        assert_eq!(results.events.len(), 16);
    }

    #[test]
    fn merges_filters_without_repeats() {
        let (_dir, store) = open();
        let note = Event::sign(ALICE, 100, 1, vec![], "");
        put(&store, &note);
        let found = ids(&store, &[json!({"kinds": [1]}), json!({"ids": [note.id]})], 100);
        assert_eq!(found, vec![note.id.clone()]);
    }
}
