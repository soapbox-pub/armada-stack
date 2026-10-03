//! Adding the [`ENV_PATH`] script to a site's pages, once, when a version
//! goes live. Ported from npanel's `inject.rs`, trimmed to the one script.
//!
//! The tag is the first thing in the head, a classic script that blocks the
//! parser, so `window.ENV` is set before anything the site wrote runs.

use super::env::ENV_PATH;

/// Largest document the script is added to. A page bigger than this is
/// almost certainly a generated dump, and is served as published.
pub const MAX_INJECT_BYTES: u64 = 4 * 1024 * 1024;

/// A page with the script added, or `None` to serve it as published.
///
/// Edited as bytes rather than parsed and re-serialized, so everything the
/// site wrote comes back exactly as it was apart from the one tag, whatever
/// its encoding: everything written into it is ASCII.
///
/// The tag goes after `<head>`, and failing that where the head would have
/// begun — after `<html>` or the doctype, or before `<body>`. A file with
/// none of those is a fragment some page fetches and inserts, and a script
/// tag inserted that way never runs anyway, so it is left alone.
///
/// Any `<meta>` Content Security Policy in the head is widened to let the
/// script load from the site's own origin. A page whose policy trusts
/// scripts by `'strict-dynamic'` is left alone: that trusts a script by
/// hash, and this one is written per request.
pub fn inject_env(html: &[u8]) -> Option<Vec<u8>> {
    let lower = html.to_ascii_lowercase();
    let tags = tags(&lower);
    let at = head_start(&tags)?;
    // A tag at the start of the head comes before the policies in it, which
    // still have to let it through: armada sends the declared policy as a
    // header, and a header applies to the whole page.
    let end = head_end(&tags).unwrap_or(html.len()).max(at);

    let before = allow_meta_policies(&html[..at])?;
    let after = allow_meta_policies(&html[at..end])?;
    let tag = format!(r#"<script src="{ENV_PATH}"></script>"#);

    let mut out = Vec::with_capacity(html.len() + tag.len() + 64);
    out.extend_from_slice(&before);
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&after);
    out.extend_from_slice(&html[end..]);
    Some(out)
}

/// Whitespace as HTML's tokenizer reads it between a tag's name and its
/// attributes.
fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

/// One piece of markup a page's tokenizer would see.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    /// `<name …>`, by its lowercased name.
    Start(Vec<u8>),
    /// `</name …>`.
    End(Vec<u8>),
    /// `<!doctype …>`.
    Doctype,
}

type Tags = Vec<(usize, usize, Token)>;

/// The tags of a document, from its lowercased bytes, with where each begins
/// and ends — found the way a browser's tokenizer finds them, so a `</head>`
/// in a comment or an inline script is not the end of the head, `</header>`
/// is not `</head>`, and a `>` inside a quoted attribute doesn't end its tag.
///
/// Not a parser: nothing is built from the tags, and no tag is implied. Only
/// what the tokenizer decides matters here, and all of it is ASCII, so the
/// site's own bytes need no decoding.
fn tags(lower: &[u8]) -> Tags {
    let mut tags = Vec::new();
    let mut at = 0;

    while let Some(offset) = lower[at..].iter().position(|&b| b == b'<') {
        let start = at + offset;
        let rest = &lower[start..];

        if rest.starts_with(b"<!--") {
            at = find(&lower[start + 4..], b"-->").map_or(lower.len(), |end| start + 4 + end + 3);
            continue;
        }
        if rest.starts_with(b"<!") || rest.starts_with(b"<?") {
            let end = find(rest, b">").map_or(lower.len(), |end| start + end + 1);
            if rest.starts_with(b"<!doctype") {
                tags.push((start, end, Token::Doctype));
            }
            at = end;
            continue;
        }

        let closing = rest.get(1) == Some(&b'/');
        let name_start = start + 1 + usize::from(closing);
        if !lower.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            at = start + 1;
            continue;
        }
        let name_end = lower[name_start..].iter().position(|&b| is_space(b) || b == b'/' || b == b'>').map_or(lower.len(), |n| name_start + n);
        let name = lower[name_start..name_end].to_vec();

        // Attribute values may hold a `>` when quoted.
        let mut end = name_end;
        let mut quote = None;
        while end < lower.len() {
            match (quote, lower[end]) {
                (None, b'>') => break,
                (None, q @ (b'"' | b'\'')) if !closing => quote = Some(q),
                (Some(q), b) if b == q => quote = None,
                _ => {}
            }
            end += 1;
        }
        end = (end + 1).min(lower.len());

        if closing {
            tags.push((start, end, Token::End(name)));
            at = end;
            continue;
        }

        // The text of these is not markup, whatever it looks like.
        let raw = matches!(name.as_slice(), b"script" | b"style" | b"textarea" | b"title" | b"xmp" | b"iframe" | b"noembed" | b"noframes");
        let closer = [b"</".as_slice(), &name].concat();
        tags.push((start, end, Token::Start(name)));
        at = end;
        if raw {
            let mut search = end;
            at = lower.len();
            while let Some(found) = find(&lower[search..], &closer) {
                let after = search + found + closer.len();
                if lower.get(after).is_none_or(|&b| is_space(b) || b == b'/' || b == b'>') {
                    at = search + found;
                    break;
                }
                search = after;
            }
        }
    }

    tags
}

/// Where the head begins: after `<head>`, or failing that after `<html>` or
/// the doctype, or before `<body>`.
fn head_start(tags: &Tags) -> Option<usize> {
    let start = |name: &[u8]| tags.iter().find(|(_, _, t)| *t == Token::Start(name.to_vec()));

    start(b"head")
        .or_else(|| start(b"html"))
        .or_else(|| tags.iter().find(|(_, _, t)| *t == Token::Doctype))
        .map(|(_, end, _)| *end)
        .or_else(|| start(b"body").map(|(at, _, _)| *at))
}

/// Where the head ends: before `</head>`, or failing that before `<body>`,
/// or after `<html>` or the doctype.
fn head_end(tags: &Tags) -> Option<usize> {
    let find_tag = |token: Token| tags.iter().find(|(_, _, t)| *t == token);

    find_tag(Token::End(b"head".to_vec()))
        .or_else(|| find_tag(Token::Start(b"body".to_vec())))
        .map(|(at, _, _)| *at)
        .or_else(|| find_tag(Token::Start(b"html".to_vec())).or_else(|| find_tag(Token::Doctype)).map(|(_, end, _)| *end))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// One attribute of a tag: its lowercased name, its raw value, and where the
/// whole `name=value` sits in the tag.
struct Attribute {
    name: Vec<u8>,
    value: Vec<u8>,
    start: usize,
    end: usize,
}

/// The attributes of a start tag, `<name` and the closing `>` excluded.
fn attributes(tag: &[u8]) -> Vec<Attribute> {
    let mut attributes = Vec::new();
    let mut at = 0;
    let stop = |b: u8| is_space(b) || b == b'/' || b == b'>';
    while at < tag.len() {
        if stop(tag[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < tag.len() && !stop(tag[at]) && tag[at] != b'=' {
            at += 1;
        }
        let name = tag[start..at].to_ascii_lowercase();
        let mut probe = at;
        while probe < tag.len() && is_space(tag[probe]) {
            probe += 1;
        }
        let mut value = Vec::new();
        if tag.get(probe) == Some(&b'=') {
            probe += 1;
            while probe < tag.len() && is_space(tag[probe]) {
                probe += 1;
            }
            match tag.get(probe) {
                Some(&quote @ (b'"' | b'\'')) => {
                    let close = tag[probe + 1..].iter().position(|&b| b == quote).map_or(tag.len(), |n| probe + 1 + n);
                    value = tag[probe + 1..close].to_vec();
                    at = (close + 1).min(tag.len());
                }
                _ => {
                    let from = probe;
                    while probe < tag.len() && !is_space(tag[probe]) && tag[probe] != b'>' {
                        probe += 1;
                    }
                    value = tag[from..probe].to_vec();
                    at = probe;
                }
            }
        }
        attributes.push(Attribute { name, value, start, end: at });
    }
    attributes
}

/// Every `<meta http-equiv="Content-Security-Policy">` in `head`, widened,
/// or `None` if one uses `'strict-dynamic'`.
fn allow_meta_policies(head: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(head.len());
    let mut last = 0;

    let metas = tags(&head.to_ascii_lowercase()).into_iter().filter(|(_, _, token)| *token == Token::Start(b"meta".to_vec()));
    for (start, end, _) in metas {
        let tag = &head[start..end];
        let attributes = attributes(&tag[5..]);
        let equiv = attributes.iter().find(|a| a.name == b"http-equiv").map(|a| latin1(&a.value).trim().to_lowercase());
        let content = attributes.iter().find(|a| a.name == b"content");

        let mut rewritten = None;
        if let (Some("content-security-policy"), Some(content)) = (equiv.as_deref(), content) {
            let policy = decode_attribute(&latin1(&content.value));
            // Nothing a policy can say is outside printable ASCII, and
            // anything that is would not survive being written back.
            if policy.chars().all(|c| c == '\t' || (' '..='~').contains(&c)) {
                if policy.to_ascii_lowercase().contains("'strict-dynamic'") {
                    return None;
                }
                let widened = allow_script(&policy);
                if widened != policy {
                    let attribute = format!("content=\"{}\"", widened.replace('&', "&amp;").replace('"', "&quot;"));
                    rewritten = Some([&tag[..5 + content.start], attribute.as_bytes(), &tag[5 + content.end..]].concat());
                }
            }
        }

        out.extend_from_slice(&head[last..start]);
        out.extend_from_slice(rewritten.as_deref().unwrap_or(tag));
        last = end;
    }
    out.extend_from_slice(&head[last..]);
    Some(out)
}

/// Bytes as Latin-1 text: one character per byte.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// An attribute value with its character references decoded, by the parser
/// that knows every named one.
fn decode_attribute(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let quote = if raw.contains('"') { '\'' } else { '"' };
    let fragment = scraper::Html::parse_fragment(&format!("<i title={quote}{raw}{quote}></i>"));
    let selector = scraper::Selector::parse("i").expect("selector");
    fragment.select(&selector).next().and_then(|element| element.value().attr("title")).unwrap_or(raw).to_string()
}

struct Directive {
    name: String,
    sources: Vec<String>,
}

/// A Content Security Policy that lets a script load from the site's own
/// origin, and is otherwise exactly what the site wrote: `'self'` joins
/// `script-src-elem` and `script-src` where the site wrote them, and a copy
/// of `default-src` where it relied on the fallback, so nothing that
/// fallback allowed is taken away. `'none'` gives way to `'self'`, and a
/// directive that already allows the origin is untouched.
///
/// `policy` may be several policies joined with commas; each is widened on
/// its own.
fn allow_script(policy: &str) -> String {
    let policies: Vec<&str> = policy.split(',').map(str::trim).collect();
    let widened: Vec<String> = policies.iter().map(|one| allow_in_policy(one)).collect();
    if widened.iter().zip(&policies).all(|(a, b)| a == b) { policy.to_string() } else { widened.join(", ") }
}

fn allow_in_policy(policy: &str) -> String {
    let mut directives: Vec<Directive> = policy
        .split(';')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| {
            let mut parts = d.split_whitespace();
            let name = parts.next().unwrap_or("").to_lowercase();
            Directive { name, sources: parts.map(str::to_string).collect() }
        })
        .collect();

    if !widen(&mut directives) {
        return policy.to_string();
    }
    directives
        .iter()
        .map(|d| std::iter::once(d.name.as_str()).chain(d.sources.iter().map(String::as_str)).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("; ")
}

fn widen(directives: &mut Vec<Directive>) -> bool {
    let present: Vec<usize> = ["script-src-elem", "script-src"].iter().filter_map(|name| directives.iter().position(|d| d.name == *name)).collect();
    if !present.is_empty() {
        let mut changed = false;
        for index in present {
            if !allows(&directives[index]) {
                grant(&mut directives[index]);
                changed = true;
            }
        }
        return changed;
    }

    let Some(fallback) = directives.iter().find(|d| d.name == "default-src") else {
        return false;
    };
    let mut copy = Directive { name: "script-src".into(), sources: fallback.sources.clone() };
    if allows(&copy) {
        return false;
    }
    grant(&mut copy);
    directives.push(copy);
    true
}

fn allows(directive: &Directive) -> bool {
    directive.sources.iter().any(|s| s.eq_ignore_ascii_case("'self'") || s == "*")
}

fn grant(directive: &mut Directive) {
    directive.sources.retain(|s| !s.eq_ignore_ascii_case("'none'"));
    directive.sources.push("'self'".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = r#"<script src="/_armada/env.js"></script>"#;

    fn inject(html: &str) -> Option<String> {
        inject_env(html.as_bytes()).map(|bytes| String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn places_the_tag_first() {
        assert_eq!(
            inject("<!doctype html><html><HEAD lang=en><script src=/app.js></script></head><body></body></html>").unwrap(),
            format!("<!doctype html><html><HEAD lang=en>{TAG}<script src=/app.js></script></head><body></body></html>")
        );
        assert_eq!(inject("<html><header>x</header>").unwrap(), format!("<html>{TAG}<header>x</header>"));
        assert_eq!(inject("<!DOCTYPE html><script src=/a.js></script>").unwrap(), format!("<!DOCTYPE html>{TAG}<script src=/a.js></script>"));
        assert_eq!(inject("<p>hi</p><body>").unwrap(), format!("<p>hi</p>{TAG}<body>"));
        assert_eq!(inject("<div>fragment</div>"), None);
    }

    #[test]
    fn finds_tags_as_a_browser_does() {
        // A `<head>` in a comment or a script is text.
        assert_eq!(inject("<!-- <head> --><html><p>x").unwrap(), format!("<!-- <head> --><html>{TAG}<p>x"));
        assert_eq!(inject(r#"<html data-x="a>b"><body>"#).unwrap(), format!(r#"<html data-x="a>b">{TAG}<body>"#));
        // No-break space is not HTML whitespace, so this is no head.
        assert_eq!(inject("<head\u{a0}x><p>"), None);
    }

    #[test]
    fn keeps_other_bytes() {
        let page = b"<head>\xff\xfe caf\xe9</head>".to_vec();
        let out = inject_env(&page).unwrap();
        assert_eq!(out, [b"<head>".as_slice(), TAG.as_bytes(), b"\xff\xfe caf\xe9</head>"].concat());
    }

    #[test]
    fn widens_meta_policies() {
        let out = inject(r#"<head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src *"></head><body><meta http-equiv="Content-Security-Policy" content="default-src 'none'">"#).unwrap();
        assert_eq!(
            out,
            format!(r#"<head>{TAG}<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src *; script-src 'self'"></head><body><meta http-equiv="Content-Security-Policy" content="default-src 'none'">"#)
        );
        // Armada's own, which already allows it, is left exactly as written.
        let page = r#"<head><meta http-equiv=content-security-policy content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'"></head>"#;
        assert_eq!(inject(page).unwrap(), page.replacen("<head>", &format!("<head>{TAG}"), 1));
        let out = inject(r#"<head><meta content='script-src &apos;none&apos;' http-equiv="content-security-policy"></head>"#).unwrap();
        assert!(out.contains(r#"content="script-src 'self'""#), "{out}");
    }

    #[test]
    fn leaves_strict_dynamic_pages_alone() {
        assert_eq!(inject(r#"<head><meta http-equiv="content-security-policy" content="script-src 'strict-dynamic' 'nonce-x'"></head>"#), None);
    }

    #[test]
    fn leaves_permissive_policies() {
        assert_eq!(allow_script("default-src 'self'"), "default-src 'self'");
        assert_eq!(allow_script("img-src *"), "img-src *");
        assert_eq!(allow_script("script-src 'none', connect-src *"), "script-src 'self', connect-src *");
    }
}
