//! The Content Security Policy the site is served under: the one its own
//! `index.html` declares, or a default.
//!
//! Sent as a header as well as left in the page, because a header covers
//! what a `<meta>` tag can't: every response, not just documents, and
//! directives like `frame-ancestors` that browsers ignore in markup. A site
//! whose policy doesn't say who may frame it may be framed by no one, since
//! a page holding someone's keys is worth clickjacking; one that says
//! otherwise keeps its word.

use http::HeaderValue;

/// How much of a document is read looking for meta tags. The tags that
/// matter are in `<head>`, so this only has to cover a large one.
pub const MAX_HTML_BYTES: u64 = 128 * 1024;

/// Largest policy sent, in characters. A header field that outgrows what
/// proxies accept would take the whole response down with it; over this, the
/// default is sent instead.
const MAX_POLICY_LENGTH: usize = 8 * 1024;

/// The policy for a site that declares none: the `<meta>` policy mkstack
/// ships, which is what most nsites are built from.
pub const DEFAULT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
frame-src 'self' https:; font-src 'self'; base-uri 'self'; manifest-src 'self'; \
connect-src 'self' blob: https: wss:; img-src 'self' data: blob: https:; media-src 'self' https:; \
frame-ancestors 'none'";

/// Added, as a policy of its own, to a site's that doesn't name
/// `frame-ancestors`.
const NO_FRAMING: &str = "frame-ancestors 'none'";

/// The policy to send for a site whose `/index.html` is `html`, if it has one.
pub fn site_policy(html: Option<&str>) -> HeaderValue {
    html.and_then(extract_csp)
        .map(|policy| if frame_ancestors(&policy).next().is_some() { policy } else { format!("{policy}, {NO_FRAMING}") })
        // Only printable ASCII gets this far, which is always a valid header.
        .and_then(|policy| HeaderValue::from_str(&policy).ok())
        .unwrap_or(HeaderValue::from_static(DEFAULT_CSP))
}

/// Whether a policy lets no one frame the site, which is what
/// `X-Frame-Options: DENY` says to browsers older than `frame-ancestors`.
pub fn denies_framing(policy: &str) -> bool {
    frame_ancestors(policy).any(|sources| sources.eq_ignore_ascii_case("'none'"))
}

/// The sources of each `frame-ancestors` directive in a policy list.
fn frame_ancestors(policy: &str) -> impl Iterator<Item = &str> {
    policy.split([',', ';']).filter_map(|directive| {
        let directive = directive.trim();
        let (name, sources) = directive.split_once(' ').unwrap_or((directive, ""));
        name.eq_ignore_ascii_case("frame-ancestors").then(|| sources.trim())
    })
}

/// The enforcing Content Security Policy an HTML document declares.
///
/// Only tags in `<head>` count, as only those count to a browser. Every
/// matching `<meta http-equiv>` is taken, joined into the comma-separated
/// list the header defines, because a browser enforces each meta policy on
/// top of the last. A `-Report-Only` tag is skipped — a policy the site asked
/// only to be told about must not become the one it is held to.
pub fn extract_csp(html: &str) -> Option<String> {
    let document = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse("head meta").ok()?;
    let mut policies = Vec::new();

    for element in document.select(&selector) {
        let element = element.value();
        let equiv = element.attr("http-equiv").map(|v| v.trim().to_lowercase());
        if equiv.as_deref() != Some("content-security-policy") {
            continue;
        }
        let Some(content) = element.attr("content") else { continue };
        // Whitespace runs collapse: a policy written across lines in the
        // markup means the same on one line, and a newline can't go in a
        // header.
        let policy = content.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
        // Anything else outside printable ASCII is either a policy that isn't
        // one or an attempt to write a second header from inside the markup.
        if policy.is_empty() || policy.chars().any(|c| !(' '..='~').contains(&c)) {
            continue;
        }
        policies.push(policy);
    }

    if policies.is_empty() {
        return None;
    }
    let combined = policies.join(", ");
    (combined.len() <= MAX_POLICY_LENGTH).then_some(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_policies() {
        assert_eq!(extract_csp("<html><head><title>x</title></head></html>"), None);
        assert_eq!(
            extract_csp(r#"<meta http-equiv="Content-Security-Policy" content=" default-src 'self' ">"#).as_deref(),
            Some("default-src 'self'")
        );
        assert_eq!(
            extract_csp(
                r#"<meta http-equiv="content-security-policy" content="a"><meta http-equiv="Content-Security-Policy-Report-Only" content="b"><meta http-equiv="CONTENT-SECURITY-POLICY" content="c &amp; d">"#
            )
            .as_deref(),
            Some("a, c & d")
        );
        assert_eq!(
            extract_csp("<meta http-equiv=\"content-security-policy\" content=\"default-src 'self';\n      img-src https:\">").as_deref(),
            Some("default-src 'self'; img-src https:")
        );
        assert_eq!(extract_csp("<meta http-equiv=\"content-security-policy\" content=\"a\u{2028}b\">"), None);
        let long = format!(r#"<meta http-equiv="content-security-policy" content="{}">"#, "a".repeat(9000));
        assert_eq!(extract_csp(&long), None);
        assert_eq!(extract_csp(r#"<head></head><body><div><meta http-equiv="content-security-policy" content="a"></div></body>"#), None);
    }

    #[test]
    fn falls_back_to_the_default() {
        assert_eq!(site_policy(None), DEFAULT_CSP);
        assert_eq!(site_policy(Some("<title>x</title>")), DEFAULT_CSP);
        assert_eq!(site_policy(Some(r#"<meta http-equiv="content-security-policy" content="a">"#)), "a, frame-ancestors 'none'");
    }

    #[test]
    fn denies_framing_unless_the_site_says_otherwise() {
        let policy = |content: &str| site_policy(Some(&format!(r#"<meta http-equiv="content-security-policy" content="{content}">"#)));
        assert!(denies_framing(DEFAULT_CSP));
        assert!(denies_framing(policy("default-src 'self'").to_str().unwrap()));
        let own = policy("default-src 'self'; Frame-Ancestors https://host.example");
        assert_eq!(own, "default-src 'self'; Frame-Ancestors https://host.example");
        assert!(!denies_framing(own.to_str().unwrap()));
        assert!(denies_framing("default-src 'self'; frame-ancestors 'none'"));
        // Only the directive itself counts.
        assert!(!denies_framing("default-src 'self'; frame-src 'none'"));
        assert_eq!(policy("frame-src 'none'"), "frame-src 'none', frame-ancestors 'none'");
    }
}
