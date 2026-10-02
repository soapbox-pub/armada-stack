//! The version being served, held in memory, and how a request path finds a
//! file in it.

use std::collections::HashMap;

use http::HeaderValue;

use super::csp::{MAX_HTML_BYTES, site_policy};
use crate::blobs::{BlobStore, Variants};
use crate::hash::BlobHash;
use crate::nostr::Event;
use crate::nsite::{join_root, manifest_paths, normalize_site_path};
use crate::util::{extname, http_date};

#[derive(Clone, Copy, Debug)]
pub struct File {
    pub sha256: BlobHash,
    /// Sizes of the blob and its compressed copies, read once when the
    /// version went live.
    pub variants: Variants,
}

/// One version of the site, every file of it on disk. Immutable: a new
/// version is a new `Site`, swapped in whole.
pub struct Site {
    pub event_id: String,
    pub files: HashMap<String, File>,
    /// The `Last-Modified` every response carries: when the version was
    /// published, as its author's clock tells it.
    pub last_modified: HeaderValue,
    /// The `Content-Security-Policy` every response carries.
    pub csp: HeaderValue,
}

/// What a request path resolved to.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved<'a> {
    /// The site path whose file answers, which names its content type.
    pub path: &'a str,
    /// 200 for a file the site has, or 404 for its not-found page.
    pub status: u16,
}

impl Site {
    /// The site a manifest describes, if every blob it lists is stored.
    /// Otherwise the first missing hash.
    pub fn load(event: &Event, blobs: &BlobStore) -> Result<Site, BlobHash> {
        let mut files = HashMap::new();
        for (path, sha256) in manifest_paths(event) {
            let variants = blobs.variants(sha256).ok_or(sha256)?;
            files.insert(path, File { sha256, variants });
        }
        let index = files.get("/index.html").map(|file| blobs.read_text(file.sha256, MAX_HTML_BYTES));
        Ok(Site {
            event_id: event.id.clone(),
            files,
            last_modified: HeaderValue::from_str(&http_date(event.created_at)).expect("an HTTP date is a valid header"),
            csp: site_policy(index.as_deref()),
        })
    }

    /// Resolve a request path: exact match, then — for an extensionless
    /// path — a `.html` sibling and then `index.html` beneath it, and finally
    /// the site's own `/404.html`.
    ///
    /// `spa` turns the last step into a client-side router's entry point: a
    /// document request gets the site's shell under a `200` — `/404.html`
    /// first, since NIP-5A names it as the fallback path, then `/index.html`.
    /// Asset requests are untouched: a missing script must 404, not answer
    /// with a page of HTML, or Armada's chunk-error recovery can't tell.
    pub fn resolve(&self, request_path: &str, spa: bool) -> Option<(Resolved<'_>, &File)> {
        let normalized = normalize_site_path(request_path);
        let extension = extname(&normalized);
        let extensionless = extension.is_empty();
        let shell = spa && matches!(extension.to_ascii_lowercase().as_str(), "" | ".html" | ".htm");

        let mut candidates: Vec<(String, u16)> = vec![(normalized.clone(), 200)];
        if extensionless && normalized != "/" {
            candidates.push((format!("{normalized}.html"), 200));
        }
        if extensionless {
            candidates.push((join_root(&format!("{normalized}/index.html")), 200));
        }
        candidates.push(("/404.html".into(), if shell { 200 } else { 404 }));
        if shell {
            candidates.push(("/index.html".into(), 200));
        }

        candidates.into_iter().find_map(|(path, status)| {
            let (path, file) = self.files.get_key_value(&path)?;
            Some((Resolved { path, status }, file))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(paths: &[&str]) -> Site {
        let file = File { sha256: BlobHash::of(b"x"), variants: Variants { identity: 1, br: None, gzip: None } };
        Site {
            event_id: String::new(),
            files: paths.iter().map(|path| (path.to_string(), file)).collect(),
            last_modified: HeaderValue::from_static(""),
            csp: HeaderValue::from_static(""),
        }
    }

    fn resolve(site: &Site, path: &str, spa: bool) -> Option<(String, u16)> {
        site.resolve(path, spa).map(|(resolved, _)| (resolved.path.to_string(), resolved.status))
    }

    #[test]
    fn resolves_paths() {
        let docs = site(&["/index.html", "/about.html", "/guide/index.html", "/a b.txt", "/404.html"]);
        let found = |path: &str| Some((path.to_string(), 200));

        assert_eq!(resolve(&docs, "/", false), found("/index.html"));
        assert_eq!(resolve(&docs, "/about", false), found("/about.html"));
        assert_eq!(resolve(&docs, "/guide", false), found("/guide/index.html"));
        assert_eq!(resolve(&docs, "/guide/", false), found("/guide/index.html"));
        assert_eq!(resolve(&docs, "/a%20b.txt", false), found("/a b.txt"));
        assert_eq!(resolve(&docs, "/../about.html", false), found("/about.html"));
        assert_eq!(resolve(&docs, "/missing", false), Some(("/404.html".into(), 404)));
        assert_eq!(resolve(&docs, "/missing", true), Some(("/404.html".into(), 200)));
        assert_eq!(resolve(&docs, "/missing.js", true), Some(("/404.html".into(), 404)));
    }

    #[test]
    fn falls_back_to_the_shell() {
        let app = site(&["/index.html", "/assets/app.js"]);
        assert_eq!(resolve(&app, "/invite/naddr1abc", true), Some(("/index.html".into(), 200)));
        assert_eq!(resolve(&app, "/settings.html", true), Some(("/index.html".into(), 200)));
        assert_eq!(resolve(&app, "/assets/gone.js", true), None);
        assert_eq!(resolve(&app, "/invite/naddr1abc", false), None);
    }
}
