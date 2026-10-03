//! The version being served, held in memory, and how a request path finds a
//! file in it.

use std::collections::HashMap;

use http::HeaderValue;

use super::csp::{MAX_HTML_BYTES, site_policy};
use super::inject::{MAX_INJECT_BYTES, inject_env};
use crate::blobs::{BlobStore, Variants};
use crate::hash::BlobHash;
use crate::nostr::Event;
use crate::nsite::{join_root, manifest_paths, normalize_site_path};
use crate::util::{http_date, lowercase_extname};

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
    /// Whether it's the site's shell, standing in for a path it has no
    /// file for.
    pub shell: bool,
}

impl Site {
    /// The site a manifest describes, if every blob it lists is stored.
    /// Otherwise the first missing hash.
    pub fn load(event: &Event, blobs: &BlobStore) -> Result<Site, BlobHash> {
        let mut files = HashMap::new();
        for (path, sha256) in manifest_paths(event) {
            let variants = blobs.variants(sha256).ok_or(sha256)?;
            let mut file = File { sha256, variants };
            if matches!(&*lowercase_extname(&path), ".html" | ".htm") {
                file = with_env(&path, file, blobs);
            }
            files.insert(path, file);
        }
        let index = files.get("/index.html").map(|file| blobs.read_text(file.sha256, MAX_HTML_BYTES));
        Ok(Site {
            event_id: event.id.clone(),
            files,
            last_modified: HeaderValue::from_str(&http_date(event.created_at)).expect("an HTTP date is a valid header"),
            csp: site_policy(index.as_deref()),
        })
    }

    /// Resolve a request path: exact match, then a `.html` sibling, then
    /// `index.html` beneath it.
    ///
    /// Past that, the path is a client-side route, whatever it looks like,
    /// and gets the site's shell: `/404.html` first, since NIP-5A names it as
    /// the fallback path, then `/index.html`. Every other service's paths
    /// were routed away before this, and the manifest says which files the
    /// site has, so nothing is left to tell apart. A missing chunk getting
    /// HTML is fine: browsers refuse HTML as a module, or as anything at all
    /// under `nosniff`, so the import fails just the same.
    pub fn resolve(&self, request_path: &str) -> Option<(Resolved<'_>, &File)> {
        let normalized = normalize_site_path(request_path);
        let mut candidates: Vec<(String, bool)> = vec![(normalized.clone(), false)];
        if normalized != "/" {
            candidates.push((format!("{normalized}.html"), false));
        }
        candidates.push((join_root(&format!("{normalized}/index.html")), false));
        candidates.push(("/404.html".into(), true));
        candidates.push(("/index.html".into(), true));

        candidates.into_iter().find_map(|(path, shell)| {
            let (path, file) = self.files.get_key_value(&path)?;
            Some((Resolved { path, shell }, file))
        })
    }
}

/// A page with the `window.ENV` script added, stored and compressed under a
/// hash of its own — the site's own copy is left as published. Blocking. A
/// page that can't take the tag, or can't be rewritten, is served as it is.
fn with_env(path: &str, file: File, blobs: &BlobStore) -> File {
    if file.variants.identity > MAX_INJECT_BYTES {
        return file;
    }
    let rewrite = || -> anyhow::Result<Option<File>> {
        let Some(page) = inject_env(&blobs.open(file.sha256, None)?) else { return Ok(None) };
        let sha256 = BlobHash::of(&page);
        // Stored by an earlier load of this version, or another with the same page.
        if blobs.size(sha256).is_none() {
            blobs.put(sha256, &page)?;
        }
        blobs.ensure_variants(sha256)?;
        Ok(blobs.variants(sha256).map(|variants| File { sha256, variants }))
    };
    match rewrite() {
        Ok(Some(rewritten)) => rewritten,
        Ok(None) => {
            tracing::info!(path, "page left without the env script: no head, or a 'strict-dynamic' policy");
            file
        }
        Err(error) => {
            tracing::warn!(path, %error, "could not add the env script to a page");
            file
        }
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

    fn resolve(site: &Site, path: &str) -> Option<(String, bool)> {
        site.resolve(path).map(|(resolved, _)| (resolved.path.to_string(), resolved.shell))
    }

    #[test]
    fn resolves_paths() {
        let docs = site(&["/index.html", "/about.html", "/guide/index.html", "/a b.txt", "/404.html"]);
        let found = |path: &str| Some((path.to_string(), false));

        assert_eq!(resolve(&docs, "/"), found("/index.html"));
        assert_eq!(resolve(&docs, "/about"), found("/about.html"));
        assert_eq!(resolve(&docs, "/guide"), found("/guide/index.html"));
        assert_eq!(resolve(&docs, "/guide/"), found("/guide/index.html"));
        assert_eq!(resolve(&docs, "/a%20b.txt"), found("/a b.txt"));
        assert_eq!(resolve(&docs, "/../about.html"), found("/about.html"));
        assert_eq!(resolve(&docs, "/missing"), Some(("/404.html".into(), true)));
        assert_eq!(resolve(&docs, "/missing.js"), Some(("/404.html".into(), true)));
    }

    #[test]
    fn falls_back_to_the_shell() {
        let app = site(&["/index.html", "/assets/app.js"]);
        let shell = || Some(("/index.html".into(), true));
        assert_eq!(resolve(&app, "/invite/naddr1abc"), shell());
        assert_eq!(resolve(&app, "/settings.html"), shell());
        // However much a route looks like a file.
        assert_eq!(resolve(&app, "/s/relay.ditto.pub"), shell());
        assert_eq!(resolve(&app, "/assets/gone.js"), shell());
        assert_eq!(resolve(&app, "/assets/app.js"), Some(("/assets/app.js".into(), false)));
        assert_eq!(resolve(&site(&["/about.html"]), "/missing"), None);
    }
}
