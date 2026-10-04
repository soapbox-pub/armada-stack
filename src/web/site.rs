//! The version being served, with the versions before it merged beneath,
//! held in memory, and how a request path finds a file in it.
//!
//! Merged as npanel merges a host's deployments: a path is served from the
//! newest version that has it. Armada's chunks are named by their content,
//! and a page already open goes on asking for the names of the version it
//! was loaded from, which are just the files the next version drops.

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

/// One version of the site and those merged beneath it, every file of them
/// on disk. Immutable: a new version is a new `Site`, swapped in whole.
pub struct Site {
    /// The version being served.
    pub event_id: String,
    pub files: HashMap<String, File>,
    /// The `Last-Modified` every response carries: when the version was
    /// published, as its author's clock tells it.
    pub last_modified: HeaderValue,
    /// The `Content-Security-Policy` every response carries.
    pub csp: HeaderValue,
}

/// Where a Vite build puts its chunks, each named by its content.
pub const ASSETS: &str = "/assets/";

/// Where software probes a site for a capability (RFC 8615).
const WELL_KNOWN: &str = "/.well-known";

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
    /// The site `served` describes, with the files of `earlier` versions,
    /// newest first, beneath it, if every blob `served` lists is stored.
    /// Otherwise the first missing hash. An earlier version missing a blob is
    /// left out.
    pub fn load(served: &Event, earlier: &[Event], blobs: &BlobStore) -> Result<Site, BlobHash> {
        let mut files = version_files(served, blobs)?;
        for event in earlier {
            match version_files(event, blobs) {
                Ok(older) => {
                    for (path, file) in older {
                        files.entry(path).or_insert(file);
                    }
                }
                Err(missing) => tracing::warn!(event_id = event.id, sha256 = %missing, "an earlier version is missing blobs; its files aren't merged"),
            }
        }
        for (path, file) in &mut files {
            if matches!(&*lowercase_extname(path), ".html" | ".htm") {
                *file = with_env(path, *file, blobs);
            }
        }
        let index = files.get("/index.html").map(|file| blobs.read_text(file.sha256, MAX_HTML_BYTES));
        Ok(Site {
            event_id: served.id.clone(),
            files,
            last_modified: HeaderValue::from_str(&http_date(served.created_at)).expect("an HTTP date is a valid header"),
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
    /// site has, so nothing is left to tell apart.
    ///
    /// Except under [`ASSETS`], where the build puts its chunks and nothing
    /// is a route. A chunk no kept version has is a 404, as Armada's own
    /// hosting answered, which its chunk-error recovery takes as the cue to
    /// reload onto the version being served.
    ///
    /// And except under [`WELL_KNOWN`]: what asks there is software probing
    /// for a capability — Universal Links, WebFinger, NIP-05 — and any page
    /// at all, let alone the shell under a `200`, tells it the site has one.
    pub fn resolve(&self, request_path: &str) -> Option<(Resolved<'_>, &File)> {
        let normalized = normalize_site_path(request_path);
        let well_known = normalized.strip_prefix(WELL_KNOWN).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
        if normalized.starts_with(ASSETS) || well_known {
            return self.files.get_key_value(&normalized).map(|(path, file)| (Resolved { path, shell: false }, file));
        }
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

/// The files a manifest lists, if every blob is stored. Otherwise the first
/// missing hash.
fn version_files(event: &Event, blobs: &BlobStore) -> Result<HashMap<String, File>, BlobHash> {
    manifest_paths(event).into_iter().map(|(path, sha256)| Ok((path, File { sha256, variants: blobs.variants(sha256).ok_or(sha256)? }))).collect()
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
        assert_eq!(resolve(&app, "/assets/app.js"), Some(("/assets/app.js".into(), false)));
        // Except for chunks, which are files or nothing.
        assert_eq!(resolve(&app, "/assets/gone.js"), None);
        assert_eq!(resolve(&app, "/assets/"), None);
        assert_eq!(resolve(&app, "/assets/../settings"), shell());
        assert_eq!(resolve(&app, "/assetsx/gone.js"), shell());
        assert_eq!(resolve(&site(&["/about.html"]), "/missing"), None);
    }

    #[test]
    fn well_known_is_the_file_or_nothing() {
        let aasa = "/.well-known/apple-app-site-association";
        let app = site(&["/index.html", "/404.html", aasa, "/.well-known/matrix.html", "/.well-known/x/index.html"]);
        assert_eq!(resolve(&app, aasa), Some((aasa.into(), false)));
        assert_eq!(resolve(&app, "/.well-known/nostr.json"), None);
        assert_eq!(resolve(&app, "/.well-known/matrix"), None);
        assert_eq!(resolve(&app, "/.well-known/x"), None);
        assert_eq!(resolve(&app, "/.well-known/"), None);
        assert_eq!(resolve(&app, "/.well-known"), None);
        assert_eq!(resolve(&app, "/.well-known-x/foo"), Some(("/404.html".into(), true)));
    }
}
