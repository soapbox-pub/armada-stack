//! The tests run against the LiveKit releases build in, so the two
//! workflows have to pin the same one.

#[test]
fn tests_and_releases_pin_the_same_livekit() {
    let test = include_str!("../.ngit/act/workflows/test.yml");
    let release = include_str!("../.ngit/act/workflows/release.yml");
    for name in ["LIVEKIT_VERSION", "LIVEKIT_AMD64_SHA256"] {
        let pin = |workflow: &str| {
            let line = workflow.lines().map(str::trim).find(|line| line.starts_with(&format!("{name}:")));
            line.expect("the workflow pins LiveKit").to_string()
        };
        assert_eq!(pin(test), pin(release), "test.yml's {name} differs from release.yml's");
    }
}
