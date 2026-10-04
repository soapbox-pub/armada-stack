//! install.sh carries its own copy of the systemd unit, so it can be run
//! alone; it must be the one in deploy/.

#[test]
fn install_sh_writes_the_deploy_unit() {
    let unit = include_str!("../deploy/armada.service");
    let unit = &unit[unit.find("[Unit]").expect("deploy/armada.service has a [Unit] section")..];
    let script = include_str!("../install.sh");
    assert!(
        script.contains(&format!("<<'EOF'\n{unit}EOF\n")),
        "install.sh's unit differs from deploy/armada.service, from [Unit] on"
    );
}
