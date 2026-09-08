use nomad_engine::xray::{XrayConfig, XrayOutbound};
use serde_json::Value;

const FIXTURES: &str = include_str!("fixtures/xray/v25.12.8.json");

fn outbound_name(outbound: &XrayOutbound) -> &'static str {
    match outbound {
        XrayOutbound::Blackhole { .. } => "blackhole",
        XrayOutbound::Freedom(_) => "freedom",
        XrayOutbound::Dns(_) => "dns",
        XrayOutbound::Socks5(_) => "socks",
        XrayOutbound::HttpConnect(_) => "http",
        XrayOutbound::Shadowsocks(_) => "shadowsocks",
        XrayOutbound::Vless(_) => "vless",
        XrayOutbound::Vmess(_) => "vmess",
        XrayOutbound::Trojan(_) => "trojan",
        XrayOutbound::Hysteria(_) => "hysteria",
        XrayOutbound::WireGuard(_) => "wireguard",
        XrayOutbound::Loopback(_) => "loopback",
    }
}

#[test]
fn pinned_xray_reference_profiles_have_matching_nomad_signatures() {
    let root: Value = serde_json::from_str(FIXTURES).expect("fixture set is valid JSON");
    for fixture in root["fixtures"].as_array().expect("fixtures array") {
        let id = fixture["id"].as_str().expect("fixture id");
        let should_accept = fixture["referenceAccepted"].as_bool().unwrap_or(true);
        let result = XrayConfig::from_json(&fixture["profile"].to_string());
        if !should_accept {
            assert!(
                result.is_err(),
                "Nomad accepted rejected reference fixture {id}"
            );
            continue;
        }
        let config =
            result.unwrap_or_else(|error| panic!("Nomad rejected reference fixture {id}: {error}"));
        let expected = &fixture["expected"];
        assert_eq!(
            outbound_name(config.outbound()),
            expected["protocol"].as_str().expect("expected protocol"),
            "protocol mismatch for {id}"
        );
        assert_eq!(
            config.transport().method.as_str(),
            expected["transport"].as_str().expect("expected transport"),
            "transport mismatch for {id}"
        );
        assert_eq!(
            config.transport().security.as_str(),
            expected["security"].as_str().expect("expected security"),
            "security mismatch for {id}"
        );
        if id == "dns-tcp-explicit-server" {
            let XrayOutbound::Dns(dns) = config.outbound() else {
                panic!("DNS fixture did not produce a DNS outbound");
            };
            assert_eq!(dns.address.as_deref(), Some("1.1.1.1"));
            assert_eq!(dns.port, Some(53));
        }
    }
}
