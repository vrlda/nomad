use std::env;
use std::fs;
use std::process;

use nomad_engine::xray::{XrayConfig, XrayOutbound};
use serde_json::{json, Value};

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

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: xray-fixture-check <fixture-set.json>");
        process::exit(2);
    };
    let raw = fs::read_to_string(path).unwrap_or_else(|error| {
        eprintln!("failed to read fixture set: {error}");
        process::exit(2);
    });
    let root: Value = serde_json::from_str(&raw).unwrap_or_else(|error| {
        eprintln!("fixture set is invalid JSON: {error}");
        process::exit(2);
    });
    let Some(fixtures) = root["fixtures"].as_array() else {
        eprintln!("fixture set must contain a fixtures array");
        process::exit(2);
    };

    for fixture in fixtures {
        let id = fixture["id"].as_str().unwrap_or("unknown");
        let profile = fixture["profile"].to_string();
        let result = match XrayConfig::from_json(&profile) {
            Ok(config) => json!({
                "id": id,
                "accepted": true,
                "protocol": outbound_name(config.outbound()),
                "transport": config.transport().method.as_str(),
                "security": config.transport().security.as_str(),
            }),
            Err(error) => json!({
                "id": id,
                "accepted": false,
                "error": error.to_string(),
            }),
        };
        println!("{result}");
    }
}
