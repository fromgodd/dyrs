//! Address classification and local interface discovery.
//!
//! This is where dyrs decides what your connection actually is, which is the
//! question DDNS tools usually skip and then fail silently on.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of address we are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Routable on the public internet. This is the one you can point DNS at.
    Global,
    /// RFC 6598 100.64.0.0/10 — the carrier's side of a CGNAT. Seeing this on
    /// your WAN interface is the definitive "you are behind CGNAT" signal.
    Cgnat,
    /// RFC 1918 / RFC 4193 — your own LAN.
    Private,
    /// 169.254/16 or fe80::/10 — no DHCP answered, or link-local only.
    LinkLocal,
    Loopback,
    /// Multicast, documentation ranges, reserved space.
    Unusable,
}

impl Kind {
    pub fn describe(self) -> &'static str {
        match self {
            Kind::Global => "globally routable",
            Kind::Cgnat => "carrier-grade NAT (RFC 6598)",
            Kind::Private => "private / LAN",
            Kind::LinkLocal => "link-local",
            Kind::Loopback => "loopback",
            Kind::Unusable => "reserved or unusable",
        }
    }

    /// Can the outside world open a connection to this address?
    pub fn reachable(self) -> bool {
        self == Kind::Global
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

pub fn classify(ip: IpAddr) -> Kind {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

pub fn classify_v4(ip: Ipv4Addr) -> Kind {
    let o = ip.octets();
    if ip.is_loopback() {
        return Kind::Loopback;
    }
    if ip.is_link_local() {
        return Kind::LinkLocal;
    }
    // RFC 6598: 100.64.0.0/10 — the whole reason `doctor` exists.
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return Kind::Cgnat;
    }
    if ip.is_private() {
        return Kind::Private;
    }
    if ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified() {
        return Kind::Unusable;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 are documentation ranges,
    // and 240/4 is reserved. None of them belong on a real WAN interface.
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240
    {
        return Kind::Unusable;
    }
    Kind::Global
}

pub fn classify_v6(ip: Ipv6Addr) -> Kind {
    if ip.is_loopback() {
        return Kind::Loopback;
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Kind::Unusable;
    }
    let seg = ip.segments();
    // fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return Kind::LinkLocal;
    }
    // fc00::/7 unique-local — the IPv6 equivalent of RFC 1918
    if (seg[0] & 0xfe00) == 0xfc00 {
        return Kind::Private;
    }
    // 2001:db8::/32 documentation
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return Kind::Unusable;
    }
    // 2000::/3 is the only space currently allocated as global unicast.
    if (seg[0] & 0xe000) == 0x2000 {
        return Kind::Global;
    }
    Kind::Unusable
}

/// One address found on a local interface.
#[derive(Debug, Clone)]
pub struct Local {
    pub interface: String,
    pub ip: IpAddr,
    pub kind: Kind,
    /// A container bridge, VM tap, VPN tunnel or similar. Never the way you
    /// reach the internet, and on a Docker host there can be dozens, so
    /// `doctor` folds them away unless asked.
    pub virtual_iface: bool,
}

/// Interface names that are created by software rather than plugged in.
/// The naming differs wildly by platform, so the list lives in `platform`.
use crate::platform::looks_virtual;

/// Every address on every interface, loopback excluded.
pub fn local_addresses() -> Vec<Local> {
    let mut out = Vec::new();
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            let ip = a.ip();
            let kind = classify(ip);
            if kind == Kind::Loopback {
                continue;
            }
            let virtual_iface = looks_virtual(&a.name);
            out.push(Local {
                interface: a.name.clone(),
                ip,
                kind,
                virtual_iface,
            });
        }
    }
    out.sort_by(|a, b| a.interface.cmp(&b.interface));
    out
}

/// The address dyrs would publish as an AAAA record.
///
/// Picks a global IPv6 off a real interface. This needs no external service at
/// all — if your ISP gives you IPv6, the address is already sitting on your
/// machine, which is exactly why IPv6 is the honest answer to CGNAT.
pub fn global_ipv6() -> Option<Local> {
    local_addresses()
        .into_iter()
        // A global address on a tunnel is someone else's; we want the one the
        // ISP put on a real interface.
        .filter(|l| l.kind == Kind::Global && l.ip.is_ipv6() && !l.virtual_iface)
        // Prefer a non-temporary-looking address: lowest is a weak but stable
        // heuristic, and a stable record beats one that rotates twice a day.
        .min_by_key(|l| l.ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Kind {
        classify_v4(s.parse().unwrap())
    }
    fn v6(s: &str) -> Kind {
        classify_v6(s.parse().unwrap())
    }

    #[test]
    fn cgnat_range_boundaries() {
        // RFC 6598 is 100.64.0.0/10 — that is 100.64.x.x through 100.127.x.x.
        // Getting either edge wrong is the difference between telling someone
        // they can self-host and telling them they cannot.
        assert_eq!(v4("100.64.0.0"), Kind::Cgnat, "first address in range");
        assert_eq!(v4("100.127.255.255"), Kind::Cgnat, "last address in range");
        assert_eq!(v4("100.100.50.1"), Kind::Cgnat, "middle of range");
        assert_eq!(v4("100.63.255.255"), Kind::Global, "one below the range");
        assert_eq!(v4("100.128.0.0"), Kind::Global, "one above the range");
    }

    #[test]
    fn ordinary_v4_classification() {
        assert_eq!(v4("8.8.8.8"), Kind::Global);
        assert_eq!(v4("5.133.121.212"), Kind::Global);
        assert_eq!(v4("192.168.1.1"), Kind::Private);
        assert_eq!(v4("10.0.0.1"), Kind::Private);
        assert_eq!(v4("172.16.0.1"), Kind::Private);
        assert_eq!(v4("172.32.0.1"), Kind::Global, "just outside 172.16/12");
        assert_eq!(v4("169.254.1.1"), Kind::LinkLocal);
        assert_eq!(v4("127.0.0.1"), Kind::Loopback);
        assert_eq!(v4("192.0.2.5"), Kind::Unusable, "TEST-NET-1");
        assert_eq!(v4("240.0.0.1"), Kind::Unusable, "reserved");
    }

    #[test]
    fn v6_classification() {
        assert_eq!(v6("2001:4860:4860::8888"), Kind::Global);
        assert_eq!(v6("2a00:1450:4001::1"), Kind::Global);
        assert_eq!(v6("fe80::1"), Kind::LinkLocal);
        assert_eq!(v6("fd00::1"), Kind::Private, "unique-local");
        assert_eq!(v6("fc00::1"), Kind::Private);
        assert_eq!(v6("::1"), Kind::Loopback);
        assert_eq!(v6("2001:db8::1"), Kind::Unusable, "documentation range");
        assert_eq!(v6("ff02::1"), Kind::Unusable, "multicast");
    }

    #[test]
    fn only_global_is_reachable() {
        assert!(Kind::Global.reachable());
        for k in [
            Kind::Cgnat,
            Kind::Private,
            Kind::LinkLocal,
            Kind::Loopback,
            Kind::Unusable,
        ] {
            assert!(!k.reachable(), "{k:?} must not count as reachable");
        }
    }

    #[test]
    fn tunnels_are_virtual_everywhere() {
        for name in ["wg0", "tailscale0", "tun0", "utun3", "zt5u4"] {
            assert!(
                looks_virtual(name),
                "{name} should be virtual on any platform"
            );
        }
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux_interface_names() {
        for name in ["docker0", "br-01f408ab71c9", "veth1a2b", "lo", "virbr0"] {
            assert!(looks_virtual(name), "{name} should be virtual");
        }
        for name in ["eth0", "ens18", "enp3s0", "wlan0", "ppp0"] {
            assert!(!looks_virtual(name), "{name} should be a real interface");
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_interface_names() {
        for name in ["lo0", "awdl0", "bridge0", "gif0"] {
            assert!(looks_virtual(name), "{name} should be virtual");
        }
        for name in ["en0", "en1"] {
            assert!(!looks_virtual(name), "{name} should be a real interface");
        }
    }

    #[test]
    #[cfg(windows)]
    fn windows_interface_names() {
        for name in [
            "vEthernet (Default Switch)",
            "VirtualBox Host-Only Network",
            "Loopback Pseudo-Interface 1",
        ] {
            assert!(looks_virtual(name), "{name} should be virtual");
        }
        for name in ["Ethernet", "Wi-Fi", "Ethernet 2"] {
            assert!(!looks_virtual(name), "{name} should be a real interface");
        }
    }
}
