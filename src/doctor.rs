//! `dyrs doctor` — what connection do you actually have, and what can you
//! host on it?
//!
//! People currently answer this by stitching together forum posts. The one
//! rule here is that dyrs says what it knows, says what it cannot know from
//! this machine alone, and never guesses in a way that reads like a fact.

use crate::config::Config;
use crate::net::{self, Kind};
use crate::stun;
use std::net::IpAddr;

pub fn run(cfg: &Config, show_all: bool) -> i32 {
    println!("dyrs doctor\n");

    // ---- what this machine holds ------------------------------------------
    let locals = net::local_addresses();
    let (real, virt): (Vec<_>, Vec<_>) = locals.iter().partition(|l| show_all || !l.virtual_iface);
    println!("Local interfaces");
    if real.is_empty() {
        println!("  (none found — that is unusual)");
    }
    for l in &real {
        println!(
            "  {:<16} {:<40} {}{}",
            l.interface,
            l.ip.to_string(),
            l.kind,
            if l.kind.reachable() {
                "  <- reachable from outside"
            } else {
                ""
            }
        );
    }
    if !virt.is_empty() {
        println!(
            "  ({} address(es) on container/VPN interfaces hidden — dyrs doctor --all)",
            virt.len()
        );
    }
    let on_cgnat_directly = locals.iter().any(|l| l.kind == Kind::Cgnat);
    let holds_global_v4 = locals
        .iter()
        .any(|l| l.kind == Kind::Global && l.ip.is_ipv4());
    let global_v6 = net::global_ipv6();

    // ---- what the outside sees --------------------------------------------
    println!("\nPublic IPv4 (STUN — no account, no API key)");
    let (agreed_v4, results) = stun::consensus(&cfg.stun_servers, cfg.timeout(), false);
    let mut answered = 0;
    for (server, r) in &results {
        match r {
            Ok(reflexive) => {
                answered += 1;
                println!(
                    "  {:<28} {:<16} (sent from {})",
                    server,
                    reflexive.public.ip().to_string(),
                    reflexive.local.ip()
                );
            }
            Err(e) => println!("  {:<28} unreachable ({})", server, short(&e.to_string())),
        }
    }
    if answered == 0 {
        println!("\n  No STUN server answered. UDP may be blocked on this network.");
    }

    // ---- IPv6 --------------------------------------------------------------
    println!("\nIPv6");
    match &global_v6 {
        Some(l) => println!("  {} on {} — globally routable", l.ip, l.interface),
        None => println!("  no global IPv6 address on this machine"),
    }

    // ---- the verdict -------------------------------------------------------
    println!("\n{}", "-".repeat(64));
    println!("Verdict\n");
    let mut exit = 0;

    match agreed_v4 {
        Some(public) if net::classify(public) == Kind::Cgnat => {
            // The carrier did not even hand out a routable address.
            println!("  Behind CGNAT — confirmed.");
            println!("  The address the internet sees for you ({public}) is itself inside");
            println!("  100.64.0.0/10, the carrier NAT range. Nobody outside can reach it.");
            exit = 1;
        }
        Some(public) if holds_global_v4 && locals.iter().any(|l| l.ip == public) => {
            println!("  You have a public IPv4 address directly on this machine ({public}).");
            println!("  Inbound works with no port forwarding. A records will do what you expect.");
        }
        Some(public) if on_cgnat_directly => {
            println!("  Behind CGNAT — confirmed.");
            println!("  This machine's WAN address is inside 100.64.0.0/10, so the address");
            println!("  the world sees ({public}) is shared with other customers and no");
            println!("  port forwarding you set can reach you.");
            exit = 1;
        }
        Some(public) => {
            println!("  The internet sees you as {public}, which is globally routable.");
            println!("  This machine holds a private address, so there is at least one NAT");
            println!("  between you and the internet — almost certainly your own router.");
            println!();
            println!("  dyrs cannot tell from this machine alone whether there is a SECOND");
            println!("  NAT above it at your ISP. To settle it, open your router's status");
            println!("  page and look at its WAN address:");
            println!();
            println!("      100.64.x.x - 100.127.x.x   -> you are behind CGNAT");
            println!("      anything else public       -> you are not; port forwarding will work");
            println!();
            println!("  (If your router does PPPoE, the WAN address is the one PPP assigned.)");
        }
        None if answered == 0 => {
            println!("  Could not determine your public address — no STUN server replied.");
            exit = 2;
        }
        None => {
            println!("  STUN servers disagreed about your address, which usually means a");
            println!("  load-balanced or multi-homed connection. Re-run; if it persists,");
            println!("  your outbound traffic is leaving via more than one address.");
            exit = 2;
        }
    }

    println!();
    match &global_v6 {
        Some(l) => {
            println!("  You have working IPv6 ({}).", l.ip);
            println!("  This is the way out of CGNAT: an AAAA record pointing here is");
            println!("  reachable from any IPv6-capable client, with no relay, no VPS and");
            println!("  no third party in the path. Set ipv6 = true in your config.");
        }
        None => {
            println!("  No IPv6. If you are behind CGNAT, that combination means nothing");
            println!("  dyrs does can make you reachable from outside — something with a");
            println!("  public address has to relay for you (WireGuard on a cheap VPS, or");
            println!("  a tunnel service). That is a property of the network, not a gap in");
            println!("  this tool. Ask your ISP whether they offer IPv6; many that deploy");
            println!("  CGNAT do, precisely because they ran out of IPv4.");
        }
    }

    println!("\n  Outbound still works regardless: anything that dials out — a Telegram");
    println!("  bot, a backup job, a tunnel client — is unaffected by any of the above.");

    exit
}

fn short(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(48).collect()
}

/// Shared by `update`: the address we would publish, or why we cannot.
pub fn discover(cfg: &Config) -> (Option<IpAddr>, Option<IpAddr>) {
    let v4 = if cfg.ipv4 {
        stun::consensus(&cfg.stun_servers, cfg.timeout(), false).0
    } else {
        None
    };
    let v6 = if cfg.ipv6 {
        net::global_ipv6().map(|l| l.ip)
    } else {
        None
    };
    (v4, v6)
}
