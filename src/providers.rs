//! Pushing a new address to a DNS provider.
//!
//! Every provider here has a free tier that does not ask for a payment card.
//! None of them is required: a `command` hook can drive `nsupdate` (RFC 2136)
//! against a nameserver you run yourself, which is the only truly
//! vendor-neutral way to do this and the one dyrs treats as first-class.

use crate::config::Provider;
use std::net::IpAddr;

pub struct Outcome {
    pub label: String,
    pub result: Result<String, String>,
}

fn agent(timeout: std::time::Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent(concat!("dyrs/", env!("CARGO_PKG_VERSION")))
        .build()
}

pub fn update(
    provider: &Provider,
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    timeout: std::time::Duration,
) -> Outcome {
    let label = provider.label();
    let result = match provider {
        Provider::Duckdns { domains, token } => duckdns(domains, token, v4, v6, timeout),
        Provider::Desec { domain, token } => desec(domain, token, v4, v6, timeout),
        Provider::Dynv6 { hostname, token } => dynv6(hostname, token, v4, v6, timeout),
        Provider::Cloudflare {
            zone_id,
            record_name,
            api_token,
            proxied,
        } => cloudflare(zone_id, record_name, api_token, *proxied, v4, v6, timeout),
    };
    Outcome { label, result }
}

fn duckdns(
    domains: &str,
    token: &str,
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let mut req = agent(timeout)
        .get("https://www.duckdns.org/update")
        .query("domains", domains)
        .query("token", token);
    // DuckDNS takes an empty value as "work it out from my source address",
    // which is wrong for us: we already know, and the source address of this
    // request may be a different family than the record we mean to set.
    if let Some(ip) = v4 {
        req = req.query("ip", &ip.to_string());
    }
    if let Some(ip) = v6 {
        req = req.query("ipv6", &ip.to_string());
    }
    let body = req
        .call()
        .map_err(|e| format!("request failed: {e}"))?
        .into_string()
        .map_err(|e| format!("unreadable reply: {e}"))?;
    // DuckDNS answers with a bare OK or KO and HTTP 200 either way.
    if body.trim().starts_with("OK") {
        Ok("OK".into())
    } else {
        Err(format!("DuckDNS rejected the update ({})", body.trim()))
    }
}

fn desec(
    domain: &str,
    token: &str,
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let mut req = agent(timeout)
        .get("https://update.dedyn.io/")
        .set("Authorization", &format!("Token {token}"))
        .query("hostname", domain);
    if let Some(ip) = v4 {
        req = req.query("myipv4", &ip.to_string());
    }
    if let Some(ip) = v6 {
        req = req.query("myipv6", &ip.to_string());
    }
    let body = req
        .call()
        .map_err(|e| format!("request failed: {e}"))?
        .into_string()
        .map_err(|e| format!("unreadable reply: {e}"))?;
    if body.trim().eq_ignore_ascii_case("good") || body.trim().is_empty() {
        Ok("good".into())
    } else {
        Err(format!("deSEC said: {}", body.trim()))
    }
}

fn dynv6(
    hostname: &str,
    token: &str,
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let mut req = agent(timeout)
        .get("https://dynv6.com/api/update")
        .query("hostname", hostname)
        .query("token", token);
    if let Some(ip) = v4 {
        req = req.query("ipv4", &ip.to_string());
    }
    if let Some(ip) = v6 {
        req = req.query("ipv6", &ip.to_string());
    }
    let body = req
        .call()
        .map_err(|e| format!("request failed: {e}"))?
        .into_string()
        .map_err(|e| format!("unreadable reply: {e}"))?;
    let reply = body.trim();
    if reply.contains("updated") || reply.contains("unchanged") || reply.is_empty() {
        Ok(if reply.is_empty() {
            "updated".into()
        } else {
            reply.to_string()
        })
    } else {
        Err(format!("dynv6 said: {reply}"))
    }
}

/// Cloudflare needs the record's id, which is not something a human should
/// have to dig out of the dashboard and paste into a config file. dyrs looks
/// it up by name on every run — one extra request, and the config stays
/// readable.
fn cloudflare(
    zone_id: &str,
    record_name: &str,
    api_token: &str,
    proxied: bool,
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let mut done = Vec::new();
    for (rtype, ip) in [("A", v4), ("AAAA", v6)] {
        let Some(ip) = ip else { continue };
        let agent = agent(timeout);
        let base = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");

        let found: serde_json::Value = agent
            .get(&base)
            .set("Authorization", &format!("Bearer {api_token}"))
            .query("type", rtype)
            .query("name", record_name)
            .call()
            .map_err(|e| format!("lookup failed: {}", trim_cf(e)))?
            .into_json()
            .map_err(|e| format!("unreadable lookup reply: {e}"))?;

        let record_id = found["result"]
            .get(0)
            .and_then(|r| r["id"].as_str())
            .ok_or_else(|| {
                format!("no existing {rtype} record named {record_name} in that zone — create it once in the dashboard, dyrs will keep it updated")
            })?
            .to_string();

        let payload = serde_json::json!({
            "type": rtype,
            "name": record_name,
            "content": ip.to_string(),
            "ttl": 60,
            "proxied": proxied,
        });

        let reply: serde_json::Value = agent
            .put(&format!("{base}/{record_id}"))
            .set("Authorization", &format!("Bearer {api_token}"))
            .send_json(payload)
            .map_err(|e| format!("update failed: {}", trim_cf(e)))?
            .into_json()
            .map_err(|e| format!("unreadable update reply: {e}"))?;

        if reply["success"].as_bool() != Some(true) {
            let why = reply["errors"][0]["message"]
                .as_str()
                .unwrap_or("unknown error");
            return Err(format!("Cloudflare refused the {rtype} update: {why}"));
        }
        done.push(rtype);
    }
    if done.is_empty() {
        Ok("nothing to do".into())
    } else {
        Ok(format!("{} updated", done.join(" + ")))
    }
}

/// ureq puts the whole response body in the Display of an HTTP error, which
/// for Cloudflare is a wall of JSON. Keep the useful front of it.
fn trim_cf(e: ureq::Error) -> String {
    let s = e.to_string();
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s
    }
}
