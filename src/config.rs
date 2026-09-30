//! The TOML config. One file, no config language, no templating.

use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

fn default_stun_servers() -> Vec<String> {
    crate::stun::DEFAULT_SERVERS
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_timeout() -> u64 {
    4
}
fn default_state() -> String {
    crate::platform::default_state()
        .to_string_lossy()
        .into_owned()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Where the last-seen addresses are remembered between runs. An absolute
    /// path on purpose: dyrs is meant to be run from cron, whose working
    /// directory is not something you should have to think about.
    #[serde(default = "default_state")]
    pub state: String,

    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,

    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Publish an A record from the STUN-discovered IPv4 address.
    #[serde(default = "default_true")]
    pub ipv4: bool,

    /// Publish an AAAA record from a global IPv6 address on this machine.
    /// Off by default because a host without IPv6 should not log errors
    /// about it on every run.
    #[serde(default)]
    pub ipv6: bool,

    #[serde(default)]
    pub provider: Vec<Provider>,

    #[serde(default)]
    pub on_change: Vec<Hook>,
}

/// A DNS provider to update. Every one of these has a free tier that does not
/// ask for a card; `command` is the escape hatch for everything else,
/// including RFC 2136 via nsupdate against a server you run yourself.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Provider {
    /// duckdns.org — free, token only.
    Duckdns { domains: String, token: String },
    /// desec.io — free, run by a German non-profit, open source.
    Desec { domain: String, token: String },
    /// dynv6.com — free.
    Dynv6 { hostname: String, token: String },
    /// Cloudflare's free tier. Needs an API token scoped to Zone:DNS:Edit.
    Cloudflare {
        zone_id: String,
        record_name: String,
        api_token: String,
        #[serde(default)]
        proxied: bool,
    },
}

impl Provider {
    pub fn label(&self) -> String {
        match self {
            Provider::Duckdns { domains, .. } => format!("duckdns:{domains}"),
            Provider::Desec { domain, .. } => format!("desec:{domain}"),
            Provider::Dynv6 { hostname, .. } => format!("dynv6:{hostname}"),
            Provider::Cloudflare { record_name, .. } => format!("cloudflare:{record_name}"),
        }
    }
}

/// Something to run when the address changes. This is the "companion" half:
/// updating DNS is just one useful reaction to a new address, not the only one.
#[derive(Debug, Deserialize)]
pub struct Hook {
    /// Program to run. Argument vector, not a shell string — no quoting bugs,
    /// no accidental shell injection from a value that came off the network.
    pub command: Vec<String>,
    /// Optional label for the log line.
    #[serde(default)]
    pub name: Option<String>,
}

impl Config {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.max(1))
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Used by `doctor`, which must work before any config exists.
    pub fn defaults() -> Config {
        Config {
            state: default_state(),
            stun_servers: default_stun_servers(),
            timeout_secs: default_timeout(),
            ipv4: true,
            ipv6: false,
            provider: Vec::new(),
            on_change: Vec::new(),
        }
    }
}
