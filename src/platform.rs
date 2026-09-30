//! The few places where Linux, macOS and Windows genuinely differ.
//!
//! Kept in one file on purpose. Everything else in dyrs is plain std and
//! portable by accident rather than by effort, which is how it should stay.

use std::path::PathBuf;

/// Where the config lives if `--config` was not given.
///
/// Each platform gets the location its own packages would use, so dyrs does
/// not look like a Unix program that was dropped onto Windows.
pub fn default_config() -> PathBuf {
    if let Some(explicit) = std::env::var_os("DYRS_CONFIG") {
        return PathBuf::from(explicit);
    }
    #[cfg(windows)]
    {
        // C:\ProgramData\dyrs\dyrs.toml — writable by admins, readable by the
        // service account, and it survives user profile changes.
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("dyrs").join("dyrs.toml")
    }
    #[cfg(target_os = "macos")]
    {
        // Homebrew's prefix for config; /etc on macOS is for the system.
        PathBuf::from("/usr/local/etc/dyrs.toml")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/etc/dyrs.toml")
    }
}

/// Where the last-seen address is remembered, when the config does not say.
pub fn default_state() -> PathBuf {
    if let Some(explicit) = std::env::var_os("DYRS_STATE") {
        return PathBuf::from(explicit);
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("dyrs").join("state")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/var/dyrs/state")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/dyrs/state")
    }
}

/// Interface names that software created rather than something you plugged in.
///
/// The three platforms name things nothing like each other, so this is the one
/// list that genuinely has to know where it is running.
pub fn looks_virtual(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();

    // Tunnels and overlays, named consistently enough to check everywhere.
    const COMMON: &[&str] = &["wg", "tailscale", "zt", "tun", "tap", "utun", "ipsec"];
    if COMMON.iter().any(|p| lower.starts_with(p)) {
        return true;
    }

    #[cfg(windows)]
    {
        // Windows uses friendly names with spaces: "vEthernet (Default Switch)",
        // "Hyper-V Virtual Ethernet Adapter", "VirtualBox Host-Only Network".
        const WIN: &[&str] = &[
            "loopback",
            "vethernet",
            "virtualbox",
            "vmware",
            "hyper-v",
            "bluetooth",
            "teredo",
            "isatap",
            "npcap",
            "wan miniport",
        ];
        return WIN.iter().any(|p| lower.contains(p));
    }
    #[cfg(target_os = "macos")]
    {
        // en0/en1 are the real ones; these are not.
        const MAC: &[&str] = &["lo", "awdl", "llw", "bridge", "gif", "stf", "ap", "vmenet"];
        return MAC.iter().any(|p| lower.starts_with(p));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        const LINUX: &[&str] = &[
            "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "cni", "flannel", "kube",
            "lxcbr", "lo", "dummy",
        ];
        LINUX.iter().any(|p| lower.starts_with(p))
    }
}

/// How to schedule dyrs on this platform — shown by `--help` so the answer is
/// where someone will actually look for it.
pub fn schedule_hint() -> &'static str {
    #[cfg(windows)]
    {
        "Schedule it (run as Administrator):\n    \
         schtasks /create /tn dyrs /tr \"C:\\Program Files\\dyrs\\dyrs.exe update\" /sc minute /mo 5 /ru SYSTEM"
    }
    #[cfg(target_os = "macos")]
    {
        "Schedule it with launchd (a plist with StartInterval 300), or cron:\n    \
         */5 * * * * /usr/local/bin/dyrs update >> /usr/local/var/log/dyrs.log 2>&1"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "Schedule it with cron:\n    \
         */5 * * * * /usr/local/bin/dyrs update >> /var/log/dyrs.log 2>&1"
    }
}
