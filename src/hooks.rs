//! Running something when the address changes.
//!
//! The command is an argument vector, never a shell string. The new address
//! arrives through the environment rather than string interpolation, so a
//! value that came off the network can never become part of a command line.

use crate::config::Hook;
use std::net::IpAddr;
use std::process::Command;

pub struct Ran {
    pub name: String,
    pub result: Result<String, String>,
}

pub fn run(hook: &Hook, v4: Option<IpAddr>, v6: Option<IpAddr>, previous: Option<IpAddr>) -> Ran {
    let name = hook.name.clone().unwrap_or_else(|| {
        hook.command
            .first()
            .cloned()
            .unwrap_or_else(|| "(empty)".into())
    });

    let Some((program, args)) = hook.command.split_first() else {
        return Ran {
            name,
            result: Err("hook has no command".into()),
        };
    };

    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(ip) = v4 {
        cmd.env("DYRS_IPV4", ip.to_string());
    }
    if let Some(ip) = v6 {
        cmd.env("DYRS_IPV6", ip.to_string());
    }
    if let Some(ip) = previous {
        cmd.env("DYRS_PREVIOUS", ip.to_string());
    }

    let result = match cmd.output() {
        Err(e) => Err(format!("could not run {program}: {e}")),
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Ok(if s.is_empty() {
                "ok".into()
            } else {
                first_line(&s)
            })
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(format!(
                "exit {}: {}",
                out.status.code().unwrap_or(-1),
                if err.is_empty() {
                    "(no stderr)".into()
                } else {
                    first_line(&err)
                }
            ))
        }
    };
    Ran { name, result }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(160).collect()
}
