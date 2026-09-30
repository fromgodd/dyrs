//! dyrs — dynamic DNS companion.
//!
//! Three things, in this order of importance:
//!   doctor  tell me what connection I actually have
//!   update  keep DNS pointed at me, and run hooks when I move
//!   ip      print the address and shut up (for scripts)
//!
//! No daemon. Run it from cron or a systemd timer; it does its work and exits.

mod config;
mod doctor;
mod hooks;
mod net;
mod platform;
mod providers;
mod state;
mod stun;

use config::Config;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
dyrs — dynamic DNS companion

USAGE:
    dyrs [--config PATH] <COMMAND>

COMMANDS:
    doctor        Report what connection this machine has and what it can host
    update        Update DNS and run hooks if the address changed (default)
    ip            Print the current public address, one per line
    version       Print the version

OPTIONS:
    -c, --config PATH    Config file (see `dyrs version` for this platform's default)
    -f, --force          Update even if the address has not changed
    -n, --dry-run        Say what would happen, change nothing
    -a, --all            doctor: show container and VPN interfaces too
    -h, --help           This

";

struct Args {
    command: String,
    config: PathBuf,
    force: bool,
    dry_run: bool,
    all: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut command = None;
    let mut config = platform::default_config();
    let (mut force, mut dry_run, mut all) = (false, false, false);

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                println!("{}", platform::schedule_hint());
                std::process::exit(0);
            }
            "-c" | "--config" => {
                config = it
                    .next()
                    .map(PathBuf::from)
                    .ok_or("--config needs a path")?;
            }
            "-f" | "--force" => force = true,
            "-n" | "--dry-run" => dry_run = true,
            "-a" | "--all" => all = true,
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            other => {
                if command.replace(other.to_string()).is_some() {
                    return Err(format!("unexpected extra argument {other}"));
                }
            }
        }
    }
    Ok(Args {
        command: command.unwrap_or_else(|| "update".into()),
        config,
        force,
        dry_run,
        all,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("dyrs: {e}\n");
            print!("{USAGE}");
            return ExitCode::from(64); // EX_USAGE
        }
    };

    match args.command.as_str() {
        "version" => {
            println!("dyrs {}", env!("CARGO_PKG_VERSION"));
            println!(
                "platform    {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            println!("config      {}", platform::default_config().display());
            println!("state       {}", platform::default_state().display());
            ExitCode::SUCCESS
        }
        // doctor must work before a config exists — that is the point of it.
        "doctor" => {
            let cfg = Config::load(&args.config).unwrap_or_else(|_| Config::defaults());
            ExitCode::from(doctor::run(&cfg, args.all) as u8)
        }
        "ip" => {
            let cfg = Config::load(&args.config).unwrap_or_else(|_| Config::defaults());
            let (v4, v6) = doctor::discover(&Config { ipv6: true, ..cfg });
            if v4.is_none() && v6.is_none() {
                eprintln!("dyrs: could not determine any public address");
                return ExitCode::FAILURE;
            }
            if let Some(ip) = v4 {
                println!("{ip}");
            }
            if let Some(ip) = v6 {
                println!("{ip}");
            }
            ExitCode::SUCCESS
        }
        "update" => match update(&args) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("dyrs: {e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("dyrs: unknown command {other}\n");
            print!("{USAGE}");
            ExitCode::from(64)
        }
    }
}

fn update(args: &Args) -> Result<u8, String> {
    let cfg = Config::load(&args.config)?;
    let state_path = PathBuf::from(&cfg.state);
    let previous = state::State::load(&state_path);

    let (v4, v6) = doctor::discover(&cfg);
    if v4.is_none() && v6.is_none() {
        return Err("could not determine any public address — run `dyrs doctor`".into());
    }

    let changed = v4 != previous.v4 || v6 != previous.v6;
    let stamp = timestamp();

    if !changed && !args.force {
        // The common case, several times an hour. Keep it to one quiet line so
        // a year of cron output is still readable.
        println!(
            "{stamp} unchanged {}",
            [v4.map(|i| i.to_string()), v6.map(|i| i.to_string())]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ")
        );
        return Ok(0);
    }

    println!(
        "{stamp} changed {} -> {}",
        describe(previous.v4, previous.v6),
        describe(v4, v6)
    );

    if args.dry_run {
        for p in &cfg.provider {
            println!("{stamp}   would update {}", p.label());
        }
        for h in &cfg.on_change {
            println!("{stamp}   would run {}", h.command.join(" "));
        }
        return Ok(0);
    }

    let mut failures = 0;
    for p in &cfg.provider {
        let outcome = providers::update(p, v4, v6, cfg.timeout());
        match outcome.result {
            Ok(msg) => println!("{stamp}   {} {}", outcome.label, msg),
            Err(msg) => {
                failures += 1;
                eprintln!("{stamp}   {} FAILED: {}", outcome.label, msg);
            }
        }
    }

    for h in &cfg.on_change {
        let ran = hooks::run(h, v4, v6, previous.v4.or(previous.v6));
        match ran.result {
            Ok(msg) => println!("{stamp}   hook {} {}", ran.name, msg),
            Err(msg) => {
                failures += 1;
                eprintln!("{stamp}   hook {} FAILED: {}", ran.name, msg);
            }
        }
    }

    // Only remember the new address once everything that had to know has been
    // told. If a provider was down, the next run must try again rather than
    // believe the record is already correct.
    if failures == 0 {
        state::State { v4, v6 }
            .save(&state_path)
            .map_err(|e| format!("could not write {}: {e}", state_path.display()))?;
    } else {
        eprintln!("{stamp}   {failures} step(s) failed — not saving state, will retry next run");
    }

    Ok(if failures == 0 { 0 } else { 1 })
}

fn describe(v4: Option<std::net::IpAddr>, v6: Option<std::net::IpAddr>) -> String {
    let parts: Vec<String> = [v4, v6]
        .into_iter()
        .flatten()
        .map(|i| i.to_string())
        .collect();
    if parts.is_empty() {
        "(none)".into()
    } else {
        parts.join(" ")
    }
}

/// Timestamps without pulling in a date library: cron logs want something
/// sortable and unambiguous, and seconds since the epoch is both.
fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil date from a Unix timestamp (Howard Hinnant's days_from_civil, inverted).
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}
