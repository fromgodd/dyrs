# dyrs

**Dynamic DNS companion.** Tells you honestly what connection you have, then
keeps DNS pointed at you and runs whatever you want when your address moves.

One static binary, ~2 MB. No daemon, no account, no API key to find out your
own address. Run it from cron; it does its work and exits.

```
$ dyrs doctor

Local interfaces
  ppp0             100.83.14.207                            carrier-grade NAT (RFC 6598)

Public IPv4 (STUN — no account, no API key)
  stun.l.google.com:19302      81.30.2.14       (sent from 100.83.14.207)
  stun.cloudflare.com:3478     81.30.2.14       (sent from 100.83.14.207)

IPv6
  2a0d:5641:22:1::8f on ppp0 — globally routable

----------------------------------------------------------------
Verdict

  Behind CGNAT — confirmed.
  This machine's WAN address is inside 100.64.0.0/10, so the address
  the world sees (81.30.2.14) is shared with other customers and no
  port forwarding you set can reach you.

  You have working IPv6 (2a0d:5641:22:1::8f).
  This is the way out of CGNAT: an AAAA record pointing here is
  reachable from any IPv6-capable client, with no relay, no VPS and
  no third party in the path. Set ipv6 = true in your config.
```

## Why this exists

Dynamic DNS clients are not scarce. What is scarce is a tool that tells you
the truth first.

If your ISP put you behind carrier-grade NAT, **no dynamic DNS client can make
you reachable** — you do not have a public address to point a record at. Most
DDNS tools will cheerfully update your A record with the carrier's shared
address anyway, and you will spend an evening wondering why port forwarding
does nothing. `dyrs doctor` answers that question in one command, before you
configure anything.

And when you *are* behind CGNAT, there is usually a way out that nobody points
at: **IPv6**. ISPs deploy CGNAT precisely because they ran out of IPv4, and
most of them hand you a real, globally routable IPv6 address on the same line.
An AAAA record pointing at it is reachable from any IPv6 client, with no relay,
no VPS, and nothing in the path but you. dyrs treats IPv6 as a first-class
path rather than an afterthought — and finding that address needs no external
service at all, because it is already on your machine.

## What it does

| | |
|---|---|
| `dyrs doctor` | What connection do I have? Can I host on it? |
| `dyrs update` | Update DNS and run hooks, if the address changed |
| `dyrs ip` | Print the current public address, for scripts |

Discovery is **STUN** (RFC 5389) — one UDP packet to servers that need no
account and no key. Several are asked and an address is only believed when two
agree, so one server going dark or lying cannot move your DNS record.

## Runs on

| Platform | Binary | Config | State |
|---|---|---|---|
| Linux (x86_64, arm64, armv7) | static musl, no libc needed | `/etc/dyrs.toml` | `/var/lib/dyrs/state` |
| macOS (Apple Silicon, Intel) | native | `/usr/local/etc/dyrs.toml` | `/usr/local/var/dyrs/state` |
| Windows (x86_64) | `dyrs.exe` | `%ProgramData%\dyrs\dyrs.toml` | `%ProgramData%\dyrs\state` |

`dyrs version` prints the paths for the machine you are on. `DYRS_CONFIG` and
`DYRS_STATE` override them.

The Linux build is a single static file — no glibc version to match, no
runtime to install. Copy it onto a router, a Pi or an Alpine container and it
runs.

## Install

Grab a binary from [Releases](https://github.com/fromgodd/dyrs/releases), or
build it:

```bash
cargo build --release
```

**Linux**

```bash
sudo install -m755 target/release/dyrs /usr/local/bin/dyrs
sudo cp config.example.toml /etc/dyrs.toml
sudo $EDITOR /etc/dyrs.toml
```

```cron
*/5 * * * * /usr/local/bin/dyrs update >> /var/log/dyrs.log 2>&1
```

**macOS**

```bash
sudo install -m755 target/release/dyrs /usr/local/bin/dyrs
sudo mkdir -p /usr/local/etc /usr/local/var/dyrs
sudo cp config.example.toml /usr/local/etc/dyrs.toml
```

cron works, or a launchd agent with `StartInterval 300` if you prefer it the
Apple way.

**Windows** (PowerShell as Administrator)

```powershell
mkdir "$env:ProgramData\dyrs"
copy target\release\dyrs.exe "$env:ProgramData\dyrs\dyrs.exe"
copy config.example.toml "$env:ProgramData\dyrs\dyrs.toml"
schtasks /create /tn dyrs /tr "$env:ProgramData\dyrs\dyrs.exe update" /sc minute /mo 5 /ru SYSTEM
```

Hooks on Windows take `cmd` or `powershell` instead of `/bin/sh`:

```toml
[[on_change]]
command = ["powershell", "-NoProfile", "-Command", "Restart-Service MyService"]
```

Unchanged runs print one quiet line, so a year of that log is still readable.

## Providers

Built in, all with a free tier that does not ask for a payment card:
**DuckDNS**, **deSEC** (non-profit, open source), **dynv6**, **Cloudflare**.

You do not need any of them. `[[on_change]]` runs any command, which means
**RFC 2136** — the actual IETF standard for dynamic DNS updates — works against
any BIND/Knot/PowerDNS including one you run yourself:

```toml
[[on_change]]
name = "rfc2136"
command = ["/bin/sh", "-c", "printf 'server ns.example.com\nupdate delete home.example.com. A\nupdate add home.example.com. 60 A %s\nsend\n' \"$DYRS_IPV4\" | nsupdate -k /etc/dyrs/tsig.key"]
```

Hooks get `DYRS_IPV4`, `DYRS_IPV6` and `DYRS_PREVIOUS` in the environment. The
command is an argument list, never a shell string, so an address that arrived
over the network can never become part of a command line.

## Design

- **No async runtime.** dyrs makes a handful of requests and exits; tokio would
  be a whole scheduler for nothing.
- **Four dependencies.** HTTP+TLS, TOML, serde, interface enumeration. The STUN
  client is ~190 lines of std-only code rather than a fifth.
- **State is only saved when every step succeeded.** If a provider was down,
  the next run tries again instead of believing the record is already correct.
  This is the bug in most hand-rolled DDNS scripts.
- **Nothing runs as a daemon.** cron, launchd and Task Scheduler already
  solved that.
- **One file knows about platforms.** `platform.rs` holds the default paths,
  the interface-naming rules and the scheduling hint. Everything else is plain
  std and portable without trying.

## Honest limits

- If you are behind CGNAT **and** have no IPv6, dyrs cannot make you reachable.
  Nothing can, without something that has a public address relaying for you —
  WireGuard on a cheap VPS, or a tunnel service. That is how networks work, not
  a missing feature. dyrs will say so plainly instead of pretending.
- `doctor` cannot always tell a single NAT from a double one from inside your
  network. When it cannot, it says so and tells you exactly where to look
  instead of guessing. (Router WAN address in `100.64.x.x`–`100.127.x.x`
  means CGNAT.)
- CI builds and tests on Linux, macOS and Windows runners every push. The
  Linux and Windows binaries have been run; the macOS one is built and tested
  in CI but has not been used in anger by the author. BSD is not covered,
  though nothing in the code should object to it.

## License

MIT
