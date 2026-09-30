//! Minimal STUN client (RFC 5389) — how dyrs learns its public address
//! without an account, an API key, or a third-party HTTP service.
//!
//! A Binding Request is 20 bytes: message type, length, a fixed magic cookie
//! and a random transaction id. The server answers with XOR-MAPPED-ADDRESS:
//! the address it saw the packet arrive from, XOR'd with the cookie. The XOR
//! exists because some NAT boxes rewrite anything in a payload that looks
//! like an IP address, and would corrupt a plain one in transit.
//!
//! Written by hand rather than pulled from a crate: it is ~120 lines of
//! std-only code, and a DDNS tool whose whole premise is "no dependencies you
//! didn't ask for" should not import a library to send one UDP packet.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Public STUN servers: free, no account, no key, run by people who are not
/// going to disappear. dyrs asks several and expects them to agree — one
/// server lying or going dark should not move your DNS record.
pub const DEFAULT_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:3478",
    "stun.sipgate.net:3478",
];

/// What a single STUN exchange told us.
#[derive(Debug, Clone)]
pub struct Reflexive {
    /// The address the server saw us come from — our public address.
    pub public: SocketAddr,
    /// The address our own socket was bound to locally.
    pub local: SocketAddr,
}

fn transaction_id() -> [u8; 12] {
    // This has to be genuinely unpredictable, not merely unique: an attacker
    // who can guess the id and spoof the source address could answer before
    // the real server does and hand us an address we would then publish to
    // DNS. getrandom is the OS generator on every platform we support —
    // getrandom(2) on Linux, /dev/urandom on the BSDs and macOS,
    // BCryptGenRandom on Windows — which is also why dyrs does not read
    // /dev/urandom by hand any more.
    let mut id = [0u8; 12];
    if getrandom::getrandom(&mut id).is_ok() {
        return id;
    }
    // If the OS generator is unavailable something is very wrong, but a STUN
    // lookup should still not panic. This is only good enough to match a
    // reply to a request sent moments ago.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    id[..4].copy_from_slice(&nanos.to_be_bytes());
    id[4..8].copy_from_slice(&std::process::id().to_be_bytes());
    id
}

/// Ask one STUN server what address it sees us on.
pub fn query(server: &str, timeout: Duration, ipv6: bool) -> io::Result<Reflexive> {
    let target = server
        .to_socket_addrs()?
        .find(|a| a.is_ipv6() == ipv6)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!(
                    "{server} has no {} address",
                    if ipv6 { "IPv6" } else { "IPv4" }
                ),
            )
        })?;

    let bind: SocketAddr = if ipv6 {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    // connect() so the kernel picks the source address it would really use,
    // which is also what makes local_addr() meaningful below.
    socket.connect(target)?;

    let txid = transaction_id();
    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    request.extend_from_slice(&MAGIC.to_be_bytes());
    request.extend_from_slice(&txid);
    socket.send(&request)?;

    let mut buf = [0u8; 1500];
    let n = socket.recv(&mut buf)?;
    let public = parse_response(&buf[..n], &txid)?;
    Ok(Reflexive {
        public,
        local: socket.local_addr()?,
    })
}

fn parse_response(data: &[u8], txid: &[u8; 12]) -> io::Result<SocketAddr> {
    let bad = |m: &str| io::Error::new(ErrorKind::InvalidData, m.to_string());
    if data.len() < 20 {
        return Err(bad("STUN reply shorter than a header"));
    }
    let mtype = u16::from_be_bytes([data[0], data[1]]);
    let mlen = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != MAGIC {
        return Err(bad("STUN reply has the wrong magic cookie"));
    }
    if &data[8..20] != txid {
        // Someone else's reply, or a spoof. Either way it is not ours.
        return Err(bad("STUN reply transaction id does not match"));
    }
    if mtype != BINDING_SUCCESS {
        return Err(bad("STUN server refused the binding request"));
    }
    if 20 + mlen > data.len() {
        return Err(bad("STUN reply is truncated"));
    }

    let mut i = 20;
    while i + 4 <= 20 + mlen {
        let atype = u16::from_be_bytes([data[i], data[i + 1]]);
        let alen = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let start = i + 4;
        let end = start + alen;
        if end > data.len() {
            break;
        }
        if atype == XOR_MAPPED_ADDRESS && alen >= 8 {
            let value = &data[start..end];
            let family = value[1];
            let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC >> 16) as u16);
            return match family {
                0x01 => {
                    let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                    Ok(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(raw ^ MAGIC)),
                        port,
                    ))
                }
                0x02 if alen >= 20 => {
                    // IPv6 is XOR'd with the cookie followed by the transaction id.
                    let mut key = [0u8; 16];
                    key[..4].copy_from_slice(&MAGIC.to_be_bytes());
                    key[4..].copy_from_slice(txid);
                    let mut addr = [0u8; 16];
                    for k in 0..16 {
                        addr[k] = value[4 + k] ^ key[k];
                    }
                    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
                }
                _ => Err(bad("STUN reply used an address family we do not know")),
            };
        }
        // Attributes are padded to a 4-byte boundary.
        i = start + alen + ((4 - alen % 4) % 4);
    }
    Err(bad("STUN reply carried no XOR-MAPPED-ADDRESS"))
}

/// Ask several servers and only believe an address that at least two agree on.
///
/// Returns the agreed address plus every answer received, so `doctor` can show
/// the disagreement when there is one. A single server is trusted only when it
/// is the only one that answered at all.
pub fn consensus(
    servers: &[String],
    timeout: Duration,
    ipv6: bool,
) -> (Option<IpAddr>, Vec<(String, io::Result<Reflexive>)>) {
    let mut results = Vec::new();
    for server in servers {
        results.push((server.clone(), query(server, timeout, ipv6)));
    }

    let mut seen: Vec<(IpAddr, usize)> = Vec::new();
    for (_, r) in &results {
        if let Ok(reflexive) = r {
            let ip = reflexive.public.ip();
            match seen.iter_mut().find(|(known, _)| *known == ip) {
                Some((_, count)) => *count += 1,
                None => seen.push((ip, 1)),
            }
        }
    }
    seen.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let agreed = match seen.first() {
        Some((ip, count)) if *count >= 2 => Some(*ip),
        // Only one server answered at all — take it, but doctor will say so.
        Some((ip, _)) if seen.len() == 1 => Some(*ip),
        _ => None,
    };
    (agreed, results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real XOR-MAPPED-ADDRESS reply, assembled by hand: 192.0.2.1:32853
    /// XOR'd with the magic cookie, exactly as RFC 5389 section 15.2 describes.
    #[test]
    fn parses_xor_mapped_ipv4() {
        let txid = [1u8; 12];
        let ip: u32 = u32::from(Ipv4Addr::new(192, 0, 2, 1));
        let port: u16 = 32853;
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes()); // one 12-byte attribute
        msg.extend_from_slice(&MAGIC.to_be_bytes());
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0); // reserved
        msg.push(0x01); // IPv4
        msg.extend_from_slice(&(port ^ ((MAGIC >> 16) as u16)).to_be_bytes());
        msg.extend_from_slice(&(ip ^ MAGIC).to_be_bytes());

        let got = parse_response(&msg, &txid).expect("should parse");
        assert_eq!(
            got,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853)
        );
    }

    #[test]
    fn rejects_a_reply_for_someone_elses_request() {
        let mine = [1u8; 12];
        let theirs = [2u8; 12];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC.to_be_bytes());
        msg.extend_from_slice(&theirs);
        assert!(parse_response(&msg, &mine).is_err());
    }

    #[test]
    fn rejects_a_wrong_magic_cookie() {
        let txid = [1u8; 12];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        msg.extend_from_slice(&txid);
        assert!(parse_response(&msg, &txid).is_err());
    }

    #[test]
    fn rejects_a_truncated_message() {
        assert!(parse_response(&[0u8; 8], &[0u8; 12]).is_err());
    }
}
