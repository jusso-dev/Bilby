//! Address classification and the byte-order conversions the Windows
//! connection tables need. Pure, so it's tested on any OS. No lookups: Bilby
//! never resolves names or locates addresses (issue #12, ADR 0004).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// What kind of address an IP is. Only `Public` means "somewhere on the
/// internet".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrClass {
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and `fc00::/7`.
    Private,
    /// `169.254/16`, `fe80::/10`.
    LinkLocal,
    /// Carrier-grade NAT, `100.64/10`.
    Cgnat,
    /// `224/4`, `ff00::/8`.
    Multicast,
    /// `0.0.0.0`, `::`: listening on every address.
    Unspecified,
    /// Anything else.
    Public,
}

/// Classifies an address. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is classified
/// as the IPv4 address it carries.
pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    let [a, b, ..] = ip.octets();
    if ip.is_unspecified() {
        AddrClass::Unspecified
    } else if ip.is_loopback() {
        AddrClass::Loopback
    } else if ip.is_private() {
        AddrClass::Private
    } else if ip.is_link_local() {
        AddrClass::LinkLocal
    } else if a == 100 && (64..128).contains(&b) {
        AddrClass::Cgnat
    } else if ip.is_multicast() || ip.is_broadcast() {
        AddrClass::Multicast
    } else {
        AddrClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    let first = ip.segments()[0];
    if ip.is_unspecified() {
        AddrClass::Unspecified
    } else if ip.is_loopback() {
        AddrClass::Loopback
    } else if first & 0xfe00 == 0xfc00 {
        AddrClass::Private
    } else if first & 0xffc0 == 0xfe80 {
        AddrClass::LinkLocal
    } else if ip.is_multicast() {
        AddrClass::Multicast
    } else {
        AddrClass::Public
    }
}

/// A port from the Windows connection tables: network byte order in the
/// low 16 bits of a `u32`, upper bits undefined.
pub fn port_from_table(dw: u32) -> u16 {
    let low = (dw & 0xFFFF) as u16;
    u16::from_be(low)
}

/// An IPv4 address from the Windows tables: the four octets in network
/// order, as they sit in memory, read as a little-endian `u32` (all
/// Windows targets Bilby supports are little-endian).
pub fn ipv4_from_table(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_network_order_in_the_low_half() {
        // Port 443 is 0x01BB; in network order its bytes are 01 BB, which
        // a little-endian u32 reads as 0xBB01.
        assert_eq!(port_from_table(0x0000_BB01), 443);
        assert_eq!(port_from_table(0x0000_5000), 80);
        assert_eq!(port_from_table(0x0000_8700), 135);
        // Upper bits are ignored.
        assert_eq!(port_from_table(0xDEAD_BB01), 443);
        assert_eq!(port_from_table(0x0000_FFFF), 65535);
        assert_eq!(port_from_table(0), 0);
    }

    #[test]
    fn ipv4_octets_are_in_memory_order() {
        assert_eq!(ipv4_from_table(0x0100_007F), Ipv4Addr::LOCALHOST);
        assert_eq!(ipv4_from_table(0x0101_A8C0), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ipv4_from_table(0), Ipv4Addr::UNSPECIFIED);
    }
}
