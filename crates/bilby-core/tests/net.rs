//! Address classification cases. Runs on any OS.

use std::net::IpAddr;

use bilby_core::net::{AddrClass, classify};

#[test]
fn classification_table() {
    use AddrClass::{Cgnat, LinkLocal, Loopback, Multicast, Private, Public, Unspecified};
    let cases = [
        ("127.0.0.1", Loopback),
        ("127.255.0.9", Loopback),
        ("::1", Loopback),
        ("10.0.0.5", Private),
        ("172.16.0.1", Private),
        ("172.31.255.255", Private),
        ("192.168.1.10", Private),
        ("fc00::1", Private),
        ("fd12:3456::1", Private),
        ("169.254.10.20", LinkLocal),
        ("fe80::1", LinkLocal),
        ("100.64.0.1", Cgnat),
        ("100.127.255.255", Cgnat),
        ("224.0.0.251", Multicast),
        ("239.255.255.250", Multicast),
        ("255.255.255.255", Multicast),
        ("ff02::fb", Multicast),
        ("0.0.0.0", Unspecified),
        ("::", Unspecified),
        ("8.8.8.8", Public),
        ("1.1.1.1", Public),
        ("172.32.0.1", Public),
        ("172.15.255.255", Public),
        ("100.63.255.255", Public),
        ("100.128.0.0", Public),
        ("2606:4700::1111", Public),
        // IPv4-mapped IPv6 is classified as the IPv4 address it carries.
        ("::ffff:192.168.1.1", Private),
        ("::ffff:127.0.0.1", Loopback),
        ("::ffff:8.8.8.8", Public),
    ];
    for (ip, want) in cases {
        let addr: IpAddr = ip.parse().expect("valid address");
        assert_eq!(classify(addr), want, "{ip}");
    }
}
