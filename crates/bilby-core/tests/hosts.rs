//! Hosts file decoding and parsing. Runs on any OS.

use bilby_core::hosts::{decode, is_blackhole, parse};

#[test]
fn parses_comments_tabs_ipv6_and_many_names() {
    let text = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n\
                #\r\n\
                \t127.0.0.1\tlocalhost   # loopback\r\n\
                ::1\tlocalhost ip6-localhost\r\n\
                \r\n\
                10.0.0.5 nas.local nas printer.local\r\n\
                fe80::1%3 router.local\r\n\
                not-an-ip ignored.example\r\n\
                192.168.1.1\r\n\
                0.0.0.0 ads.example.test #ad\r\n";
    let e = parse(text);
    let summary: Vec<(usize, &str, Vec<&str>)> = e
        .iter()
        .map(|x| {
            (
                x.line,
                x.ip.as_str(),
                x.names.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (3, "127.0.0.1", vec!["localhost"]),
            (4, "::1", vec!["localhost", "ip6-localhost"]),
            (6, "10.0.0.5", vec!["nas.local", "nas", "printer.local"]),
            (7, "fe80::1%3", vec!["router.local"]),
            (10, "0.0.0.0", vec!["ads.example.test"]),
        ]
    );
}

#[test]
fn names_are_lower_case() {
    let e = parse("127.0.0.1 WWW.CommBank.com.au");
    assert_eq!(e[0].names, ["www.commbank.com.au"]);
}

#[test]
fn decodes_bom_and_utf16() {
    let text = "127.0.0.1 a.test\r\n";
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(text.as_bytes());
    assert_eq!(decode(&bom), text);

    let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut le_bom = vec![0xFF, 0xFE];
    le_bom.extend_from_slice(&le);
    assert_eq!(decode(&le_bom), text);
    // Notepad's "Unicode" without a mark: detected from the zero bytes.
    assert_eq!(decode(&le), text);

    let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let mut be_bom = vec![0xFE, 0xFF];
    be_bom.extend_from_slice(&be);
    assert_eq!(decode(&be_bom), text);

    assert_eq!(decode(text.as_bytes()), text);
    assert_eq!(parse(&decode(&le_bom))[0].names, ["a.test"]);
}

#[test]
fn blackhole_addresses() {
    for ip in ["0.0.0.0", "127.0.0.1", "::1", "::"] {
        assert!(is_blackhole(ip), "{ip}");
    }
    for ip in ["10.0.0.1", "203.0.113.9", "127.0.0.2"] {
        assert!(!is_blackhole(ip), "{ip}");
    }
}
