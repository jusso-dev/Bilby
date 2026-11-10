//! TCP and UDP tables with owning process ids, from the IP Helper API.
//! Read-only; no lookups of any kind (issue #12, ADR 0004).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use bilby_core::model::CheckStatus;
use bilby_core::net::{ipv4_from_table, port_from_table};
use bilby_core::snapshot::{ConnectionFact, NetworkFacts, Proto, TcpState};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_LISTEN,
    MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// The tables can grow between the size call and the read; retry a few
/// times rather than loop forever.
const ATTEMPTS: usize = 5;

/// Reads one table into an aligned buffer, retrying on
/// `ERROR_INSUFFICIENT_BUFFER`. On failure, the Win32 error code.
fn read_table(
    call: impl Fn(Option<*mut core::ffi::c_void>, &mut u32) -> u32,
) -> Result<Vec<u64>, u32> {
    let mut size = 0u32;
    let _ = call(None, &mut size);
    let mut last = ERROR_INSUFFICIENT_BUFFER.0;
    for _ in 0..ATTEMPTS {
        let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
        match call(Some(buf.as_mut_ptr().cast()), &mut size) {
            rc if rc == NO_ERROR.0 => return Ok(buf),
            rc if rc == ERROR_INSUFFICIENT_BUFFER.0 => last = rc,
            rc => return Err(rc),
        }
    }
    Err(last)
}

/// What the network collector found and how reading went.
pub struct Collected {
    /// The rows, if any table could be read.
    pub facts: Option<NetworkFacts>,
    /// `Ran` if every table read; `Failed` naming the tables that didn't.
    pub status: CheckStatus,
}

/// The rows of a table that starts with a `u32` count followed by rows.
/// Every MIB `*TABLE_OWNER_PID` struct has that shape, and the rows are
/// aligned to 4 bytes after the count.
fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    let bytes = buf.len() * 8;
    if bytes < 4 {
        return Vec::new();
    }
    // SAFETY: the buffer was filled by GetExtended*Table, which writes a u32
    // count at the start; `buf` is 8-byte aligned and at least 4 bytes.
    let count = unsafe { *buf.as_ptr().cast::<u32>() } as usize;
    let offset = std::mem::align_of::<T>().max(4);
    let available = bytes.saturating_sub(offset) / std::mem::size_of::<T>();
    let n = count.min(available);
    // SAFETY: `n` rows of T fit after the count within the buffer (checked
    // above), and the offset keeps them aligned for T.
    let first = unsafe { buf.as_ptr().cast::<u8>().add(offset).cast::<T>() };
    // SAFETY: as above; the rows are plain data copied out.
    unsafe { std::slice::from_raw_parts(first, n) }.to_vec()
}

fn tcp_state(dw: u32) -> TcpState {
    let s = i32::try_from(dw).unwrap_or(-1);
    if s == MIB_TCP_STATE_LISTEN.0 {
        TcpState::Listen
    } else if s == MIB_TCP_STATE_ESTAB.0 {
        TcpState::Established
    } else {
        TcpState::Other
    }
}

fn v6(addr: [u8; 16], port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port_from_table(port))
}

fn v4(addr: u32, port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ipv4_from_table(addr)), port_from_table(port))
}

/// Every TCP and UDP row, IPv4 and IPv6, keeping only rows owned by a pid
/// in `known_pids` (the process snapshot taken just before).
pub fn collect<S: std::hash::BuildHasher>(known_pids: &HashSet<u32, S>) -> Collected {
    let tcp = |family: u32| {
        read_table(|buf, size| {
            // SAFETY: `buf` is None (size query) or a buffer of `size` bytes
            // that outlives the call; no ordering, owner-pid table class.
            unsafe { GetExtendedTcpTable(buf, size, false, family, TCP_TABLE_OWNER_PID_ALL, 0) }
        })
    };
    let udp = |family: u32| {
        read_table(|buf, size| {
            // SAFETY: as above, for the UDP table.
            unsafe { GetExtendedUdpTable(buf, size, false, family, UDP_TABLE_OWNER_PID, 0) }
        })
    };
    let v4fam = u32::from(AF_INET.0);
    let v6fam = u32::from(AF_INET6.0);
    let mut out = Vec::new();
    let mut any = false;
    let mut failed: Vec<String> = Vec::new();
    let mut note = |name: &str, r: &Result<Vec<u64>, u32>| {
        if let Err(code) = r {
            failed.push(format!("{name} table: error {code}"));
        }
    };
    let (t4, t6, u4, u6) = (tcp(v4fam), tcp(v6fam), udp(v4fam), udp(v6fam));
    note("TCP IPv4", &t4);
    note("TCP IPv6", &t6);
    note("UDP IPv4", &u4);
    note("UDP IPv6", &u6);
    if let Ok(buf) = t4 {
        any = true;
        for r in rows::<MIB_TCPROW_OWNER_PID>(&buf) {
            let state = tcp_state(r.dwState);
            out.push(ConnectionFact {
                proto: Proto::Tcp,
                local: v4(r.dwLocalAddr, r.dwLocalPort),
                remote: (state != TcpState::Listen).then(|| v4(r.dwRemoteAddr, r.dwRemotePort)),
                state: Some(state),
                pid: r.dwOwningPid,
            });
        }
    }
    if let Ok(buf) = t6 {
        any = true;
        for r in rows::<MIB_TCP6ROW_OWNER_PID>(&buf) {
            let state = tcp_state(r.dwState);
            out.push(ConnectionFact {
                proto: Proto::Tcp,
                local: v6(r.ucLocalAddr, r.dwLocalPort),
                remote: (state != TcpState::Listen).then(|| v6(r.ucRemoteAddr, r.dwRemotePort)),
                state: Some(state),
                pid: r.dwOwningPid,
            });
        }
    }
    if let Ok(buf) = u4 {
        any = true;
        for r in rows::<MIB_UDPROW_OWNER_PID>(&buf) {
            out.push(ConnectionFact {
                proto: Proto::Udp,
                local: v4(r.dwLocalAddr, r.dwLocalPort),
                remote: None,
                state: None,
                pid: r.dwOwningPid,
            });
        }
    }
    if let Ok(buf) = u6 {
        any = true;
        for r in rows::<MIB_UDP6ROW_OWNER_PID>(&buf) {
            out.push(ConnectionFact {
                proto: Proto::Udp,
                local: v6(r.ucLocalAddr, r.dwLocalPort),
                remote: None,
                state: None,
                pid: r.dwOwningPid,
            });
        }
    }
    // Rows whose process has exited, or isn't in the snapshot, can't be
    // tied to a program, so they're dropped.
    out.retain(|c| known_pids.contains(&c.pid));
    Collected {
        facts: any.then_some(NetworkFacts { connections: out }),
        // A missing table is a gap in what was checked, so say so rather
        // than look complete.
        status: if failed.is_empty() {
            CheckStatus::Ran
        } else {
            CheckStatus::Failed(failed.join("; "))
        },
    }
}
