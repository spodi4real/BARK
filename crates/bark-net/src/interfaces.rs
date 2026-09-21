//! Which network addresses this computer has.
//!
//! These become the *local candidates* a peer tries first. Two machines on the
//! same office network should find each other by their LAN addresses and never
//! touch the internet — that is both the lowest-latency path available and one
//! that needs no hole punching at all.
//!
//! First version is IPv4 only. Company LANs and the NATs in front of them are
//! overwhelmingly IPv4; IPv6 candidates are a planned addition.

use std::net::Ipv4Addr;

/// One usable address on a network adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    pub ip: Ipv4Addr,
    /// Adapter name as Windows shows it, e.g. "Ethernet" or "Wi-Fi".
    pub adapter: String,
    pub kind: AdapterKind,
    /// The adapter has a default gateway, which is a good sign it is the one
    /// actually carrying traffic rather than a virtual or host-only network.
    pub has_gateway: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterKind {
    Ethernet,
    WiFi,
    /// VPNs, Hyper-V switches, virtual machine networks and the like. Kept,
    /// because a VPN address is sometimes exactly how two machines can reach
    /// each other, but tried after physical adapters.
    Other,
}

impl LocalAddress {
    /// Lower is tried first.
    fn rank(&self) -> (u8, AdapterKind) {
        (u8::from(!self.has_gateway), self.kind)
    }
}

/// Whether an address is worth offering to a peer.
///
/// Loopback is useless to anyone else; link-local (169.254.x.x) means the
/// adapter never got a real address; unspecified and broadcast addresses are
/// not addresses at all.
pub fn is_candidate_address(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation())
}

/// Lists the IPv4 addresses on adapters that are up, best first.
///
/// Never fails: a machine whose adapters cannot be read simply offers no local
/// candidates and relies on the address the coordination server observes.
pub fn local_ipv4_addresses() -> Vec<LocalAddress> {
    let mut found = platform::enumerate();
    found.retain(|a| is_candidate_address(a.ip));
    found.sort_by_key(|a| a.rank());
    found.dedup_by_key(|a| a.ip);
    found
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD,
        IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    pub fn enumerate() -> Vec<LocalAddress> {
        // Microsoft recommends starting with a 15 KB buffer and growing it if
        // the call reports overflow; adapters can appear between calls, so
        // retry a few times rather than once.
        let mut size: u32 = 15 * 1024;
        for _ in 0..4 {
            // u64 elements keep the buffer 8-byte aligned, which the adapter
            // structures require.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let first = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_INET.0 as u32,
                    GAA_FLAG_SKIP_ANYCAST
                        | GAA_FLAG_SKIP_MULTICAST
                        | GAA_FLAG_SKIP_DNS_SERVER
                        | GAA_FLAG_INCLUDE_GATEWAYS,
                    None,
                    Some(first),
                    &mut size,
                )
            };
            match rc {
                ERROR_SUCCESS => return unsafe { walk(first) },
                ERROR_BUFFER_OVERFLOW => continue,
                other => {
                    tracing::warn!("could not list network adapters (error {other})");
                    return Vec::new();
                }
            }
        }
        tracing::warn!("network adapters kept changing while being listed");
        Vec::new()
    }

    /// Walks the adapter list Windows filled in.
    ///
    /// # Safety
    /// `first` must point at a list produced by a successful
    /// `GetAdaptersAddresses` call whose buffer is still alive.
    unsafe fn walk(first: *mut IP_ADAPTER_ADDRESSES_LH) -> Vec<LocalAddress> {
        let mut out = Vec::new();
        let mut adapter = first;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };
            adapter = a.Next;

            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }

            let kind = match a.IfType {
                IF_TYPE_ETHERNET_CSMACD => AdapterKind::Ethernet,
                IF_TYPE_IEEE80211 => AdapterKind::WiFi,
                _ => AdapterKind::Other,
            };
            let name = if a.FriendlyName.is_null() {
                String::new()
            } else {
                unsafe { a.FriendlyName.to_string() }.unwrap_or_default()
            };
            let has_gateway = !a.FirstGatewayAddress.is_null();

            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                let u = unsafe { &*unicast };
                unicast = u.Next;

                let sa = u.Address.lpSockaddr;
                if sa.is_null() || (u.Address.iSockaddrLength as usize) < std::mem::size_of::<SOCKADDR_IN>() {
                    continue;
                }
                if unsafe { (*sa).sa_family } != AF_INET {
                    continue;
                }
                let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                // S_addr is stored in network byte order.
                let raw = unsafe { sin.sin_addr.S_un.S_addr };
                let ip = Ipv4Addr::from(u32::from_be(raw));

                out.push(LocalAddress { ip, adapter: name.clone(), kind, has_gateway });
            }
        }
        out
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn enumerate() -> Vec<LocalAddress> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn useless_addresses_are_not_offered() {
        assert!(!is_candidate_address(Ipv4Addr::LOCALHOST));
        assert!(!is_candidate_address(Ipv4Addr::new(169, 254, 10, 20)), "link-local");
        assert!(!is_candidate_address(Ipv4Addr::UNSPECIFIED));
        assert!(!is_candidate_address(Ipv4Addr::BROADCAST));
        assert!(!is_candidate_address(Ipv4Addr::new(224, 0, 0, 1)), "multicast");

        assert!(is_candidate_address(Ipv4Addr::new(192, 168, 1, 20)));
        assert!(is_candidate_address(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(is_candidate_address(Ipv4Addr::new(172, 16, 4, 1)));
        assert!(is_candidate_address(Ipv4Addr::new(100, 64, 1, 1)), "CGNAT/VPN ranges are kept");
    }

    #[test]
    fn physical_adapters_with_a_gateway_come_first() {
        let mut v = [
            LocalAddress { ip: Ipv4Addr::new(172, 20, 0, 1), adapter: "vEthernet".into(), kind: AdapterKind::Other, has_gateway: false },
            LocalAddress { ip: Ipv4Addr::new(192, 168, 1, 20), adapter: "Wi-Fi".into(), kind: AdapterKind::WiFi, has_gateway: true },
            LocalAddress { ip: Ipv4Addr::new(10, 0, 0, 7), adapter: "Ethernet".into(), kind: AdapterKind::Ethernet, has_gateway: true },
        ];
        v.sort_by_key(|a| a.rank());
        assert_eq!(v[0].adapter, "Ethernet");
        assert_eq!(v[1].adapter, "Wi-Fi");
        assert_eq!(v[2].adapter, "vEthernet");
    }

    #[cfg(windows)]
    #[test]
    fn this_machine_reports_at_least_one_real_address() {
        // The dev laptop is on a network. If this ever fails on a machine that
        // is online, adapter enumeration is broken.
        let found = local_ipv4_addresses();
        for a in &found {
            assert!(is_candidate_address(a.ip), "{a:?} should have been filtered");
        }
        assert!(!found.is_empty(), "no usable IPv4 address found on this machine");
    }
}
