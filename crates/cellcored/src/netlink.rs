//! Pure-Rust Linux `AF_NETLINK` (`NETLINK_ROUTE`) link, address, and route
//! management with zero subprocess forks (`ip`/`ifconfig` are never spawned).

use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Mutex,
};

use serde::Serialize;

pub const TABLE_MAIN: u32 = 254;
pub const TABLE_LOCAL: u32 = 255;
pub const TABLE_WARP: u32 = crate::vpn::policy::DEFAULT_TABLE;

const NLMSG_ERR_TYPE: u16 = 2;
const NLMSG_DONE_TYPE: u16 = 3;

const NLM_F_REQUEST_BIT: u16 = 0x0001;
const NLM_F_MULTI_BIT: u16 = 0x0002;
const NLM_F_ACK_BIT: u16 = 0x0004;
const NLM_F_ROOT_BIT: u16 = 0x0100;
const NLM_F_MATCH_BIT: u16 = 0x0200;
const NLM_F_REPLACE_BIT: u16 = 0x0100;
const NLM_F_EXCL_BIT: u16 = 0x0200;
const NLM_F_CREATE_BIT: u16 = 0x0400;
const NLM_F_DUMP_BITS: u16 = NLM_F_REQUEST_BIT | NLM_F_ROOT_BIT | NLM_F_MATCH_BIT;
const NLA_F_NESTED_BIT: u16 = 0x8000;

const RTM_NEWLINK_OP: u16 = 16;
const RTM_DELLINK_OP: u16 = 17;
const RTM_GETLINK_OP: u16 = 18;
const RTM_NEWADDR_OP: u16 = 20;
const RTM_DELADDR_OP: u16 = 21;
const RTM_GETADDR_OP: u16 = 22;
const RTM_NEWROUTE_OP: u16 = 24;
const RTM_DELROUTE_OP: u16 = 25;
const RTM_GETROUTE_OP: u16 = 26;

const IFLA_IFNAME_ATTR: u16 = 3;
const IFLA_MTU_ATTR: u16 = 4;
const IFLA_LINK_ATTR: u16 = 5;
const IFLA_MASTER_ATTR: u16 = 10;
const IFLA_LINKINFO_ATTR: u16 = 18;
const IFLA_INFO_KIND_ATTR: u16 = 1;
const IFLA_INFO_DATA_ATTR: u16 = 2;
const IFLA_RMNET_MUX_ID_ATTR: u16 = 1;

const IFA_ADDRESS_ATTR: u16 = 1;
const IFA_LOCAL_ATTR: u16 = 2;

const RTA_DST_ATTR: u16 = 1;
const RTA_OIF_ATTR: u16 = 4;
const RTA_GATEWAY_ATTR: u16 = 5;
const RTA_PRIORITY_ATTR: u16 = 6;
const RTA_METRICS_ATTR: u16 = 8;
const RTA_TABLE_ATTR: u16 = 15;

const RTAX_LOCK_ATTR: u16 = 1;
const RTAX_MTU_ATTR: u16 = 2;
const RTAX_LOCK_MTU_BIT: u32 = 1 << 2;

const RTPROT_BOOT_VAL: u8 = 3;
const RTPROT_STATIC_VAL: u8 = 4;
const RT_SCOPE_UNIVERSE_VAL: u8 = 0;
const RT_SCOPE_LINK_VAL: u8 = 253;
const RTN_UNICAST_VAL: u8 = 1;
const RT_TABLE_COMPAT_VAL: u8 = 252;

const IFF_UP_BIT: u32 = 1 << 0;
const IFF_RUNNING_BIT: u32 = 1 << 6;
const IFF_LOWER_UP_BIT: u32 = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlinkLink {
    pub ifindex: i32,
    pub name: String,
    pub up: bool,
    pub lower_up: bool,
    pub mtu: u32,
    pub kind: Option<String>,
    pub rmnet_mux_id: Option<u16>,
    pub master_index: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlinkAddr {
    pub ifindex: i32,
    pub family: u8,
    pub address: String,
    pub prefix_len: u8,
    pub scope: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlinkRoute {
    pub family: u8,
    pub dst: String,
    pub dst_len: u8,
    pub gateway: Option<String>,
    pub oif: Option<i32>,
    pub table: u32,
    pub priority: Option<u32>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttrHdr {
    rta_len: u16,
    rta_type: u16,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Hard safety guard: native data-plane mutations only ever touch `rmnet_data*` or `wwan*`
/// interfaces, NEVER `lo`, `eth0`, `br-lan`, or `rmnet_ipa0`.
pub fn validate_managed_iface(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 15 {
        return Err(format!("invalid interface name {name:?}"));
    }
    if !n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) {
        return Err(format!("invalid interface characters in {name:?}"));
    }
    if matches!(n, "lo" | "eth0" | "br-lan" | "rmnet_ipa0") {
        return Err(format!("refusing to mutate protected interface {n}"));
    }
    if !n.starts_with("rmnet_data") && !n.starts_with("wwan") {
        return Err(format!(
            "interface {n} is not a cellular data interface (expected rmnet_data* or wwan*)"
        ));
    }
    Ok(())
}

/// Hard safety guard: never touch local (`255`), unspec (`0`), or WARP routing table (`51820`).
pub fn validate_managed_table(table: u32) -> Result<(), String> {
    if table == 0 || table == TABLE_LOCAL || table == TABLE_WARP {
        return Err(format!("refusing protected routing table {table}"));
    }
    Ok(())
}

/// Allowlist for IPPT passthrough downstream `/32` host routes: `br-lan` or `br-lan<digits>`.
pub fn validate_passthrough_bridge(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 15 {
        return Err(format!("invalid passthrough bridge {name:?}"));
    }
    if let Some(rest) = n.strip_prefix("br-lan")
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(());
    }
    Err(format!("refusing passthrough route on non-LAN bridge {n}"))
}

pub fn resolve_rmnet_link<'a>(
    links: &'a [NetlinkLink],
    iface: &str,
    mux_id: u8,
) -> Option<&'a NetlinkLink> {
    links
        .iter()
        .find(|l| l.name == iface)
        .or_else(|| {
            (mux_id > 0)
                .then(|| links.iter().find(|l| l.rmnet_mux_id == Some(u16::from(mux_id))))
                .flatten()
        })
}

fn push_attr_bytes(buf: &mut Vec<u8>, rta_type: u16, val: &[u8]) {
    let rta_len = (mem::size_of::<RtAttrHdr>() + val.len()) as u16;
    let hdr = RtAttrHdr { rta_len, rta_type };
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(&hdr as *const RtAttrHdr as *const u8, mem::size_of::<RtAttrHdr>())
    };
    buf.extend_from_slice(hdr_bytes);
    buf.extend_from_slice(val);
    let aligned = align4(buf.len());
    buf.resize(aligned, 0);
}

pub(crate) fn encode_metrics_mtu(mtu: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity((mem::size_of::<RtAttrHdr>() + 4) * 2);
    push_attr_bytes(&mut out, RTAX_LOCK_ATTR, &RTAX_LOCK_MTU_BIT.to_ne_bytes());
    push_attr_bytes(&mut out, RTAX_MTU_ATTR, &mtu.to_ne_bytes());
    out
}

pub(crate) struct NlBuilder {
    buf: Vec<u8>,
}

impl NlBuilder {
    pub fn new(nlmsg_type: u16, nlmsg_flags: u16, seq: u32, payload: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(64);
        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type,
            nlmsg_flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const NlMsgHdr as *const u8, mem::size_of::<NlMsgHdr>())
        };
        buf.extend_from_slice(hdr_bytes);
        buf.extend_from_slice(payload);
        let aligned = align4(buf.len());
        buf.resize(aligned, 0);
        Self { buf }
    }

    pub fn push_attr(&mut self, rta_type: u16, val: &[u8]) -> &mut Self {
        push_attr_bytes(&mut self.buf, rta_type, val);
        self
    }

    pub fn push_u32(&mut self, rta_type: u16, v: u32) -> &mut Self {
        self.push_attr(rta_type, &v.to_ne_bytes())
    }

    pub fn push_i32(&mut self, rta_type: u16, v: i32) -> &mut Self {
        self.push_attr(rta_type, &v.to_ne_bytes())
    }

    pub fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn parse_attrs(mut slice: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let hdr_len = mem::size_of::<RtAttrHdr>();
    while slice.len() >= hdr_len {
        let rta_len = u16::from_ne_bytes([slice[0], slice[1]]) as usize;
        let rta_type = u16::from_ne_bytes([slice[2], slice[3]]) & 0x7FFF;
        if rta_len < hdr_len || rta_len > slice.len() {
            break;
        }
        out.push((rta_type, &slice[hdr_len..rta_len]));
        let step = align4(rta_len);
        if step >= slice.len() {
            break;
        }
        slice = &slice[step..];
    }
    out
}

fn open_netlink_route() -> Result<OwnedFd, String> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(format!("socket(AF_NETLINK): {}", io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("bind(AF_NETLINK): {}", io::Error::last_os_error()));
    }
    Ok(fd)
}

type NlFrames = Vec<(u16, Vec<u8>)>;
type NlErrno = (Option<i32>, String);

fn send_recv_netlink(req: &[u8]) -> Result<NlFrames, String> {
    send_recv_netlink_errno(req).map_err(|(_, msg)| msg)
}

struct NetlinkSocketPool {
    fd: Option<OwnedFd>,
    buf: Vec<u8>,
}

static NL_POOL: Mutex<NetlinkSocketPool> = Mutex::new(NetlinkSocketPool {
    fd: None,
    buf: Vec::new(),
});

const NL_RECV_BUF_LEN: usize = 32768;

fn send_recv_netlink_once(
    raw_fd: libc::c_int,
    buf: &mut [u8],
    req: &[u8],
) -> Result<NlFrames, (bool /* transport_broken */, NlErrno)> {
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            raw_fd,
            req.as_ptr() as *const libc::c_void,
            req.len(),
            0,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        let e = io::Error::last_os_error();
        return Err((true, (e.raw_os_error(), format!("sendto(AF_NETLINK): {e}"))));
    }

    let hdr_len = mem::size_of::<NlMsgHdr>();
    let mut frames = Vec::new();
    loop {
        let n = unsafe {
            libc::recv(
                raw_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err((true, (e.raw_os_error(), format!("recv(AF_NETLINK): {e}"))));
        }
        if n == 0 {
            break;
        }
        let mut slice = &buf[..n as usize];
        let mut saw_done = false;
        let mut saw_multi = false;
        while slice.len() >= hdr_len {
            let nlmsg_len = u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
            let nlmsg_type = u16::from_ne_bytes([slice[4], slice[5]]);
            let nlmsg_flags = u16::from_ne_bytes([slice[6], slice[7]]);
            if nlmsg_len < hdr_len || nlmsg_len > slice.len() {
                return Err((true, (None, "malformed netlink message length".into())));
            }
            if (nlmsg_flags & NLM_F_MULTI_BIT) != 0 {
                saw_multi = true;
            }
            let payload = &slice[hdr_len..nlmsg_len];
            match nlmsg_type {
                NLMSG_DONE_TYPE => {
                    saw_done = true;
                    break;
                }
                NLMSG_ERR_TYPE => {
                    if payload.len() < 4 {
                        return Err((true, (None, "truncated NLMSG_ERROR".into())));
                    }
                    let err_code = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    if err_code == 0 {
                        saw_done = true;
                        break;
                    }
                    let raw = -err_code;
                    return Err((false, (Some(raw), io::Error::from_raw_os_error(raw).to_string())));
                }
                other => {
                    frames.push((other, payload.to_vec()));
                }
            }
            let step = align4(nlmsg_len);
            if step >= slice.len() {
                break;
            }
            slice = &slice[step..];
        }
        if saw_done || !saw_multi {
            break;
        }
    }
    Ok(frames)
}

fn send_recv_netlink_errno(req: &[u8]) -> Result<NlFrames, NlErrno> {
    let mut pool = NL_POOL.lock().unwrap_or_else(|e| e.into_inner());
    if pool.buf.len() < NL_RECV_BUF_LEN {
        pool.buf.resize(NL_RECV_BUF_LEN, 0);
    }
    for attempt in 0..2 {
        let reopened = pool.fd.is_none();
        if reopened {
            let fd = open_netlink_route().map_err(|e| (None, e))?;
            pool.fd = Some(fd);
        }
        let raw_fd = pool.fd.as_ref().expect("netlink fd initialized").as_raw_fd();
        match send_recv_netlink_once(raw_fd, &mut pool.buf, req) {
            Ok(frames) => return Ok(frames),
            Err((true, err)) => {
                // Socket may be stale/broken (EBADF, ENOBUFS, partial stream); drop and
                // transparently recreate once if this came from a reused socket.
                pool.fd = None;
                if attempt == 0 && !reopened {
                    continue;
                }
                return Err(err);
            }
            Err((false, err)) => return Err(err),
        }
    }
    unreachable!()
}

pub(crate) fn parse_link_payload(payload: &[u8]) -> Option<NetlinkLink> {
    let hdr_len = mem::size_of::<IfInfoMsg>();
    if payload.len() < hdr_len {
        return None;
    }
    let ifindex = i32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let flags = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let attrs = parse_attrs(&payload[hdr_len..]);

    let mut name = String::new();
    let mut mtu = 0u32;
    let mut master_index = None;
    let mut kind = None;
    let mut rmnet_mux_id = None;

    for (t, v) in attrs {
        match t {
            IFLA_IFNAME_ATTR => {
                name = String::from_utf8_lossy(v).trim_end_matches('\0').to_string();
            }
            IFLA_MTU_ATTR if v.len() >= 4 => {
                mtu = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]);
            }
            IFLA_MASTER_ATTR if v.len() >= 4 => {
                master_index = Some(i32::from_ne_bytes([v[0], v[1], v[2], v[3]]));
            }
            IFLA_LINKINFO_ATTR => {
                for (it, iv) in parse_attrs(v) {
                    if it == IFLA_INFO_KIND_ATTR {
                        let k = String::from_utf8_lossy(iv).trim_end_matches('\0').to_string();
                        if !k.is_empty() {
                            kind = Some(k);
                        }
                    } else if it == IFLA_INFO_DATA_ATTR && kind.as_deref() == Some("rmnet") {
                        for (dt, dv) in parse_attrs(iv) {
                            if dt == IFLA_RMNET_MUX_ID_ATTR && dv.len() >= 2 {
                                rmnet_mux_id = Some(u16::from_ne_bytes([dv[0], dv[1]]));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(NetlinkLink {
        ifindex,
        name,
        up: (flags & IFF_UP_BIT) != 0,
        lower_up: (flags & IFF_LOWER_UP_BIT) != 0 || (flags & IFF_RUNNING_BIT) != 0,
        mtu,
        kind,
        rmnet_mux_id,
        master_index,
    })
}

pub(crate) fn parse_addr_payload(payload: &[u8]) -> Option<NetlinkAddr> {
    let hdr_len = mem::size_of::<IfAddrMsg>();
    if payload.len() < hdr_len {
        return None;
    }
    let family = payload[0];
    let prefix_len = payload[1];
    let scope = payload[3];
    let ifindex = i32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let attrs = parse_attrs(&payload[hdr_len..]);

    let raw = attrs
        .iter()
        .find(|(t, _)| *t == IFA_LOCAL_ATTR)
        .or_else(|| attrs.iter().find(|(t, _)| *t == IFA_ADDRESS_ATTR))
        .map(|(_, v)| *v)?;
    let addr: IpAddr = match family as i32 {
        libc::AF_INET if raw.len() >= 4 => {
            IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
        }
        libc::AF_INET6 if raw.len() >= 16 => {
            let arr: [u8; 16] = raw[..16].try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(arr))
        }
        _ => return None,
    };
    Some(NetlinkAddr {
        ifindex,
        family,
        address: addr.to_string(),
        prefix_len,
        scope,
    })
}

pub(crate) fn parse_route_payload(payload: &[u8]) -> Option<NetlinkRoute> {
    let hdr_len = mem::size_of::<RtMsg>();
    if payload.len() < hdr_len {
        return None;
    }
    let family = payload[0];
    let dst_len = payload[1];
    let rtm_table = payload[4] as u32;
    let rtm_type = payload[7];
    if rtm_type != RTN_UNICAST_VAL {
        return None;
    }
    let attrs = parse_attrs(&payload[hdr_len..]);
    let mut dst: Option<IpAddr> = None;
    let mut gateway: Option<String> = None;
    let mut oif: Option<i32> = None;
    let mut table = rtm_table;
    let mut priority = None;

    let decode_ip = |v: &[u8]| -> Option<IpAddr> {
        match family as i32 {
            libc::AF_INET if v.len() >= 4 => Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]))),
            libc::AF_INET6 if v.len() >= 16 => {
                let arr: [u8; 16] = v[..16].try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(arr)))
            }
            _ => None,
        }
    };

    for (t, v) in attrs {
        match t {
            RTA_DST_ATTR => dst = decode_ip(v),
            RTA_GATEWAY_ATTR => gateway = decode_ip(v).map(|ip| ip.to_string()),
            RTA_OIF_ATTR if v.len() >= 4 => {
                oif = Some(i32::from_ne_bytes([v[0], v[1], v[2], v[3]]));
            }
            RTA_TABLE_ATTR if v.len() >= 4 => {
                table = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]);
            }
            RTA_PRIORITY_ATTR if v.len() >= 4 => {
                priority = Some(u32::from_ne_bytes([v[0], v[1], v[2], v[3]]));
            }
            _ => {}
        }
    }

    let dst_str = match (dst, dst_len, family as i32) {
        (Some(ip), _, _) => format!("{ip}/{dst_len}"),
        (None, 0, libc::AF_INET) => "0.0.0.0/0".into(),
        (None, 0, libc::AF_INET6) => "::/0".into(),
        _ => return None,
    };
    Some(NetlinkRoute {
        family,
        dst: dst_str,
        dst_len,
        gateway,
        oif,
        table,
        priority,
    })
}

pub fn list_links() -> Result<Vec<NetlinkLink>, String> {
    let msg = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: 0,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfInfoMsg as *const u8, mem::size_of::<IfInfoMsg>())
    };
    let req = NlBuilder::new(RTM_GETLINK_OP, NLM_F_DUMP_BITS, 1, bytes).finish();
    let frames = send_recv_netlink(&req)?;
    Ok(frames
        .into_iter()
        .filter_map(|(t, p)| (t == RTM_NEWLINK_OP).then(|| parse_link_payload(&p)).flatten())
        .collect())
}

pub fn list_addrs() -> Result<Vec<NetlinkAddr>, String> {
    let msg = IfAddrMsg {
        ifa_family: libc::AF_UNSPEC as u8,
        ifa_prefixlen: 0,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfAddrMsg as *const u8, mem::size_of::<IfAddrMsg>())
    };
    let req = NlBuilder::new(RTM_GETADDR_OP, NLM_F_DUMP_BITS, 2, bytes).finish();
    let frames = send_recv_netlink(&req)?;
    Ok(frames
        .into_iter()
        .filter_map(|(t, p)| (t == RTM_NEWADDR_OP).then(|| parse_addr_payload(&p)).flatten())
        .collect())
}

pub fn list_routes(table_filter: Option<u32>) -> Result<Vec<NetlinkRoute>, String> {
    let msg = RtMsg {
        rtm_family: libc::AF_UNSPEC as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: 0,
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: 0,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let req = NlBuilder::new(RTM_GETROUTE_OP, NLM_F_DUMP_BITS, 3, bytes).finish();
    let frames = send_recv_netlink(&req)?;
    Ok(frames
        .into_iter()
        .filter_map(|(t, p)| (t == RTM_NEWROUTE_OP).then(|| parse_route_payload(&p)).flatten())
        .filter(|r| table_filter.is_none_or(|t| r.table == t))
        .collect())
}

/// Fast, fork-free native lookup of `name`'s primary global IPv4 address (e.g. `br-lan`).
pub fn get_iface_ipv4(name: &str) -> Option<Ipv4Addr> {
    let links = list_links().ok()?;
    let ifindex = links.into_iter().find(|l| l.name == name)?.ifindex;
    let addrs = list_addrs().ok()?;
    addrs
        .into_iter()
        .filter(|a| a.ifindex == ifindex && a.family as i32 == libc::AF_INET && a.scope < 254)
        .find_map(|a| a.address.parse::<Ipv4Addr>().ok())
}

/// Build a pure-Rust `RTM_NEWLINK` message creating `<iface>@<parent>` with `kind="rmnet"` and `mux_id`,
/// preserving Qualcomm IPA's factory-initialized parent MTU and `rmnet` hardware offload flags untouched.
pub(crate) fn build_create_rmnet_link_msg(parent_ifindex: i32, iface: &str, mux_id: u16) -> Vec<u8> {
    let msg = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: 0,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfInfoMsg as *const u8, mem::size_of::<IfInfoMsg>())
    };
    let mut b = NlBuilder::new(
        RTM_NEWLINK_OP,
        NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_EXCL_BIT,
        21,
        bytes,
    );
    b.push_u32(IFLA_LINK_ATTR, parent_ifindex as u32);
    let mut ifname = Vec::with_capacity(iface.len() + 1);
    ifname.extend_from_slice(iface.as_bytes());
    ifname.push(0);
    b.push_attr(IFLA_IFNAME_ATTR, &ifname);

    let mut info_data = Vec::new();
    push_attr_bytes(&mut info_data, IFLA_RMNET_MUX_ID_ATTR, &mux_id.to_ne_bytes());

    let mut link_info = Vec::new();
    push_attr_bytes(&mut link_info, IFLA_INFO_KIND_ATTR, b"rmnet\0");
    push_attr_bytes(&mut link_info, IFLA_INFO_DATA_ATTR | NLA_F_NESTED_BIT, &info_data);

    b.push_attr(IFLA_LINKINFO_ATTR | NLA_F_NESTED_BIT, &link_info);
    b.finish()
}

/// Build a pure-Rust `RTM_DELLINK` message for `ifindex`.
pub(crate) fn build_delete_link_msg(ifindex: i32) -> Vec<u8> {
    let msg = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: ifindex,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfInfoMsg as *const u8, mem::size_of::<IfInfoMsg>())
    };
    NlBuilder::new(RTM_DELLINK_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 22, bytes).finish()
}

/// Create `iface` (`rmnet_data*` or `wwan*`) over `rmnet_ipa0` with `mux_id` if not already present.
/// Returns `(link, created)` where `created == true` only if this call created the kernel link.
pub fn create_rmnet_link(parent_iface: &str, iface: &str, mux_id: u16) -> Result<(NetlinkLink, bool), String> {
    if parent_iface != "rmnet_ipa0" {
        return Err(format!(
            "refusing rmnet parent {parent_iface:?} (expected rmnet_ipa0)"
        ));
    }
    validate_managed_iface(iface)?;
    if !(1..=254).contains(&mux_id) {
        return Err(format!("invalid rmnet mux_id {mux_id} (expected 1..=254)"));
    }
    let links = list_links()?;
    if let Some(existing) = links.iter().find(|l| l.name == iface).cloned() {
        return Ok((existing, false));
    }
    let parent = links
        .iter()
        .find(|l| l.name == parent_iface)
        .ok_or_else(|| format!("parent interface {parent_iface} not present in kernel netlink"))?;
    let req = build_create_rmnet_link_msg(parent.ifindex, iface, mux_id);
    let created = match send_recv_netlink_errno(&req) {
        Ok(_) => true,
        Err((Some(libc::EEXIST), _)) => false,
        Err((_, msg)) => {
            return Err(format!(
                "create rmnet link {iface} (mux_id={mux_id}) on {parent_iface}: {msg}"
            ));
        }
    };
    let refreshed = list_links()?;
    let link = refreshed
        .into_iter()
        .find(|l| l.name == iface)
        .ok_or_else(|| format!("rmnet link {iface} missing after RTM_NEWLINK"))?;
    Ok((link, created))
}

/// Delete a daemon-created cellular `rmnet` interface via `RTM_DELLINK`.
pub fn delete_rmnet_link(iface: &str) -> Result<(), String> {
    validate_managed_iface(iface)?;
    let links = list_links()?;
    let Some(link) = links.into_iter().find(|l| l.name == iface) else {
        return Ok(());
    };
    if link.kind.as_deref() != Some("rmnet") {
        return Err(format!("refusing to delete non-rmnet link {iface}"));
    }
    let req = build_delete_link_msg(link.ifindex);
    match send_recv_netlink_errno(&req) {
        Ok(_) | Err((Some(libc::ENODEV), _)) => Ok(()),
        Err((_, msg)) => Err(format!("delete rmnet link {iface}: {msg}")),
    }
}

/// True for non-link-local, non-loopback, non-unspecified addresses that indicate an active WAN bearer.
pub fn is_routable_wan_addr(a: &NetlinkAddr) -> bool {
    if a.scope >= 253 {
        return false;
    }
    match a.address.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local() && !v4.is_multicast()
        }
        Ok(IpAddr::V6(v6)) => {
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_unicast_link_local()
                && !v6.is_multicast()
        }
        Err(_) => false,
    }
}

/// Return the first `rmnet_data*` link that is `UP + LOWER_UP` with at least one routable WAN address.
pub fn detect_active_rmnet_wan(links: &[NetlinkLink], addrs: &[NetlinkAddr]) -> Option<String> {
    let mut candidates: Vec<&NetlinkLink> = links
        .iter()
        .filter(|l| l.name.starts_with("rmnet_data") && l.up && l.lower_up)
        .collect();
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    candidates.into_iter().find_map(|link| {
        addrs
            .iter()
            .any(|a| a.ifindex == link.ifindex && is_routable_wan_addr(a))
            .then(|| link.name.clone())
    })
}

/// Live kernel netlink check for an active cellular WAN bearer (`rmnet_data*` UP+LOWER_UP + routable IP).
pub fn detect_active_rmnet_wan_live() -> Option<String> {
    let links = list_links().ok()?;
    let addrs = list_addrs().ok()?;
    detect_active_rmnet_wan(&links, &addrs)
}

pub fn set_link_up(iface: &str, ifindex: i32, up: bool) -> Result<(), String> {
    validate_managed_iface(iface)?;
    let msg = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: ifindex,
        ifi_flags: if up { IFF_UP_BIT } else { 0 },
        ifi_change: IFF_UP_BIT,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfInfoMsg as *const u8, mem::size_of::<IfInfoMsg>())
    };
    let req = NlBuilder::new(RTM_NEWLINK_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 10, bytes).finish();
    send_recv_netlink(&req).map(|_| ())
}

pub fn set_link_mtu(iface: &str, ifindex: i32, mtu: u32) -> Result<(), String> {
    validate_managed_iface(iface)?;
    if !(576..=9216).contains(&mtu) {
        return Err(format!("invalid MTU {mtu}"));
    }
    let msg = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: ifindex,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfInfoMsg as *const u8, mem::size_of::<IfInfoMsg>())
    };
    let mut b = NlBuilder::new(RTM_NEWLINK_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 11, bytes);
    b.push_u32(IFLA_MTU_ATTR, mtu);
    send_recv_netlink(&b.finish()).map(|_| ())
}

pub fn replace_addr(iface: &str, ifindex: i32, ip: IpAddr, prefix_len: u8) -> Result<(), String> {
    validate_managed_iface(iface)?;
    let (family, max_prefix, octets): (u8, u8, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (libc::AF_INET as u8, 32, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, 128, v6.octets().to_vec()),
    };
    let msg = IfAddrMsg {
        ifa_family: family,
        ifa_prefixlen: prefix_len.min(max_prefix),
        ifa_flags: 0,
        ifa_scope: RT_SCOPE_UNIVERSE_VAL,
        ifa_index: ifindex as u32,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const IfAddrMsg as *const u8, mem::size_of::<IfAddrMsg>())
    };
    let mut b = NlBuilder::new(
        RTM_NEWADDR_OP,
        NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_REPLACE_BIT,
        12,
        bytes,
    );
    b.push_attr(IFA_LOCAL_ATTR, &octets);
    b.push_attr(IFA_ADDRESS_ATTR, &octets);
    send_recv_netlink(&b.finish()).map(|_| ())
}

pub fn flush_iface_addrs(iface: &str, ifindex: i32, family: Option<u8>) -> Result<(), String> {
    validate_managed_iface(iface)?;
    let addrs = list_addrs()?;
    for a in addrs {
        if a.ifindex != ifindex || a.scope >= 253 {
            continue;
        }
        if family.is_some_and(|f| a.family != f) {
            continue;
        }
        let Ok(ip) = a.address.parse::<IpAddr>() else { continue };
        let octets: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let msg = IfAddrMsg {
            ifa_family: a.family,
            ifa_prefixlen: a.prefix_len,
            ifa_flags: 0,
            ifa_scope: a.scope,
            ifa_index: ifindex as u32,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(&msg as *const IfAddrMsg as *const u8, mem::size_of::<IfAddrMsg>())
        };
        let mut b = NlBuilder::new(RTM_DELADDR_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 13, bytes);
        b.push_attr(IFA_LOCAL_ATTR, &octets);
        b.push_attr(IFA_ADDRESS_ATTR, &octets);
        let _ = send_recv_netlink(&b.finish());
    }
    Ok(())
}

pub fn replace_default_route_v4(
    iface: &str,
    ifindex: i32,
    gateway: Option<Ipv4Addr>,
    table: u32,
    metric: Option<u32>,
    mtu: Option<u32>,
) -> Result<(), String> {
    validate_managed_iface(iface)?;
    validate_managed_table(table)?;
    let msg = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: RTPROT_STATIC_VAL,
        rtm_scope: if gateway.is_some() { RT_SCOPE_UNIVERSE_VAL } else { RT_SCOPE_LINK_VAL },
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(
        RTM_NEWROUTE_OP,
        NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_REPLACE_BIT,
        14,
        bytes,
    );
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_i32(RTA_OIF_ATTR, ifindex);
    if let Some(gw) = gateway {
        b.push_attr(RTA_GATEWAY_ATTR, &gw.octets());
    }
    if let Some(m) = metric {
        b.push_u32(RTA_PRIORITY_ATTR, m);
    }
    if let Some(m) = mtu.filter(|&v| (576..=9216).contains(&v)) {
        b.push_attr(RTA_METRICS_ATTR, &encode_metrics_mtu(m));
    }
    send_recv_netlink(&b.finish()).map(|_| ())
}

pub fn replace_default_route_v6(
    iface: &str,
    ifindex: i32,
    table: u32,
    metric: Option<u32>,
    mtu: Option<u32>,
) -> Result<(), String> {
    validate_managed_iface(iface)?;
    validate_managed_table(table)?;
    // Device-only IPv6 default route (no gateway nexthop attribute — Raw-IP rmnet points straight out of dev)
    let msg = RtMsg {
        rtm_family: libc::AF_INET6 as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: RTPROT_BOOT_VAL,
        rtm_scope: RT_SCOPE_UNIVERSE_VAL,
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(
        RTM_NEWROUTE_OP,
        NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_REPLACE_BIT,
        15,
        bytes,
    );
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_i32(RTA_OIF_ATTR, ifindex);
    if let Some(m) = metric {
        b.push_u32(RTA_PRIORITY_ATTR, m);
    }
    if let Some(m) = mtu.filter(|&v| (576..=9216).contains(&v)) {
        b.push_attr(RTA_METRICS_ATTR, &encode_metrics_mtu(m));
    }
    send_recv_netlink(&b.finish()).map(|_| ())
}

pub fn replace_host_route_v6(
    iface: &str,
    ifindex: i32,
    dst: Ipv6Addr,
    table: u32,
    metric: Option<u32>,
) -> Result<(), String> {
    validate_managed_iface(iface)?;
    validate_managed_table(table)?;
    let msg = RtMsg {
        rtm_family: libc::AF_INET6 as u8,
        rtm_dst_len: 128,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: RTPROT_STATIC_VAL,
        rtm_scope: RT_SCOPE_UNIVERSE_VAL,
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(
        RTM_NEWROUTE_OP,
        NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_REPLACE_BIT,
        17,
        bytes,
    );
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_attr(RTA_DST_ATTR, &dst.octets());
    b.push_i32(RTA_OIF_ATTR, ifindex);
    if let Some(m) = metric {
        b.push_u32(RTA_PRIORITY_ATTR, m);
    }
    send_recv_netlink(&b.finish()).map(|_| ())
}

pub fn del_host_route_v6(iface: &str, ifindex: i32, dst: Ipv6Addr, table: u32) -> Result<(), String> {
    validate_managed_iface(iface)?;
    validate_managed_table(table)?;
    let msg = RtMsg {
        rtm_family: libc::AF_INET6 as u8,
        rtm_dst_len: 128,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(RTM_DELROUTE_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 18, bytes);
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_attr(RTA_DST_ATTR, &dst.octets());
    b.push_i32(RTA_OIF_ATTR, ifindex);
    let _ = send_recv_netlink(&b.finish());
    Ok(())
}

pub fn replace_passthrough_host_route_v4(
    br_iface: &str,
    br_ifindex: i32,
    ip: Ipv4Addr,
    table: u32,
) -> Result<(), String> {
    validate_passthrough_bridge(br_iface)?;
    validate_managed_table(table)?;
    let msg = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 32,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: RTPROT_STATIC_VAL,
        rtm_scope: RT_SCOPE_LINK_VAL,
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(
        RTM_NEWROUTE_OP,
        NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_REPLACE_BIT,
        19,
        bytes,
    );
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_attr(RTA_DST_ATTR, &ip.octets());
    b.push_i32(RTA_OIF_ATTR, br_ifindex);
    send_recv_netlink(&b.finish()).map(|_| ())
}

pub fn del_passthrough_host_route_v4(
    br_iface: &str,
    br_ifindex: i32,
    ip: Ipv4Addr,
    table: u32,
) -> Result<(), String> {
    validate_passthrough_bridge(br_iface)?;
    validate_managed_table(table)?;
    let msg = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 32,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(RTM_DELROUTE_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 20, bytes);
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_attr(RTA_DST_ATTR, &ip.octets());
    b.push_i32(RTA_OIF_ATTR, br_ifindex);
    let _ = send_recv_netlink(&b.finish());
    Ok(())
}

pub(crate) fn build_del_default_route_msg(family: u8, ifindex: i32, table: u32) -> Vec<u8> {
    let msg = RtMsg {
        rtm_family: family,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: if table <= 255 { table as u8 } else { RT_TABLE_COMPAT_VAL },
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: RTN_UNICAST_VAL,
        rtm_flags: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&msg as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    };
    let mut b = NlBuilder::new(RTM_DELROUTE_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 16, bytes);
    b.push_u32(RTA_TABLE_ATTR, table);
    b.push_i32(RTA_OIF_ATTR, ifindex);
    b.finish()
}

pub fn del_default_routes_family(
    iface: &str,
    ifindex: i32,
    table: u32,
    family: Option<u8>,
) -> Result<(), String> {
    validate_managed_iface(iface)?;
    validate_managed_table(table)?;
    let families: &[u8] = match family {
        Some(f) if f == libc::AF_INET as u8 => &[libc::AF_INET as u8],
        Some(f) if f == libc::AF_INET6 as u8 => &[libc::AF_INET6 as u8],
        Some(other) => return Err(format!("unsupported address family {other}")),
        None => &[libc::AF_INET as u8, libc::AF_INET6 as u8],
    };
    for &fam in families {
        let req = build_del_default_route_msg(fam, ifindex, table);
        // Loop so multiple residual default routes (e.g. differing metrics/protocols)
        // on the same interface/table are all evicted until kernel reports ESRCH/ENOENT.
        for _ in 0..16 {
            match send_recv_netlink_errno(&req) {
                Ok(_) => continue,
                Err((Some(libc::ESRCH | libc::ENOENT | libc::ENODEV), _)) => break,
                Err(_) => break,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn del_default_routes(iface: &str, ifindex: i32, table: u32) -> Result<(), String> {
    del_default_routes_family(iface, ifindex, table, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_raw_attr(buf: &mut Vec<u8>, rta_type: u16, val: &[u8]) {
        let len = (4 + val.len()) as u16;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&rta_type.to_ne_bytes());
        buf.extend_from_slice(val);
        let aligned = align4(buf.len());
        buf.resize(aligned, 0);
    }

    #[test]
    fn guards_refuse_protected_ifaces_and_tables() {
        for bad in ["lo", "eth0", "br-lan", "rmnet_ipa0", "wg-warp", "tap0", "", "a very long interface name"] {
            assert!(validate_managed_iface(bad).is_err(), "{bad}");
        }
        for good in ["rmnet_data0", "rmnet_data15", "wwan0"] {
            assert!(validate_managed_iface(good).is_ok(), "{good}");
        }
        assert!(validate_managed_table(TABLE_LOCAL).is_err());
        assert!(validate_managed_table(TABLE_WARP).is_err());
        assert!(validate_managed_table(0).is_err());
        assert!(validate_managed_table(TABLE_MAIN).is_ok());
    }

    #[test]
    fn parses_rmnet_link_addr_and_route_payloads() {
        let mut link = vec![0u8; mem::size_of::<IfInfoMsg>()];
        link[4..8].copy_from_slice(&17i32.to_ne_bytes());
        link[8..12].copy_from_slice(&(IFF_UP_BIT | IFF_LOWER_UP_BIT).to_ne_bytes());
        push_raw_attr(&mut link, IFLA_IFNAME_ATTR, b"rmnet_data0\0");
        push_raw_attr(&mut link, IFLA_MTU_ATTR, &1500u32.to_ne_bytes());
        let mut info_data = Vec::new();
        push_raw_attr(&mut info_data, IFLA_RMNET_MUX_ID_ATTR, &1u16.to_ne_bytes());
        let mut link_info = Vec::new();
        push_raw_attr(&mut link_info, IFLA_INFO_KIND_ATTR, b"rmnet\0");
        push_raw_attr(&mut link_info, IFLA_INFO_DATA_ATTR, &info_data);
        push_raw_attr(&mut link, IFLA_LINKINFO_ATTR, &link_info);

        let parsed = parse_link_payload(&link).unwrap();
        assert_eq!(parsed.ifindex, 17);
        assert_eq!(parsed.name, "rmnet_data0");
        assert!(parsed.up && parsed.lower_up);
        assert_eq!(parsed.mtu, 1500);
        assert_eq!(parsed.kind.as_deref(), Some("rmnet"));
        assert_eq!(parsed.rmnet_mux_id, Some(1));

        let mut addr = vec![0u8; mem::size_of::<IfAddrMsg>()];
        addr[0] = libc::AF_INET as u8;
        addr[1] = 22;
        addr[3] = 0;
        addr[4..8].copy_from_slice(&5i32.to_ne_bytes());
        push_raw_attr(&mut addr, IFA_LOCAL_ATTR, &[192, 168, 228, 1]);
        let pa = parse_addr_payload(&addr).unwrap();
        assert_eq!(pa.address, "192.168.228.1");
        assert_eq!(pa.prefix_len, 22);

        let mut rt = vec![0u8; mem::size_of::<RtMsg>()];
        rt[0] = libc::AF_INET6 as u8;
        rt[1] = 0;
        rt[4] = TABLE_MAIN as u8;
        rt[7] = RTN_UNICAST_VAL;
        push_raw_attr(&mut rt, RTA_OIF_ATTR, &17i32.to_ne_bytes());
        push_raw_attr(&mut rt, RTA_TABLE_ATTR, &TABLE_MAIN.to_ne_bytes());
        let pr = parse_route_payload(&rt).unwrap();
        assert_eq!(pr.dst, "::/0");
        assert_eq!(pr.oif, Some(17));
        assert_eq!(pr.table, TABLE_MAIN);
    }

    #[test]
    fn builder_sets_total_length_and_4byte_alignment() {
        let msg = [0u8; mem::size_of::<IfInfoMsg>()];
        let mut b = NlBuilder::new(RTM_NEWLINK_OP, NLM_F_REQUEST_BIT | NLM_F_ACK_BIT, 9, &msg);
        b.push_u32(IFLA_MTU_ATTR, 1420);
        let raw = b.finish();
        assert_eq!(raw.len() % 4, 0);
        assert_eq!(u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize, raw.len());
    }

    #[test]
    fn encode_metrics_mtu_and_passthrough_guards_work() {
        let enc = encode_metrics_mtu(1472);
        let attrs = parse_attrs(&enc);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, RTAX_LOCK_ATTR);
        assert_eq!(u32::from_ne_bytes(attrs[0].1.try_into().unwrap()), RTAX_LOCK_MTU_BIT);
        assert_eq!(attrs[1].0, RTAX_MTU_ATTR);
        assert_eq!(u32::from_ne_bytes(attrs[1].1.try_into().unwrap()), 1472);

        assert!(validate_passthrough_bridge("br-lan").is_ok());
        assert!(validate_passthrough_bridge("br-lan2").is_ok());
        for bad in ["", "eth0", "rmnet_data0", "br-wan", "br-lan/1", "lo"] {
            assert!(validate_passthrough_bridge(bad).is_err(), "{bad}");
        }

        let links = vec![
            NetlinkLink {
                ifindex: 18,
                name: "rmnet_data0".into(),
                up: false,
                lower_up: false,
                mtu: 1500,
                kind: Some("rmnet".into()),
                rmnet_mux_id: Some(1),
                master_index: None,
            },
            NetlinkLink {
                ifindex: 19,
                name: "rmnet_data1".into(),
                up: true,
                lower_up: true,
                mtu: 1500,
                kind: Some("rmnet".into()),
                rmnet_mux_id: Some(2),
                master_index: None,
            },
        ];
        assert_eq!(resolve_rmnet_link(&links, "rmnet_data1", 1).unwrap().rmnet_mux_id, Some(2));
        assert_eq!(resolve_rmnet_link(&links, "missing", 2).unwrap().name, "rmnet_data1");
        assert!(resolve_rmnet_link(&links, "missing", 9).is_none());
        let with_zero = [NetlinkLink {
            ifindex: 20,
            name: "rmnet_ipa0".into(),
            up: true,
            lower_up: true,
            mtu: 9216,
            kind: None,
            rmnet_mux_id: Some(0),
            master_index: None,
        }];
        assert!(resolve_rmnet_link(&with_zero, "missing", 0).is_none());
    }

    #[test]
    fn builds_rmnet_create_and_delete_messages_and_enforces_guards() {
        let msg = build_create_rmnet_link_msg(14, "rmnet_data0", 1);
        assert_eq!(msg.len() % 4, 0);
        let nl_hdr_len = mem::size_of::<NlMsgHdr>();
        let if_hdr_len = mem::size_of::<IfInfoMsg>();
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize, msg.len());
        assert_eq!(u16::from_ne_bytes(msg[4..6].try_into().unwrap()), RTM_NEWLINK_OP);
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST_BIT | NLM_F_ACK_BIT | NLM_F_CREATE_BIT | NLM_F_EXCL_BIT
        );

        let raw_attrs = &msg[nl_hdr_len + if_hdr_len..];
        let attrs = parse_attrs(raw_attrs);
        let link_attr = attrs.iter().find(|(t, _)| *t == IFLA_LINK_ATTR).unwrap().1;
        assert_eq!(u32::from_ne_bytes(link_attr.try_into().unwrap()), 14);
        let name_attr = attrs.iter().find(|(t, _)| *t == IFLA_IFNAME_ATTR).unwrap().1;
        assert_eq!(name_attr, b"rmnet_data0\0");

        let linkinfo_val = attrs.iter().find(|(t, _)| *t == IFLA_LINKINFO_ATTR).unwrap().1;
        let li_attrs = parse_attrs(linkinfo_val);
        assert_eq!(
            li_attrs.iter().find(|(t, _)| *t == IFLA_INFO_KIND_ATTR).unwrap().1,
            b"rmnet\0"
        );
        let info_data_val = li_attrs.iter().find(|(t, _)| *t == IFLA_INFO_DATA_ATTR).unwrap().1;
        let id_attrs = parse_attrs(info_data_val);
        let mux_val = id_attrs.iter().find(|(t, _)| *t == IFLA_RMNET_MUX_ID_ATTR).unwrap().1;
        assert_eq!(u16::from_ne_bytes(mux_val.try_into().unwrap()), 1);

        let del = build_delete_link_msg(17);
        assert_eq!(u32::from_ne_bytes(del[0..4].try_into().unwrap()) as usize, del.len());
        assert_eq!(u16::from_ne_bytes(del[4..6].try_into().unwrap()), RTM_DELLINK_OP);
        assert_eq!(i32::from_ne_bytes(del[nl_hdr_len + 4..nl_hdr_len + 8].try_into().unwrap()), 17);

        assert!(create_rmnet_link("eth0", "rmnet_data0", 1).is_err());
        assert!(create_rmnet_link("rmnet_ipa0", "eth0", 1).is_err());
        assert!(create_rmnet_link("rmnet_ipa0", "br-lan", 1).is_err());
        assert!(create_rmnet_link("rmnet_ipa0", "rmnet_ipa0", 1).is_err());
        assert!(create_rmnet_link("rmnet_ipa0", "rmnet_data0", 0).is_err());
        assert!(create_rmnet_link("rmnet_ipa0", "rmnet_data0", 255).is_err());
        assert!(delete_rmnet_link("eth0").is_err());
        assert!(delete_rmnet_link("br-lan").is_err());
        assert!(delete_rmnet_link("rmnet_ipa0").is_err());
    }

    #[test]
    fn detect_active_rmnet_wan_requires_up_carrier_and_routable_ip() {
        let mk_link = |ifindex: i32, name: &str, up: bool, lower_up: bool| NetlinkLink {
            ifindex,
            name: name.into(),
            up,
            lower_up,
            mtu: 1500,
            kind: Some("rmnet".into()),
            rmnet_mux_id: Some(1),
            master_index: None,
        };
        let mk_addr = |ifindex: i32, family: i32, addr: &str, prefix_len: u8, scope: u8| NetlinkAddr {
            ifindex,
            family: family as u8,
            address: addr.into(),
            prefix_len,
            scope,
        };

        // Only link-local fe80:: -> None
        let links = vec![mk_link(17, "rmnet_data0", true, true)];
        let addrs = vec![mk_addr(17, libc::AF_INET6, "fe80::1", 64, 253)];
        assert_eq!(detect_active_rmnet_wan(&links, &addrs), None);

        // DOWN link with global IPv4 -> None; eth0 with global IPv4 -> None
        let links2 = vec![
            mk_link(2, "eth0", true, true),
            mk_link(17, "rmnet_data0", false, false),
        ];
        let addrs2 = vec![
            mk_addr(2, libc::AF_INET, "192.168.1.2", 24, 0),
            mk_addr(17, libc::AF_INET, "192.0.0.2", 27, 0),
        ];
        assert_eq!(detect_active_rmnet_wan(&links2, &addrs2), None);

        // UP + LOWER_UP rmnet_data1 with T-Mobile CLAT 192.0.0.2/27 -> Some("rmnet_data1")
        let links3 = vec![
            mk_link(17, "rmnet_data0", true, true),
            mk_link(18, "rmnet_data1", true, true),
        ];
        let addrs3 = vec![
            mk_addr(17, libc::AF_INET6, "fe80::1", 64, 253),
            mk_addr(18, libc::AF_INET, "192.0.0.2", 27, 0),
        ];
        assert_eq!(detect_active_rmnet_wan(&links3, &addrs3).as_deref(), Some("rmnet_data1"));

        // UP + LOWER_UP rmnet_data0 with global IPv6 -> Some("rmnet_data0")
        let addrs4 = vec![mk_addr(17, libc::AF_INET6, "2607:fb90::1", 64, 0)];
        assert_eq!(detect_active_rmnet_wan(&links, &addrs4).as_deref(), Some("rmnet_data0"));
    }

    #[test]
    fn del_default_route_msg_and_guards() {
        let m4 = build_del_default_route_msg(libc::AF_INET as u8, 17, TABLE_MAIN);
        assert_eq!(m4.len() % 4, 0);
        assert_eq!(u16::from_ne_bytes([m4[4], m4[5]]), RTM_DELROUTE_OP);
        let m6 = build_del_default_route_msg(libc::AF_INET6 as u8, 17, TABLE_MAIN);
        assert_eq!(m6.len() % 4, 0);
        assert_eq!(u16::from_ne_bytes([m6[4], m6[5]]), RTM_DELROUTE_OP);
        assert!(del_default_routes("br-lan", 5, TABLE_MAIN).is_err());
        assert!(del_default_routes("rmnet_data0", 17, TABLE_WARP).is_err());
    }
}
