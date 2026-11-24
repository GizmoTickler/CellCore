//! Native Linux `AF_QIPCRTR` (`42`) QRTR bus discovery, per-client QMI sockets,
//! unsolicited indication forwarding, and modem SSR recovery.

use std::{
    collections::HashMap,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::unix::AsyncFd,
    sync::{Notify, broadcast, mpsc, oneshot},
};

use super::{
    BoxFuture, QmiClient, QmiError, QmiIndication, QmiRpcResult, SVC_DMS, SVC_NAS, SVC_UIM,
    SVC_WDA, SVC_WDS, ServiceEndpoint,
    codec::{QMI_FLAG_INDICATION, QMI_FLAG_RESPONSE, decode_sdu, encode_request},
    service_name,
};

fn is_core_modem_service(service: u32) -> bool {
    matches!(service, SVC_WDS | SVC_DMS | SVC_NAS | SVC_UIM | SVC_WDA)
}

type PendingWaiters = Mutex<HashMap<(u16, u16), oneshot::Sender<QmiRpcResult>>>;

pub const AF_QIPCRTR: libc::c_int = 42;
#[allow(dead_code)]
pub const QRTR_NODE_BCAST: u32 = 0xFFFF_FFFF;
pub const QRTR_PORT_CTRL: u32 = 0xFFFF_FFFE;
pub const CTRL_PKT_LEN: usize = 20;

#[allow(dead_code)]
pub const CMD_DATA: u32 = 1;
#[allow(dead_code)]
pub const CMD_HELLO: u32 = 2;
pub const CMD_BYE: u32 = 3;
pub const CMD_NEW_SERVER: u32 = 4;
pub const CMD_DEL_SERVER: u32 = 5;
#[allow(dead_code)]
pub const CMD_DEL_CLIENT: u32 = 6;
#[allow(dead_code)]
pub const CMD_RESUME_TX: u32 = 7;
pub const CMD_NEW_LOOKUP: u32 = 10;
#[allow(dead_code)]
pub const CMD_DEL_LOOKUP: u32 = 11;
pub const CMD_DEL_PROC: u32 = 13;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockAddrQrtr {
    pub sq_family: u16,
    pub _pad: u16,
    pub sq_node: u32,
    pub sq_port: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrtrCtrlPkt {
    pub cmd: u32,
    pub service: u32,
    pub version: u32,
    pub instance: u32,
    pub node: u32,
    pub port: u32,
}

impl QrtrCtrlPkt {
    pub fn new_lookup(service: u32) -> Self {
        Self {
            cmd: CMD_NEW_LOOKUP,
            service,
            version: 0,
            instance: 0,
            node: 0,
            port: 0,
        }
    }

    pub fn encode(&self) -> [u8; CTRL_PKT_LEN] {
        let mut out = [0u8; CTRL_PKT_LEN];
        let inst_ver = (self.instance << 8) | (self.version & 0xFF);
        out[0..4].copy_from_slice(&self.cmd.to_le_bytes());
        out[4..8].copy_from_slice(&self.service.to_le_bytes());
        out[8..12].copy_from_slice(&inst_ver.to_le_bytes());
        out[12..16].copy_from_slice(&self.node.to_le_bytes());
        out[16..20].copy_from_slice(&self.port.to_le_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, QmiError> {
        if buf.len() < CTRL_PKT_LEN {
            return Err(QmiError::Malformed(format!(
                "QRTR control packet too short: {} bytes",
                buf.len()
            )));
        }
        let u = |off: usize| u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let cmd = u(0);
        let service = u(4);
        let inst_ver = u(8);
        let node = u(12);
        let port = u(16);
        Ok(Self {
            cmd,
            service,
            version: inst_ver & 0xFF,
            instance: inst_ver >> 8,
            node,
            port,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrtrBusEvent {
    ServiceAdded(ServiceEndpoint),
    ServiceRemoved { service: u32, node: u32, port: u32 },
    Ssr { node: u32, reason: String },
}

#[derive(Debug, Default, Clone)]
pub struct BusSnapshot {
    pub available: bool,
    pub local_node: Option<u32>,
    pub modem_node: u32,
    pub ssr_count: u64,
    pub last_ssr_epoch: Option<u64>,
    pub services: Vec<ServiceEndpoint>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct BusState {
    pub local_node: u32,
    pub modem_node: u32,
    pub modem_node_pinned: bool,
    pub ssr_count: u64,
    pub last_ssr_epoch: Option<u64>,
    pub modem_services: HashMap<u32, ServiceEndpoint>,
    pub all_services: Vec<ServiceEndpoint>,
}

impl BusState {
    pub(crate) fn new(local_node: u32, modem_node: u32) -> Self {
        Self {
            local_node,
            modem_node,
            modem_node_pinned: true,
            ssr_count: 0,
            last_ssr_epoch: None,
            modem_services: HashMap::new(),
            all_services: Vec::new(),
        }
    }

    pub(crate) fn new_auto(local_node: u32, default_modem_node: u32) -> Self {
        Self {
            local_node,
            modem_node: default_modem_node,
            modem_node_pinned: false,
            ssr_count: 0,
            last_ssr_epoch: None,
            modem_services: HashMap::new(),
            all_services: Vec::new(),
        }
    }
}

/// Pure state transition function for QRTR control packets (separates protocol logic from kernel sockets).
pub(crate) fn apply_ctrl_pkt(
    st: &mut BusState,
    pkt: &QrtrCtrlPkt,
    now_epoch: u64,
) -> Option<QrtrBusEvent> {
    match pkt.cmd {
        CMD_NEW_SERVER => {
            // End-of-lookup sentinel emitted by kernel/NS: all zeros
            if pkt.service == 0 && pkt.node == 0 && pkt.port == 0 {
                return None;
            }
            let ep = ServiceEndpoint {
                service: pkt.service,
                name: service_name(pkt.service).to_string(),
                version: pkt.version,
                instance: pkt.instance,
                node: pkt.node,
                port: pkt.port,
            };
            st.all_services
                .retain(|s| !(s.service == ep.service && s.node == ep.node && s.port == ep.port));
            st.all_services.push(ep.clone());
            st.all_services.sort_by_key(|s| (s.node, s.service, s.port));
            if !st.modem_node_pinned
                && pkt.node != st.local_node
                && is_core_modem_service(pkt.service)
            {
                if pkt.node != st.modem_node {
                    st.modem_node = pkt.node;
                    st.modem_services.clear();
                    for existing in &st.all_services {
                        if existing.node == st.modem_node {
                            st.modem_services.insert(existing.service, existing.clone());
                        }
                    }
                }
                st.modem_node_pinned = true;
            }
            if pkt.node == st.modem_node {
                st.modem_services.insert(pkt.service, ep.clone());
                return Some(QrtrBusEvent::ServiceAdded(ep));
            }
            None
        }
        CMD_DEL_SERVER => {
            st.all_services
                .retain(|s| !(s.service == pkt.service && s.node == pkt.node && s.port == pkt.port));
            if pkt.node == st.modem_node {
                let was_tracked = st
                    .modem_services
                    .get(&pkt.service)
                    .is_some_and(|e| e.port == pkt.port);
                if was_tracked {
                    st.modem_services.remove(&pkt.service);
                    st.ssr_count += 1;
                    st.last_ssr_epoch = Some(now_epoch);
                    return Some(QrtrBusEvent::Ssr {
                        node: pkt.node,
                        reason: format!("DEL_SERVER {} on node {}", service_name(pkt.service), pkt.node),
                    });
                }
                return Some(QrtrBusEvent::ServiceRemoved {
                    service: pkt.service,
                    node: pkt.node,
                    port: pkt.port,
                });
            }
            None
        }
        CMD_BYE | CMD_DEL_PROC if pkt.node == st.modem_node => {
            st.all_services.retain(|s| s.node != pkt.node);
            st.modem_services.clear();
            st.ssr_count += 1;
            st.last_ssr_epoch = Some(now_epoch);
            let kind = if pkt.cmd == CMD_BYE { "BYE" } else { "DEL_PROC" };
            Some(QrtrBusEvent::Ssr {
                node: pkt.node,
                reason: format!("QRTR {kind} from node {}", pkt.node),
            })
        }
        _ => None,
    }
}

pub(crate) fn needs_ephemeral_bind(local: SockAddrQrtr) -> bool {
    local.sq_port == 0
}

pub(crate) fn is_deferrable_bind_errno(code: Option<i32>) -> bool {
    matches!(code, Some(libc::EINVAL | libc::EADDRINUSE))
}

fn getsockname_qrtr(fd: &OwnedFd) -> Result<SockAddrQrtr, QmiError> {
    let mut local = SockAddrQrtr::default();
    let mut len = mem::size_of::<SockAddrQrtr>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            &mut local as *mut SockAddrQrtr as *mut libc::sockaddr,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(QmiError::Io(format!(
            "getsockname(AF_QIPCRTR): {}",
            io::Error::last_os_error()
        )));
    }
    if local.sq_family != AF_QIPCRTR as u16 {
        return Err(QmiError::Io(format!(
            "getsockname(AF_QIPCRTR): unexpected address family {}",
            local.sq_family
        )));
    }
    Ok(local)
}

fn open_bound_qrtr_socket() -> Result<(OwnedFd, SockAddrQrtr), QmiError> {
    let raw = unsafe {
        libc::socket(
            AF_QIPCRTR,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        let e = io::Error::last_os_error();
        let code = e.raw_os_error().unwrap_or(0);
        if matches!(
            code,
            libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT | libc::EPROTOTYPE
        ) {
            return Err(QmiError::Unsupported(e.to_string()));
        }
        return Err(QmiError::Io(format!("socket(AF_QIPCRTR): {e}")));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Read kernel-assigned local node and port first: Qualcomm 5.15 kernels auto-assign
    // local node != 0 in socket() and reject sq_node=0 bind() with EINVAL, while libqrtr/qrtr-lookup
    // rely on getsockname() + sendto() autobind.
    let mut local = getsockname_qrtr(&fd)?;
    if needs_ephemeral_bind(local) {
        let bind_addr = SockAddrQrtr {
            sq_family: AF_QIPCRTR as u16,
            _pad: 0,
            sq_node: local.sq_node,
            sq_port: 0,
        };
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &bind_addr as *const SockAddrQrtr as *const libc::sockaddr,
                mem::size_of::<SockAddrQrtr>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            local = getsockname_qrtr(&fd)?;
        } else {
            let e = io::Error::last_os_error();
            if !is_deferrable_bind_errno(e.raw_os_error()) {
                return Err(QmiError::Io(format!("bind(AF_QIPCRTR): {e}")));
            }
        }
    }
    Ok((fd, local))
}

async fn qrtr_send_to(
    afd: &AsyncFd<OwnedFd>,
    dst: SockAddrQrtr,
    data: &[u8],
) -> Result<usize, QmiError> {
    loop {
        let mut guard = afd
            .writable()
            .await
            .map_err(|e| QmiError::Io(format!("qrtr writable wait: {e}")))?;
        let rc = unsafe {
            libc::sendto(
                afd.get_ref().as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &dst as *const SockAddrQrtr as *const libc::sockaddr,
                mem::size_of::<SockAddrQrtr>() as libc::socklen_t,
            )
        };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            guard.clear_ready();
            continue;
        }
        if e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(QmiError::Io(format!("sendto(AF_QIPCRTR): {e}")));
    }
}

async fn qrtr_recv_from(
    afd: &AsyncFd<OwnedFd>,
    buf: &mut [u8],
) -> Result<(usize, SockAddrQrtr), QmiError> {
    loop {
        let mut guard = afd
            .readable()
            .await
            .map_err(|e| QmiError::Io(format!("qrtr readable wait: {e}")))?;
        let mut src = SockAddrQrtr::default();
        let mut slen = mem::size_of::<SockAddrQrtr>() as libc::socklen_t;
        let rc = unsafe {
            libc::recvfrom(
                afd.get_ref().as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut src as *mut SockAddrQrtr as *mut libc::sockaddr,
                &mut slen,
            )
        };
        if rc >= 0 {
            return Ok((rc as usize, src));
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            guard.clear_ready();
            continue;
        }
        if e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) {
            guard.clear_ready();
            drop(guard);
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }
        return Err(QmiError::Io(format!("recvfrom(AF_QIPCRTR): {e}")));
    }
}

pub fn configured_modem_node_override() -> Option<u32> {
    std::env::var("QM_QRTR_MODEM_NODE")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

pub fn configured_modem_node() -> u32 {
    configured_modem_node_override().unwrap_or(0)
}

async fn send_lookup_on(
    ctrl_fd: &AsyncFd<OwnedFd>,
    state: &Mutex<BusState>,
) -> Result<(), QmiError> {
    let local_node = state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .local_node;
    let dst = SockAddrQrtr {
        sq_family: AF_QIPCRTR as u16,
        _pad: 0,
        sq_node: local_node,
        sq_port: QRTR_PORT_CTRL,
    };
    let pkt = QrtrCtrlPkt::new_lookup(0).encode();
    qrtr_send_to(ctrl_fd, dst, &pkt).await.map(|_| ())
}

static SHARED_BUS: Mutex<Option<Arc<QrtrBus>>> = Mutex::new(None);

/// Return a process-wide shared `QrtrBus` handle so `dataplane`, `qmi::dsp`,
/// and `telemetry` reuse a single `AF_QIPCRTR` control socket without leaking FDs.
pub fn shared_bus() -> Result<Arc<QrtrBus>, QmiError> {
    let mut g = SHARED_BUS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(bus) = g.as_ref() {
        if !bus.is_shutdown() {
            return Ok(Arc::clone(bus));
        }
        *g = None;
    }
    let bus = QrtrBus::connect()?;
    *g = Some(Arc::clone(&bus));
    Ok(bus)
}

/// Explicitly shut down and clear the shared `QrtrBus` instance (next caller reconnects).
#[allow(dead_code)]
pub fn reset_shared_bus() {
    let prev = SHARED_BUS.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(bus) = prev {
        bus.shutdown();
    }
}

/// Convenience helper over [`shared_bus`] to wait until `service_id` is registered on QRTR.
#[allow(dead_code)]
pub async fn wait_for_service(
    service_id: u32,
    timeout: Duration,
) -> Result<ServiceEndpoint, QmiError> {
    let bus = shared_bus()?;
    bus.wait_for_service(service_id, timeout).await
}

pub struct QrtrBus {
    ctrl_fd: Arc<AsyncFd<OwnedFd>>,
    state: Arc<Mutex<BusState>>,
    events_tx: broadcast::Sender<QrtrBusEvent>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
}

impl Drop for QrtrBus {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl QrtrBus {
    pub fn connect() -> Result<Arc<Self>, QmiError> {
        let (fd, local) = open_bound_qrtr_socket()?;
        let ctrl_fd = Arc::new(
            unsafe { AsyncFd::register(fd) }
                .map_err(|e| QmiError::Io(format!("AsyncFd ctrl: {e}")))?,
        );
        let bus_state = match configured_modem_node_override() {
            Some(node) => BusState::new(local.sq_node, node),
            None => BusState::new_auto(local.sq_node, 0),
        };
        let state = Arc::new(Mutex::new(bus_state));
        let (events_tx, _) = broadcast::channel(64);
        let bus = Arc::new(Self {
            ctrl_fd,
            state,
            events_tx,
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
        });
        drop(bus.spawn_ctrl_loop());
        Ok(bus)
    }

    /// Signal the background control loop to exit immediately and release the control socket FD.
    pub fn shutdown(&self) {
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            self.shutdown_notify.notify_waiters();
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<QrtrBusEvent> {
        self.events_tx.subscribe()
    }

    pub fn snapshot(&self) -> BusSnapshot {
        let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        BusSnapshot {
            available: !self.is_shutdown(),
            local_node: Some(g.local_node),
            modem_node: g.modem_node,
            ssr_count: g.ssr_count,
            last_ssr_epoch: g.last_ssr_epoch,
            services: g.all_services.clone(),
            last_error: None,
        }
    }

    pub fn endpoint_for(&self, service: u32) -> Option<ServiceEndpoint> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .modem_services
            .get(&service)
            .cloned()
    }

    pub async fn send_lookup(&self) -> Result<(), QmiError> {
        send_lookup_on(&self.ctrl_fd, &self.state).await
    }

    pub async fn wait_for_service(
        &self,
        service: u32,
        timeout: Duration,
    ) -> Result<ServiceEndpoint, QmiError> {
        self.wait_service(service, timeout).await
    }

    pub async fn wait_service(
        &self,
        service: u32,
        timeout: Duration,
    ) -> Result<ServiceEndpoint, QmiError> {
        if let Some(ep) = self.endpoint_for(service) {
            return Ok(ep);
        }
        let mut rx = self.subscribe();
        let _ = self.send_lookup().await;
        if let Some(ep) = self.endpoint_for(service) {
            return Ok(ep);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(ep) = self.endpoint_for(service) {
                return Ok(ep);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(QmiError::ServiceUnavailable(service));
            }
            match tokio::time::timeout(deadline - now, rx.recv()).await {
                Ok(Ok(QrtrBusEvent::ServiceAdded(ep))) if ep.service == service => return Ok(ep),
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    return Err(QmiError::ServiceUnavailable(service));
                }
                Err(_) => return Err(QmiError::ServiceUnavailable(service)),
            }
        }
    }

    /// Open a dedicated QMI client socket for `service` (`tag` identifies the slot in indications, e.g. `"WDS_V4"`).
    /// On QRTR each client socket's kernel-assigned ephemeral `sq_port` IS its QMI client ID.
    pub async fn open_service(
        self: &Arc<Self>,
        service: u32,
        tag: &'static str,
        ind_tx: mpsc::Sender<QmiIndication>,
        wait_timeout: Duration,
    ) -> Result<Arc<QrtrServiceClient>, QmiError> {
        let ep = self.wait_service(service, wait_timeout).await?;
        let (fd, local) = open_bound_qrtr_socket()?;
        let afd = Arc::new(
            unsafe { AsyncFd::register(fd) }
                .map_err(|e| QmiError::Io(format!("AsyncFd service: {e}")))?,
        );
        let inner = Arc::new(QrtrClientInner {
            ep: ep.clone(),
            tag,
            afd,
            next_tx_id: AtomicU16::new(1),
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        let reader_task = spawn_reader(Arc::clone(&inner), self.subscribe(), ind_tx);
        Ok(Arc::new(QrtrServiceClient {
            ep,
            tag,
            local_port: local.sq_port,
            inner,
            reader_task,
        }))
    }

    /// Spawn the QRTR control-packet reader without retaining a strong `Arc<QrtrBus>`.
    /// Dropping the last external `Arc<QrtrBus>` (or calling [`QrtrBus::shutdown`])
    /// triggers `shutdown_notify` so the task exits immediately and closes `ctrl_fd`.
    fn spawn_ctrl_loop(&self) -> tokio::task::JoinHandle<()> {
        let ctrl_fd = Arc::clone(&self.ctrl_fd);
        let state = Arc::clone(&self.state);
        let events_tx = self.events_tx.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let shutdown_notify = Arc::clone(&self.shutdown_notify);
        tokio::spawn(async move {
            if !shutdown.load(Ordering::Acquire) {
                tokio::select! {
                    biased;
                    _ = shutdown_notify.notified() => return,
                    _ = send_lookup_on(&ctrl_fd, &state) => {}
                }
            }

            let mut buf = [0u8; 512];
            loop {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                let notified = shutdown_notify.notified();
                tokio::pin!(notified);
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                let res = tokio::select! {
                    biased;
                    _ = &mut notified => break,
                    r = qrtr_recv_from(&ctrl_fd, &mut buf) => r,
                };
                match res {
                    Ok((n, _src)) => {
                        if let Ok(pkt) = QrtrCtrlPkt::decode(&buf[..n]) {
                            let evt = {
                                let mut g = state.lock().unwrap_or_else(|e| e.into_inner());
                                apply_ctrl_pkt(&mut g, &pkt, crate::auth::now_secs())
                            };
                            if let Some(ev) = evt {
                                let is_ssr = matches!(ev, QrtrBusEvent::Ssr { .. });
                                let _ = events_tx.send(ev);
                                if is_ssr && !shutdown.load(Ordering::Acquire) {
                                    let _ = send_lookup_on(&ctrl_fd, &state).await;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if shutdown.load(Ordering::Acquire) {
                            break;
                        }
                        tokio::select! {
                            biased;
                            _ = shutdown_notify.notified() => break,
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                        }
                    }
                }
            }
        })
    }
}

struct QrtrClientInner {
    ep: ServiceEndpoint,
    tag: &'static str,
    afd: Arc<AsyncFd<OwnedFd>>,
    next_tx_id: AtomicU16,
    pending: PendingWaiters,
    closed: AtomicBool,
}

impl QrtrClientInner {
    fn is_alive(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    fn fail_all_pending(&self, err: QmiError) {
        self.closed.store(true, Ordering::Relaxed);
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        for (_, tx) in g.drain() {
            let _ = tx.send(Err(err.clone()));
        }
    }

    fn alloc_tx_id(&self) -> u16 {
        let mut id = self.next_tx_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            id = self.next_tx_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }
}

pub struct QrtrServiceClient {
    pub ep: ServiceEndpoint,
    #[allow(dead_code)]
    pub tag: &'static str,
    #[allow(dead_code)]
    pub local_port: u32,
    inner: Arc<QrtrClientInner>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Drop for QrtrServiceClient {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        self.reader_task.abort();
    }
}

fn spawn_reader(
    inner: Arc<QrtrClientInner>,
    mut bus_rx: broadcast::Receiver<QrtrBusEvent>,
    ind_tx: mpsc::Sender<QmiIndication>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // QMI control SDUs on QRTR are well under 4 KiB; keep idle buffer at 8 KiB
        // (instead of 64 KiB per service client) to reduce steady-state RSS on embedded RAM.
        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                ev = bus_rx.recv() => {
                    match ev {
                        Ok(QrtrBusEvent::Ssr { .. }) => {
                            inner.fail_all_pending(QmiError::Ssr);
                            break;
                        }
                        Ok(QrtrBusEvent::ServiceRemoved { service, node, port })
                            if service == inner.ep.service && node == inner.ep.node && port == inner.ep.port =>
                        {
                            inner.fail_all_pending(QmiError::Ssr);
                            break;
                        }
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                pkt = qrtr_recv_from(&inner.afd, &mut buf) => {
                    match pkt {
                        Ok((n, src)) => {
                            // Ignore spurious non-modem or control-port packets.
                            if src.sq_node != inner.ep.node || src.sq_port == QRTR_PORT_CTRL {
                                continue;
                            }
                            if let Ok(sdu) = decode_sdu(&buf[..n]) {
                                if sdu.ctl_flags == QMI_FLAG_RESPONSE {
                                    let waiter = inner.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&(sdu.tx_id, sdu.msg_id));
                                    if let Some(tx) = waiter {
                                        let _ = tx.send(Ok(sdu.tlvs));
                                    }
                                } else if sdu.ctl_flags == QMI_FLAG_INDICATION {
                                    let _ = ind_tx.try_send(QmiIndication {
                                        service: inner.ep.service,
                                        tag: inner.tag,
                                        msg_id: sdu.msg_id,
                                        tlvs: sdu.tlvs,
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            inner.fail_all_pending(e);
                            break;
                        }
                    }
                }
            }
        }
    })
}

impl QrtrServiceClient {
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }
}

impl QmiClient for QrtrServiceClient {
    fn rpc<'a>(
        &'a self,
        msg_id: u16,
        req_tlvs: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'a, QmiRpcResult> {
        Box::pin(async move {
            if !self.inner.is_alive() {
                return Err(QmiError::Ssr);
            }
            let tx_id = self.inner.alloc_tx_id();
            let frame = encode_request(tx_id, msg_id, &req_tlvs)?;
            let (tx, rx) = oneshot::channel();
            {
                let mut g = self.inner.pending.lock().unwrap_or_else(|e| e.into_inner());
                g.insert((tx_id, msg_id), tx);
            }
            let dst = SockAddrQrtr {
                sq_family: AF_QIPCRTR as u16,
                _pad: 0,
                sq_node: self.ep.node,
                sq_port: self.ep.port,
            };
            if let Err(e) = qrtr_send_to(&self.inner.afd, dst, &frame).await {
                self.inner
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&(tx_id, msg_id));
                return Err(e);
            }
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err(QmiError::Ssr),
                Err(_) => {
                    self.inner
                        .pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&(tx_id, msg_id));
                    Err(QmiError::Timeout)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi::{SVC_DMS, SVC_NAS, SVC_WDS};

    #[test]
    fn sockaddr_qrtr_layout_is_12_bytes() {
        assert_eq!(mem::size_of::<SockAddrQrtr>(), 12);
    }

    #[test]
    fn ctrl_pkt_roundtrip_and_sentinel() {
        let lk = QrtrCtrlPkt::new_lookup(0);
        let raw = lk.encode();
        assert_eq!(raw.len(), CTRL_PKT_LEN);
        assert_eq!(QrtrCtrlPkt::decode(&raw).unwrap(), lk);

        // NEW_SERVER with inst=2, ver=1 => inst_ver = 0x0201
        let mut pkt = [0u8; 20];
        pkt[0..4].copy_from_slice(&CMD_NEW_SERVER.to_le_bytes());
        pkt[4..8].copy_from_slice(&SVC_WDS.to_le_bytes());
        pkt[8..12].copy_from_slice(&0x0000_0201u32.to_le_bytes());
        pkt[12..16].copy_from_slice(&0u32.to_le_bytes());
        pkt[16..20].copy_from_slice(&79u32.to_le_bytes());
        let d = QrtrCtrlPkt::decode(&pkt).unwrap();
        assert_eq!(d.service, SVC_WDS);
        assert_eq!(d.version, 1);
        assert_eq!(d.instance, 2);
        assert_eq!(d.port, 79);

        assert!(matches!(QrtrCtrlPkt::decode(&[0u8; 10]), Err(QmiError::Malformed(_))));
    }

    #[test]
    fn bus_state_handles_lookup_and_ssr_recovery() {
        let mut st = BusState::new(2, 0);

        // End-of-lookup sentinel ignored
        let sentinel = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: 0,
            version: 0,
            instance: 0,
            node: 0,
            port: 0,
        };
        assert_eq!(apply_ctrl_pkt(&mut st, &sentinel, 100), None);
        assert!(st.modem_services.is_empty());

        // WDS & DMS appear on modem node 0, IPA on APSS node 2
        let wds = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: SVC_WDS,
            version: 1,
            instance: 0,
            node: 0,
            port: 79,
        };
        let dms = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: SVC_DMS,
            version: 1,
            instance: 0,
            node: 0,
            port: 93,
        };
        let apss_ipa = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: 0x31,
            version: 1,
            instance: 0,
            node: 2,
            port: 16390,
        };
        assert!(matches!(apply_ctrl_pkt(&mut st, &wds, 101), Some(QrtrBusEvent::ServiceAdded(_))));
        assert!(matches!(apply_ctrl_pkt(&mut st, &dms, 101), Some(QrtrBusEvent::ServiceAdded(_))));
        assert_eq!(apply_ctrl_pkt(&mut st, &apss_ipa, 101), None);
        assert_eq!(st.modem_services.len(), 2);
        assert_eq!(st.all_services.len(), 3);

        // BYE on modem node 0 clears modem services and counts SSR, leaving node 2 intact
        let bye = QrtrCtrlPkt {
            cmd: CMD_BYE,
            service: 0,
            version: 0,
            instance: 0,
            node: 0,
            port: 0,
        };
        assert!(matches!(apply_ctrl_pkt(&mut st, &bye, 200), Some(QrtrBusEvent::Ssr { node: 0, .. })));
        assert!(st.modem_services.is_empty());
        assert_eq!(st.all_services.len(), 1);
        assert_eq!(st.ssr_count, 1);
        assert_eq!(st.last_ssr_epoch, Some(200));

        // After SSR, NAS comes back + DEL_SERVER on tracked NAS counts second SSR
        let nas = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: SVC_NAS,
            version: 1,
            instance: 0,
            node: 0,
            port: 70,
        };
        apply_ctrl_pkt(&mut st, &nas, 210);
        let del_nas = QrtrCtrlPkt {
            cmd: CMD_DEL_SERVER,
            service: SVC_NAS,
            version: 1,
            instance: 0,
            node: 0,
            port: 70,
        };
        assert!(matches!(
            apply_ctrl_pkt(&mut st, &del_nas, 220),
            Some(QrtrBusEvent::Ssr { node: 0, .. })
        ));
        assert_eq!(st.ssr_count, 2);
    }

    #[test]
    fn ephemeral_bind_and_deferrable_errno_helpers() {
        let z = SockAddrQrtr {
            sq_family: AF_QIPCRTR as u16,
            _pad: 0,
            sq_node: 1,
            sq_port: 0,
        };
        assert!(needs_ephemeral_bind(z));
        let bound = SockAddrQrtr {
            sq_family: AF_QIPCRTR as u16,
            _pad: 0,
            sq_node: 1,
            sq_port: 16390,
        };
        assert!(!needs_ephemeral_bind(bound));

        assert!(is_deferrable_bind_errno(Some(libc::EINVAL)));
        assert!(is_deferrable_bind_errno(Some(libc::EADDRINUSE)));
        assert!(!is_deferrable_bind_errno(Some(libc::EACCES)));
        assert!(!is_deferrable_bind_errno(None));
    }

    #[test]
    fn bus_state_auto_detects_non_zero_modem_node_and_backfills() {
        let mut st = BusState::new_auto(2, 0);

        let apss_ipa = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: 0x31,
            version: 1,
            instance: 0,
            node: 2,
            port: 16390,
        };
        assert_eq!(apply_ctrl_pkt(&mut st, &apss_ipa, 100), None);
        assert!(!st.modem_node_pinned);
        assert_eq!(st.modem_node, 0);

        // Non-core service on node 3 before WDS arrives gets recorded and later backfilled.
        let earlier_node3 = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: 0x15,
            version: 1,
            instance: 0,
            node: 3,
            port: 8,
        };
        assert_eq!(apply_ctrl_pkt(&mut st, &earlier_node3, 101), None);
        assert!(!st.modem_node_pinned);

        let wds_node3 = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: SVC_WDS,
            version: 1,
            instance: 0,
            node: 3,
            port: 147,
        };
        assert!(matches!(
            apply_ctrl_pkt(&mut st, &wds_node3, 102),
            Some(QrtrBusEvent::ServiceAdded(ref ep)) if ep.service == SVC_WDS && ep.node == 3
        ));
        assert!(st.modem_node_pinned);
        assert_eq!(st.modem_node, 3);
        assert_eq!(st.modem_services.len(), 2);
        assert!(st.modem_services.contains_key(&0x15));
        assert!(st.modem_services.contains_key(&SVC_WDS));
        assert!(!st.modem_services.contains_key(&0x31));

        let bye = QrtrCtrlPkt {
            cmd: CMD_BYE,
            service: 0,
            version: 0,
            instance: 0,
            node: 3,
            port: 0,
        };
        assert!(matches!(
            apply_ctrl_pkt(&mut st, &bye, 200),
            Some(QrtrBusEvent::Ssr { node: 3, .. })
        ));
        assert!(st.modem_services.is_empty());
    }

    #[test]
    fn bus_state_auto_keeps_node_zero_when_core_services_are_on_zero() {
        let mut st = BusState::new_auto(2, 0);
        let wds_node0 = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: SVC_WDS,
            version: 1,
            instance: 0,
            node: 0,
            port: 79,
        };
        assert!(matches!(
            apply_ctrl_pkt(&mut st, &wds_node0, 100),
            Some(QrtrBusEvent::ServiceAdded(ref ep)) if ep.node == 0
        ));
        assert!(st.modem_node_pinned);
        assert_eq!(st.modem_node, 0);

        // Explicit pinned BusState::new(2, 0) stays on node 0 even if node 3 advertises SVC_WDS.
        let mut pinned = BusState::new(2, 0);
        let wds_node3 = QrtrCtrlPkt {
            cmd: CMD_NEW_SERVER,
            service: SVC_WDS,
            version: 1,
            instance: 0,
            node: 3,
            port: 147,
        };
        assert_eq!(apply_ctrl_pkt(&mut pinned, &wds_node3, 100), None);
        assert_eq!(pinned.modem_node, 0);
        assert!(pinned.modem_services.is_empty());
    }

    fn make_test_bus() -> (Arc<QrtrBus>, OwnedFd, tokio::task::JoinHandle<()>) {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        let local_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let peer_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let ctrl_fd = Arc::new(unsafe { AsyncFd::register(local_fd) }.unwrap());
        let state = Arc::new(Mutex::new(BusState::new(2, 0)));
        let (events_tx, _) = broadcast::channel(16);
        let bus = Arc::new(QrtrBus {
            ctrl_fd,
            state,
            events_tx,
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
        });
        let handle = bus.spawn_ctrl_loop();
        (bus, peer_fd, handle)
    }

    #[tokio::test]
    async fn qrtr_bus_drop_exits_ctrl_loop_and_releases_fd() {
        let (bus, _peer, handle) = make_test_bus();
        let ctrl_weak = Arc::downgrade(&bus.ctrl_fd);
        let bus_weak = Arc::downgrade(&bus);
        tokio::task::yield_now().await;
        assert!(!handle.is_finished());

        // Dropping the only external Arc<QrtrBus> must trigger Drop::shutdown(),
        // wake ctrl_loop out of qrtr_recv_from, finish the task, and release ctrl_fd.
        drop(bus);
        assert!(bus_weak.upgrade().is_none(), "ctrl_loop must not hold strong Arc<QrtrBus>");
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("ctrl_loop must exit promptly on QrtrBus drop")
            .unwrap();
        assert!(ctrl_weak.upgrade().is_none(), "ctrl_fd must be released when ctrl_loop exits");
    }

    #[tokio::test]
    async fn qrtr_bus_wait_for_service_wakes_on_service_added() {
        let (bus, _peer, handle) = make_test_bus();
        let bus2 = Arc::clone(&bus);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let pkt = QrtrCtrlPkt {
                cmd: CMD_NEW_SERVER,
                service: SVC_WDS,
                version: 1,
                instance: 0,
                node: 0,
                port: 79,
            };
            let ev = {
                let mut g = bus2.state.lock().unwrap();
                apply_ctrl_pkt(&mut g, &pkt, 100)
            };
            if let Some(ev) = ev {
                let _ = bus2.events_tx.send(ev);
            }
        });
        let ep = bus
            .wait_for_service(SVC_WDS, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(ep.service, SVC_WDS);
        assert_eq!(ep.port, 79);

        bus.shutdown();
        assert!(bus.is_shutdown());
        assert!(!bus.snapshot().available);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("ctrl_loop must exit on explicit shutdown()")
            .unwrap();
    }
}
