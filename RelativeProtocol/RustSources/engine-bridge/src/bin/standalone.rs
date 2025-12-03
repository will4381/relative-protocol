//! Async standalone runner for the Relative Protocol engine.
//!
//! Uses tokio for async I/O - eliminates thread-per-flow overhead and prevents thread leaks.
//! Architecture: tokio runtime manages all network I/O with ~4 OS threads regardless of flow count.

use engine_bridge::ffi::{BridgeCallbacks, BridgeConfig, BridgeHostRuleConfig, BridgeLogSink};
use engine_bridge::logger::{self, BreadcrumbFlags};
use engine_bridge::{
    BridgeEngineHandlePacket, BridgeEngineOnDialResult, BridgeEngineOnTcpClose,
    BridgeEngineOnTcpReceive, BridgeEngineOnUdpClose, BridgeEngineOnUdpReceive, BridgeEngineStart,
    BridgeEngineStop, BridgeFreeEngine, BridgeHostRuleAdd, BridgeNewEngine,
    BridgeSetBreadcrumbMask, BridgeSetLogSink,
};
use libc::{self, c_char, c_void};
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::ptr;
use std::slice;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd};

/// Firewall mark for outbound sockets to bypass TUN routing.
#[cfg(target_os = "linux")]
const BYPASS_FWMARK: u32 = 100;

/// Read buffer size for network I/O.
#[cfg(feature = "ios-memory-profile")]
const READ_BUFFER_SIZE: usize = 4 * 1024;
#[cfg(not(feature = "ios-memory-profile"))]
const READ_BUFFER_SIZE: usize = 65535;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("standalone runner currently supports only macOS and Linux");

#[derive(Clone, Copy)]
struct EngineHandle(*mut engine_bridge::BridgeEngine);

impl EngineHandle {
    fn as_ptr(self) -> *mut engine_bridge::BridgeEngine {
        self.0
    }
}

unsafe impl Send for EngineHandle {}
unsafe impl Sync for EngineHandle {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Settings::parse()?;
    eprintln!(
        "[standalone] launching Relative Protocol engine (mtu={}, utun={:?}, ifname={:?})",
        settings.mtu, settings.utun_index, settings.ifname
    );

    let tun = SystemTunDevice::connect(&settings)?;
    let interface_name = tun.name().to_string();

    #[cfg(target_os = "macos")]
    println!(
        "[standalone] created interface {}. Configure it (as root) via:\n  sudo ifconfig {} inet 10.0.0.2 10.0.0.1 up\n  sudo ifconfig {} inet6 fd00:1::2 prefixlen 64",
        interface_name, interface_name, interface_name
    );
    #[cfg(target_os = "linux")]
    println!(
        "[standalone] created interface {}. Configure it (as root) via:\n  sudo ip link set {} up\n  sudo ip addr add 10.0.0.2/24 dev {}\n  sudo ip -6 addr add fd00:1::2/64 dev {}",
        interface_name, interface_name, interface_name, interface_name
    );

    let (mut tun_reader, mut tun_writer) = tun.into_parts();
    // Large channel to prevent packet drops under heavy load.
    // emit_packets uses try_send which drops packets if channel is full.
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(8192);

    let config = BridgeConfig {
        mtu: settings.mtu,
        ..BridgeConfig::default()
    };
    let engine_ptr = unsafe { BridgeNewEngine(&config) };
    if engine_ptr.is_null() {
        anyhow::bail!("BridgeNewEngine returned null");
    }
    let engine = EngineHandle(engine_ptr);

    install_log_sink();
    BridgeSetBreadcrumbMask(u32::MAX);

    let state = Arc::new(StandaloneState::new(tun_tx.clone()));
    let context = Box::into_raw(Box::new(StandaloneContext {
        engine,
        state: Arc::clone(&state),
    }));

    let callbacks = BridgeCallbacks {
        emit_packets,
        request_tcp_dial,
        request_udp_dial,
        tcp_send,
        udp_send,
        tcp_close,
        udp_close,
        record_dns,
        context: context as *mut c_void,
    };

    let status = unsafe { BridgeEngineStart(engine.as_ptr(), &callbacks) };
    if status != 0 {
        unsafe {
            drop(Box::from_raw(context));
            BridgeFreeEngine(engine.as_ptr());
        }
        anyhow::bail!("BridgeEngineStart failed with status {}", status);
    }
    install_startup_rules(engine);

    // TUN reader thread (blocking I/O, separate OS thread)
    let reader_engine = engine;
    std::thread::Builder::new()
        .name("tun-reader".into())
        .spawn(move || tun_reader_loop(reader_engine, &mut tun_reader))
        .expect("failed to spawn tun reader");

    // TUN writer task (receives from channel, writes to TUN)
    std::thread::Builder::new()
        .name("tun-writer".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                while let Some(frame) = tun_rx.recv().await {
                    if frame.is_empty() {
                        continue;
                    }
                    if let Err(err) = write_tun_frame(&mut tun_writer, &frame) {
                        eprintln!("[standalone][tun writer] error: {err}");
                        break;
                    }
                }
            });
        })
        .expect("failed to spawn tun writer");

    println!("[standalone] engine running (async). Press Ctrl+C to terminate.");

    // Keep main alive
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}

#[derive(Debug)]
struct Settings {
    mtu: u32,
    utun_index: Option<u32>,
    ifname: Option<String>,
}

impl Settings {
    fn parse() -> anyhow::Result<Self> {
        let mut mtu = 1500;
        let mut utun_index = None;
        let mut ifname = None;
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--mtu" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--mtu requires a value"))?;
                    mtu = value.parse().map_err(|_| anyhow::anyhow!("invalid mtu"))?;
                }
                "--utun" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--utun requires a value"))?;
                    utun_index = Some(
                        value
                            .parse()
                            .map_err(|_| anyhow::anyhow!("invalid utun index"))?,
                    );
                }
                "--ifname" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--ifname requires a value"))?;
                    if value.is_empty() {
                        anyhow::bail!("--ifname requires a non-empty value");
                    }
                    ifname = Some(value);
                }
                _ => {
                    anyhow::bail!(
                        "unknown argument '{}'. Supported: --mtu <value>, --utun <index>, --ifname <name>",
                        arg
                    );
                }
            }
        }
        Ok(Self { mtu, utun_index, ifname })
    }
}

struct SystemTunDevice {
    reader: std::fs::File,
    writer: std::fs::File,
    name: String,
}

impl SystemTunDevice {
    #[cfg(target_os = "macos")]
    fn connect(settings: &Settings) -> io::Result<Self> {
        use std::mem::{size_of, zeroed};

        const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut info: libc::ctl_info = unsafe { zeroed() };
        for (idx, byte) in UTUN_CONTROL_NAME.iter().enumerate() {
            info.ctl_name[idx] = *byte as libc::c_char;
        }
        let ioctl_status = unsafe { libc::ioctl(owned.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
        if ioctl_status < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_ctl = unsafe { zeroed() };
        addr.sc_len = size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = settings.utun_index.map(|value| value + 1).unwrap_or(0);

        let connect_status = unsafe {
            libc::connect(
                owned.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_ctl>() as u32,
            )
        };
        if connect_status < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifname = [0u8; libc::IFNAMSIZ];
        let mut ifname_len = ifname.len() as u32;
        let opt_status = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut _,
                &mut ifname_len,
            )
        };
        if opt_status < 0 {
            return Err(io::Error::last_os_error());
        }

        let trimmed_len = if ifname_len == 0 { 0 } else { (ifname_len as usize).saturating_sub(1) };
        let name = String::from_utf8_lossy(&ifname[..trimmed_len]).into_owned();

        let reader_fd = owned.try_clone()?;
        let reader = std::fs::File::from(reader_fd);
        let writer = std::fs::File::from(owned);

        Ok(Self { reader, writer, name })
    }

    #[cfg(target_os = "linux")]
    fn connect(settings: &Settings) -> io::Result<Self> {
        use std::mem::zeroed;

        const TUN_DEVICE: &str = "/dev/net/tun";
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_DEVICE)?;
        let fd = file.as_raw_fd();

        let mut ifreq: libc::ifreq = unsafe { zeroed() };
        if let Some(name) = settings.ifname.as_deref() {
            for (idx, byte) in name.as_bytes().iter().enumerate() {
                if idx >= libc::IFNAMSIZ {
                    break;
                }
                ifreq.ifr_name[idx] = *byte as libc::c_char;
            }
        }
        ifreq.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        let status = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &ifreq) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }

        let name = unsafe {
            CStr::from_ptr(ifreq.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let reader = file.try_clone()?;
        Ok(Self { reader, writer: file, name })
    }

    fn into_parts(self) -> (std::fs::File, std::fs::File) {
        (self.reader, self.writer)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Shared state for async flow management.
/// Uses tokio Mutex for async-safe access and tokio channels for communication.
struct StandaloneState {
    tun_tx: mpsc::Sender<Vec<u8>>,
    tcp: Mutex<HashMap<u64, TcpFlowHandle>>,
    udp: Mutex<HashMap<u64, UdpFlowHandle>>,
}

/// Handle to a TCP flow - includes channel to send data and abort handle to cancel the task.
struct TcpFlowHandle {
    tx: mpsc::Sender<Vec<u8>>,
    abort_handle: tokio::task::AbortHandle,
}

/// Handle to a UDP flow - uses blocking I/O on dedicated threads (more reliable than tokio for UDP).
struct UdpFlowHandle {
    tx: std::sync::mpsc::Sender<Vec<u8>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl StandaloneState {
    fn new(tun_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tun_tx,
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
        }
    }

    async fn insert_tcp(&self, handle: u64, flow: TcpFlowHandle) {
        self.tcp.lock().await.insert(handle, flow);
    }

    async fn send_tcp(&self, handle: u64, payload: Vec<u8>) -> io::Result<()> {
        let map = self.tcp.lock().await;
        if let Some(flow) = map.get(&handle) {
            flow.tx
                .send(payload)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tcp channel closed"))
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "tcp handle missing"))
        }
    }

    async fn remove_tcp(&self, handle: u64) {
        if let Some(flow) = self.tcp.lock().await.remove(&handle) {
            flow.abort_handle.abort(); // Cancel the task
        }
    }

    fn insert_udp_sync(&self, handle: u64, flow: UdpFlowHandle) {
        // Use blocking_lock since this is called from std threads
        futures::executor::block_on(async {
            self.udp.lock().await.insert(handle, flow);
        });
    }

    fn send_udp_sync(&self, handle: u64, payload: Vec<u8>) -> io::Result<()> {
        // Use blocking approach since this is called from FFI context
        futures::executor::block_on(async {
            let map = self.udp.lock().await;
            if let Some(flow) = map.get(&handle) {
                flow.tx
                    .send(payload)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "udp channel closed"))
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound, "udp handle missing"))
            }
        })
    }

    fn remove_udp_sync(&self, handle: u64) {
        futures::executor::block_on(async {
            if let Some(flow) = self.udp.lock().await.remove(&handle) {
                flow.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }
}

struct StandaloneContext {
    engine: EngineHandle,
    state: Arc<StandaloneState>,
}

// ==================== FFI Callbacks ====================

unsafe extern "C" fn emit_packets(
    packets: *const *const u8,
    sizes: *const usize,
    _protocols: *const u32,
    count: usize,
    context: *mut c_void,
) {
    if packets.is_null() || sizes.is_null() || context.is_null() {
        return;
    }
    let packets = slice::from_raw_parts(packets, count);
    let sizes = slice::from_raw_parts(sizes, count);
    let ctx = &*(context as *mut StandaloneContext);
    for i in 0..count {
        if packets[i].is_null() || sizes[i] == 0 {
            continue;
        }
        let data = slice::from_raw_parts(packets[i], sizes[i]);
        let _ = ctx.state.tun_tx.try_send(data.to_vec());
    }
}

unsafe extern "C" fn request_tcp_dial(
    host: *const c_char,
    port: u16,
    handle: u64,
    context: *mut c_void,
) {
    if host.is_null() || context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    let host_str = CStr::from_ptr(host).to_string_lossy().into_owned();
    let state = Arc::clone(&ctx.state);
    let engine = ctx.engine;

    flow_trace(format!("[standalone][dial] handle {handle} resolving {host_str}:{port}"));

    // Spawn async task for TCP connection
    tokio::spawn(async move {
        match resolve_and_connect_tcp(&host_str, port).await {
            Ok(stream) => {
                flow_trace(format!("[standalone][dial] handle {handle} connected"));
                start_tcp_flow(state, engine, handle, stream).await;
            }
            Err(err) => {
                logger::warn(format!("[standalone][dial] handle {handle} error: {err}"));
                report_dial_failure(engine, handle, err);
            }
        }
    });
}

unsafe extern "C" fn request_udp_dial(
    host: *const c_char,
    port: u16,
    handle: u64,
    context: *mut c_void,
) {
    if host.is_null() || context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    let host_str = CStr::from_ptr(host).to_string_lossy().into_owned();
    let state = Arc::clone(&ctx.state);
    let engine = ctx.engine;

    flow_trace(format!("[standalone][udp dial] handle {handle} resolving {host_str}:{port}"));

    // Spawn std thread for UDP connection (blocking I/O is more reliable for UDP)
    std::thread::Builder::new()
        .name(format!("udp-dial-{}", handle))
        .spawn(move || {
            match resolve_and_connect_udp_blocking(&host_str, port) {
                Ok(socket) => {
                    flow_trace(format!("[standalone][udp dial] handle {handle} connected"));
                    start_udp_flow_blocking(state, engine, handle, socket);
                }
                Err(err) => {
                    logger::warn(format!("[standalone][udp dial] handle {handle} error: {err}"));
                    report_dial_failure(engine, handle, err);
                }
            }
        })
        .expect("failed to spawn UDP dial thread");
}

unsafe extern "C" fn tcp_send(
    handle: u64,
    payload: *const u8,
    length: usize,
    context: *mut c_void,
) {
    if payload.is_null() || length == 0 || context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    let data = slice::from_raw_parts(payload, length).to_vec();
    let state = Arc::clone(&ctx.state);

    // Fire-and-forget send via channel
    tokio::spawn(async move {
        if let Err(err) = state.send_tcp(handle, data).await {
            logger::warn(format!("[standalone][tcp_send] handle {handle} error: {err}"));
        }
    });
}

unsafe extern "C" fn udp_send(
    handle: u64,
    payload: *const u8,
    length: usize,
    context: *mut c_void,
) {
    if payload.is_null() || length == 0 || context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    let data = slice::from_raw_parts(payload, length).to_vec();

    // Use sync method directly - no need to spawn tokio task for UDP
    if let Err(err) = ctx.state.send_udp_sync(handle, data) {
        eprintln!("[standalone][udp_send] handle {handle} error: {err}");
    }
}

unsafe extern "C" fn tcp_close(handle: u64, _message: *const c_char, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    let state = Arc::clone(&ctx.state);

    tokio::spawn(async move {
        state.remove_tcp(handle).await;
    });
}

unsafe extern "C" fn udp_close(handle: u64, _message: *const c_char, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);

    // Use sync method directly - no need to spawn tokio task for UDP
    ctx.state.remove_udp_sync(handle);
}

unsafe extern "C" fn record_dns(
    host: *const c_char,
    addresses: *const *const c_char,
    count: usize,
    _ttl_seconds: u32,
    _context: *mut c_void,
) {
    if host.is_null() {
        return;
    }
    let host_str = CStr::from_ptr(host).to_string_lossy();
    let addrs = if addresses.is_null() || count == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(addresses, count)
            .iter()
            .filter_map(|ptr| {
                if ptr.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(*ptr).to_string_lossy().into_owned())
                }
            })
            .collect::<Vec<_>>()
    };
    if addrs.is_empty() {
        println!("[standalone][dns] {host_str}: <empty>");
    } else {
        println!("[standalone][dns] {host_str} -> {}", addrs.join(", "));
    }
}

// ==================== Async Network Functions ====================

async fn resolve_and_connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    use tokio::net::lookup_host;

    let addr = lookup_host(format!("{}:{}", host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses"))?;

    #[cfg(target_os = "linux")]
    {
        // Create socket with SO_MARK before connecting
        let socket = create_marked_tcp_socket(&addr)?;
        socket.connect(addr).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        TcpStream::connect(addr).await
    }
}

#[cfg(target_os = "linux")]
fn create_marked_tcp_socket(addr: &SocketAddr) -> io::Result<tokio::net::TcpSocket> {
    use std::os::fd::FromRawFd;

    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Set SO_MARK
    let mark = BYPASS_FWMARK;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    let std_socket = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    std_socket.set_nonblocking(true)?;

    // Convert to tokio socket
    let socket = tokio::net::TcpSocket::from_std_stream(std_socket);
    Ok(socket)
}

async fn resolve_and_connect_udp(host: &str, port: u16) -> io::Result<UdpSocket> {
    use tokio::net::lookup_host;

    let addr = lookup_host(format!("{}:{}", host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses"))?;

    let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    #[cfg(target_os = "linux")]
    let socket = {
        let std_socket = create_marked_udp_socket(&addr)?;
        UdpSocket::from_std(std_socket)?
    };

    #[cfg(not(target_os = "linux"))]
    let socket = UdpSocket::bind(bind_addr).await?;

    socket.connect(addr).await?;
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn create_marked_udp_socket(addr: &SocketAddr) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::FromRawFd;

    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Set SO_MARK
    let mark = BYPASS_FWMARK;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Bind to any address
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let sockaddr = match bind_addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &sin as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(_) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::bind(
                    fd,
                    &sin6 as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };

    if sockaddr < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
}

fn report_dial_failure(engine: EngineHandle, handle: u64, err: io::Error) {
    let reason = CString::new(err.to_string()).unwrap_or_default();
    unsafe {
        BridgeEngineOnDialResult(engine.as_ptr(), handle, false, reason.as_ptr());
    }
}

// ==================== Flow Task Management ====================

/// Start a TCP flow task that handles both reading and writing using select!.
/// Single task per flow - no separate reader/writer threads.
async fn start_tcp_flow(
    state: Arc<StandaloneState>,
    engine: EngineHandle,
    handle: u64,
    stream: TcpStream,
) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    // Spawn the flow task
    let task = tokio::spawn(async move {
        let (mut reader, mut writer) = stream.into_split();
        let mut buf = vec![0u8; READ_BUFFER_SIZE];

        loop {
            tokio::select! {
                // Handle incoming data from network
                result = reader.read(&mut buf) => {
                    match result {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            unsafe {
                                BridgeEngineOnTcpReceive(engine.as_ptr(), handle, buf.as_ptr(), n);
                            }
                        }
                        Err(err) => {
                            logger::warn(format!("[tcp flow {handle}] read error: {err}"));
                            break;
                        }
                    }
                }

                // Handle outgoing data from engine
                msg = rx.recv() => {
                    match msg {
                        Some(data) if !data.is_empty() => {
                            if let Err(err) = writer.write_all(&data).await {
                                logger::warn(format!("[tcp flow {handle}] write error: {err}"));
                                break;
                            }
                        }
                        _ => break, // Channel closed or empty signal
                    }
                }
            }
        }

        // Notify engine of close
        unsafe {
            BridgeEngineOnTcpClose(engine.as_ptr(), handle);
        }
    });

    // CRITICAL: Store the flow handle BEFORE signaling dial success.
    // This prevents a race condition where the engine sends data before the handle is registered.
    state.insert_tcp(handle, TcpFlowHandle {
        tx,
        abort_handle: task.abort_handle(),
    }).await;

    // Now signal dial success - the handle is ready to receive data
    unsafe {
        BridgeEngineOnDialResult(engine.as_ptr(), handle, true, ptr::null());
    }
}

/// Blocking DNS resolution and UDP socket creation.
/// More reliable than tokio async for UDP when called from FFI context.
fn resolve_and_connect_udp_blocking(host: &str, port: u16) -> io::Result<std::net::UdpSocket> {
    use std::net::ToSocketAddrs;

    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses"))?;

    let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    #[cfg(target_os = "linux")]
    let socket = {
        create_marked_udp_socket(&addr)?
    };

    #[cfg(not(target_os = "linux"))]
    let socket = std::net::UdpSocket::bind(bind_addr)?;

    socket.connect(addr)?;
    Ok(socket)
}

/// Start a UDP flow using blocking I/O on dedicated threads.
/// This is more reliable than tokio async for UDP when called from FFI context.
fn start_udp_flow_blocking(
    state: Arc<StandaloneState>,
    engine: EngineHandle,
    handle: u64,
    socket: std::net::UdpSocket,
) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Set socket timeout for graceful shutdown
    socket.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let socket = Arc::new(socket);
    let read_socket = Arc::clone(&socket);
    let write_socket = Arc::clone(&socket);
    let shutdown_reader = Arc::clone(&shutdown);

    // Spawn reader thread
    let reader_handle = handle;
    std::thread::Builder::new()
        .name(format!("udp-read-{}", handle))
        .spawn(move || {
            let mut buf = vec![0u8; READ_BUFFER_SIZE];
            loop {
                if shutdown_reader.load(Ordering::SeqCst) {
                    break;
                }
                match read_socket.recv(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => {
                        unsafe {
                            BridgeEngineOnUdpReceive(engine.as_ptr(), reader_handle, buf.as_ptr(), n);
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                        // Timeout - check shutdown flag and continue
                        continue;
                    }
                    Err(err) => {
                        if !shutdown_reader.load(Ordering::SeqCst) {
                            eprintln!("[udp flow {reader_handle}] read error: {err}");
                        }
                        break;
                    }
                }
            }
            // Notify engine of close
            unsafe {
                BridgeEngineOnUdpClose(engine.as_ptr(), reader_handle);
            }
        })
        .expect("failed to spawn UDP reader");

    // Spawn writer thread
    let writer_handle = handle;
    let shutdown_writer = Arc::clone(&shutdown);
    std::thread::Builder::new()
        .name(format!("udp-write-{}", handle))
        .spawn(move || {
            loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(data) if !data.is_empty() => {
                        if let Err(err) = write_socket.send(&data) {
                            if !shutdown_writer.load(Ordering::SeqCst) {
                                eprintln!("[udp flow {writer_handle}] write error: {err}");
                            }
                            break;
                        }
                    }
                    Ok(_) => continue, // Empty data, continue
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if shutdown_writer.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn UDP writer");

    // CRITICAL: Store the flow handle BEFORE signaling dial success.
    // This prevents a race condition where the engine sends data before the handle is registered.
    // This is especially important for QUIC (used by TikTok) which sends data immediately.
    state.insert_udp_sync(handle, UdpFlowHandle { tx, shutdown });

    // Now signal dial success - the handle is ready to receive data
    unsafe {
        BridgeEngineOnDialResult(engine.as_ptr(), handle, true, ptr::null());
    }
}

// ==================== TUN I/O ====================

fn tun_reader_loop(engine: EngineHandle, reader: &mut std::fs::File) {
    let tun_buf_size = READ_BUFFER_SIZE.max(1600);
    let mut buf = vec![0u8; tun_buf_size];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => continue,
            Ok(n) => {
                if let Some((proto, payload)) = parse_tun_frame(&buf[..n]) {
                    unsafe {
                        BridgeEngineHandlePacket(
                            engine.as_ptr(),
                            payload.as_ptr(),
                            payload.len(),
                            proto,
                        );
                    }
                }
            }
            Err(err) => {
                eprintln!("[standalone][tun reader] error: {err}");
                break;
            }
        }
    }
}

fn infer_protocol(frame: &[u8]) -> u32 {
    if let Some(first) = frame.first() {
        match first >> 4 {
            6 => libc::AF_INET6 as u32,
            _ => libc::AF_INET as u32,
        }
    } else {
        libc::AF_INET as u32
    }
}

#[cfg(target_os = "macos")]
fn parse_tun_frame(buffer: &[u8]) -> Option<(u32, &[u8])> {
    if buffer.len() <= 4 {
        return None;
    }
    let proto = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    Some((proto, &buffer[4..]))
}

#[cfg(target_os = "linux")]
fn parse_tun_frame(buffer: &[u8]) -> Option<(u32, &[u8])> {
    if buffer.is_empty() {
        None
    } else {
        let proto = infer_protocol(buffer);
        Some((proto, buffer))
    }
}

#[cfg(target_os = "macos")]
fn write_tun_frame(writer: &mut std::fs::File, frame: &[u8]) -> io::Result<()> {
    let proto = infer_protocol(frame);
    let mut packet = Vec::with_capacity(frame.len() + 4);
    packet.extend_from_slice(&proto.to_be_bytes());
    packet.extend_from_slice(frame);
    writer.write_all(&packet)
}

#[cfg(target_os = "linux")]
fn write_tun_frame(writer: &mut std::fs::File, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame)
}

// ==================== Logging & Rules ====================

fn install_log_sink() {
    unsafe extern "C" fn log_sink(
        level: *const c_char,
        message: *const c_char,
        _breadcrumbs: u32,
        _context: *mut c_void,
    ) {
        if message.is_null() {
            return;
        }
        let entry = CStr::from_ptr(message).to_string_lossy();
        let level = if level.is_null() {
            "info".into()
        } else {
            CStr::from_ptr(level).to_string_lossy()
        };
        println!("[engine][{level}] {entry}");
    }

    let sink = BridgeLogSink {
        log: Some(log_sink),
        context: ptr::null_mut(),
        enabled_breadcrumbs: u32::MAX,
    };
    let level = CString::new("debug").unwrap();
    unsafe {
        BridgeSetLogSink(&sink, level.as_ptr(), ptr::null_mut());
    }
}

fn install_startup_rules(engine: EngineHandle) {
    let Ok(spec) = env::var("HOST_RULES") else { return };
    let spec = spec.trim();
    if spec.is_empty() {
        return;
    }
    for raw_rule in spec.split(';') {
        let entry = raw_rule.trim();
        if entry.is_empty() {
            continue;
        }
        match parse_rule(entry) {
            Ok(rule) => {
                let pattern_cstr = match CString::new(rule.pattern.clone()) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let mut id: u64 = 0;
                let config = BridgeHostRuleConfig {
                    pattern: pattern_cstr.as_ptr(),
                    block: matches!(rule.action, RuleActionSpec::Block),
                    latency_ms: match rule.action {
                        RuleActionSpec::Shape { latency_ms, .. } => latency_ms,
                        _ => 0,
                    },
                    jitter_ms: match rule.action {
                        RuleActionSpec::Shape { jitter_ms, .. } => jitter_ms,
                        _ => 0,
                    },
                };
                let ok = unsafe { BridgeHostRuleAdd(engine.as_ptr(), &config, &mut id as *mut u64) };
                if ok {
                    println!("[standalone] installed rule #{id}: {}", rule.pattern);
                }
            }
            Err(err) => eprintln!("[standalone] {err}"),
        }
    }
}

struct ParsedRule {
    pattern: String,
    action: RuleActionSpec,
}

enum RuleActionSpec {
    Block,
    Shape { latency_ms: u32, jitter_ms: u32 },
}

fn parse_rule(input: &str) -> Result<ParsedRule, String> {
    let mut parts = input.split(':').map(str::trim);
    let pattern = parts
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| format!("rule '{}' missing pattern", input))?
        .to_ascii_lowercase();
    let action = parts
        .next()
        .map(|v| v.to_ascii_lowercase())
        .ok_or_else(|| format!("rule '{}' missing action", input))?;
    let action_spec = match action.as_str() {
        "block" => RuleActionSpec::Block,
        "shape" => {
            let latency_str = parts.next().ok_or_else(|| format!("missing latency"))?;
            let latency_ms = latency_str.parse().map_err(|_| format!("invalid latency"))?;
            let jitter_ms = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            RuleActionSpec::Shape { latency_ms, jitter_ms }
        }
        _ => return Err(format!("unknown action '{}'", action)),
    };
    Ok(ParsedRule { pattern, action: action_spec })
}

fn flow_trace(message: impl Into<String>) {
    logger::breadcrumb(BreadcrumbFlags::FLOW, message.into());
}
