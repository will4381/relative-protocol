use engine_bridge::ffi::{BridgeCallbacks, BridgeConfig, BridgeLogSink};
use engine_bridge::{
    BridgeEngineHandlePacket, BridgeEngineOnDialResult, BridgeEngineOnTcpClose,
    BridgeEngineOnTcpReceive, BridgeEngineOnUdpClose, BridgeEngineOnUdpReceive, BridgeEngineStart,
    BridgeEngineStop, BridgeFreeEngine, BridgeNewEngine, BridgeSetBreadcrumbMask, BridgeSetLogSink,
};
use libc::{self, c_char, c_void};
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::slice;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy)]
struct EngineHandle(*mut engine_bridge::BridgeEngine);

impl EngineHandle {
    fn as_ptr(self) -> *mut engine_bridge::BridgeEngine {
        self.0
    }
}

unsafe impl Send for EngineHandle {}
unsafe impl Sync for EngineHandle {}

fn main() -> anyhow::Result<()> {
    let settings = Settings::parse()?;
    eprintln!(
        "[standalone] launching Relative Protocol engine (mtu={}, utun={:?})",
        settings.mtu, settings.utun_index
    );

    let utun = UtunDevice::connect(settings.utun_index)?;
    println!(
        "[standalone] created interface {}. Configure it (as root) via:\n  sudo ifconfig {} inet 10.0.0.2 10.0.0.1 up\n  sudo ifconfig {} inet6 fd00:1::2 prefixlen 64\nthen add the routes you want to steer through this interface.",
        utun.name(),
        utun.name(),
        utun.name()
    );

    let (mut tun_reader, mut tun_writer) = utun.into_parts();
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();

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
    unsafe {
        BridgeSetBreadcrumbMask(u32::MAX);
    }

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

    let reader_engine = engine;
    let reader_handle = thread::Builder::new()
        .name("tun-reader".into())
        .spawn(move || tun_reader_loop(reader_engine, &mut tun_reader))
        .expect("failed to spawn tun reader");

    let writer_handle = thread::Builder::new()
        .name("tun-writer".into())
        .spawn(move || tun_writer_loop(&mut tun_writer, tun_rx))
        .expect("failed to spawn tun writer");

    println!("[standalone] engine running. Press Ctrl+C to terminate.");
    loop {
        thread::sleep(Duration::from_secs(5));
    }

    // NOTE: unreachable under normal operation because the process is expected to be
    // terminated by the user (Ctrl+C). The following cleanup is left here for
    // completeness should we decide to add graceful shutdown logic later.
    #[allow(unreachable_code)]
    {
        unsafe {
            BridgeEngineStop(engine.as_ptr());
            drop(Box::from_raw(context));
            BridgeFreeEngine(engine.as_ptr());
        }
        let _ = reader_handle.join();
        let _ = writer_handle.join();
        Ok(())
    }
}

#[derive(Debug)]
struct Settings {
    mtu: u32,
    utun_index: Option<u32>,
}

impl Settings {
    fn parse() -> anyhow::Result<Self> {
        let mut mtu = 1500;
        let mut utun_index = None;
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
                _ => {
                    anyhow::bail!(
                        "unknown argument '{}'. Supported flags: --mtu <value>, --utun <index>",
                        arg
                    );
                }
            }
        }
        Ok(Self { mtu, utun_index })
    }
}

struct UtunDevice {
    reader: std::fs::File,
    writer: std::fs::File,
    name: String,
}

impl UtunDevice {
    fn connect(unit: Option<u32>) -> io::Result<Self> {
        #[cfg(not(target_os = "macos"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "standalone runner currently supports only macOS",
            ));
        }

        #[cfg(target_os = "macos")]
        {
            use std::mem::{size_of, zeroed};

            const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
            let fd =
                unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };

            let mut info: libc::ctl_info = unsafe { zeroed() };
            for (idx, byte) in UTUN_CONTROL_NAME.iter().enumerate() {
                info.ctl_name[idx] = *byte as libc::c_char;
            }
            let ioctl_status =
                unsafe { libc::ioctl(owned.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
            if ioctl_status < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut addr: libc::sockaddr_ctl = unsafe { zeroed() };
            addr.sc_len = size_of::<libc::sockaddr_ctl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = unit.map(|value| value + 1).unwrap_or(0);

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

            let trimmed_len = if ifname_len == 0 {
                0
            } else {
                (ifname_len as usize).saturating_sub(1)
            };
            let name = String::from_utf8_lossy(&ifname[..trimmed_len]).into_owned();

            let reader_fd = owned.try_clone()?;
            let reader = std::fs::File::from(reader_fd);
            let writer = std::fs::File::from(owned);

            Ok(Self {
                reader,
                writer,
                name,
            })
        }
    }

    fn into_parts(self) -> (std::fs::File, std::fs::File) {
        (self.reader, self.writer)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

struct StandaloneState {
    tun_tx: mpsc::Sender<Vec<u8>>,
    tcp: Mutex<HashMap<u64, TcpEntry>>,
    udp: Mutex<HashMap<u64, UdpEntry>>,
}

impl StandaloneState {
    fn new(tun_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tun_tx,
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
        }
    }

    fn insert_tcp(&self, handle: u64, entry: TcpEntry) {
        self.tcp.lock().unwrap().insert(handle, entry);
    }

    fn send_tcp(&self, handle: u64, payload: &[u8]) -> io::Result<()> {
        let map = self.tcp.lock().unwrap();
        if let Some(entry) = map.get(&handle) {
            entry
                .tx
                .send(payload.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tcp channel closed"))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "tcp handle missing",
            ))
        }
    }

    fn remove_tcp(&self, handle: u64) {
        self.tcp.lock().unwrap().remove(&handle);
    }

    fn insert_udp(&self, handle: u64, entry: UdpEntry) {
        self.udp.lock().unwrap().insert(handle, entry);
    }

    fn send_udp(&self, handle: u64, payload: &[u8]) -> io::Result<()> {
        let map = self.udp.lock().unwrap();
        if let Some(entry) = map.get(&handle) {
            entry
                .tx
                .send(payload.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "udp channel closed"))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "udp handle missing",
            ))
        }
    }

    fn remove_udp(&self, handle: u64) {
        self.udp.lock().unwrap().remove(&handle);
    }
}

struct TcpEntry {
    tx: mpsc::Sender<Vec<u8>>,
}

struct UdpEntry {
    tx: mpsc::Sender<Vec<u8>>,
}

struct StandaloneContext {
    engine: EngineHandle,
    state: Arc<StandaloneState>,
}

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
        let _ = ctx.state.tun_tx.send(data.to_vec());
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
    thread::spawn(move || match resolve_target(&host_str, port) {
        Ok(addr) => match TcpStream::connect(addr) {
            Ok(stream) => {
                if let Err(err) = stream.set_nodelay(true) {
                    report_tcp_failure(engine, handle, err);
                    return;
                }
                start_tcp_workers(state, engine, handle, stream);
            }
            Err(err) => {
                report_tcp_failure(engine, handle, err);
            }
        },
        Err(err) => {
            report_tcp_failure(engine, handle, err);
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
    thread::spawn(move || match resolve_target(&host_str, port) {
        Ok(addr) => match bind_udp(&addr) {
            Ok(socket) => {
                if let Err(err) = socket.connect(addr) {
                    report_tcp_failure(engine, handle, err);
                    return;
                }
                start_udp_workers(state, engine, handle, socket);
            }
            Err(err) => {
                report_tcp_failure(engine, handle, err);
            }
        },
        Err(err) => {
            report_tcp_failure(engine, handle, err);
        }
    });
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
    let data = slice::from_raw_parts(payload, length);
    if let Err(err) = ctx.state.send_tcp(handle, data) {
        eprintln!("[standalone][tcp_send] handle {handle} send error: {err}");
    }
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
    let data = slice::from_raw_parts(payload, length);
    if let Err(err) = ctx.state.send_udp(handle, data) {
        eprintln!("[standalone][udp_send] handle {handle} send error: {err}");
    }
}

unsafe extern "C" fn tcp_close(handle: u64, _message: *const c_char, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    ctx.state.remove_tcp(handle);
}

unsafe extern "C" fn udp_close(handle: u64, _message: *const c_char, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *mut StandaloneContext);
    ctx.state.remove_udp(handle);
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

fn resolve_target(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses"))
}

fn bind_udp(addr: &SocketAddr) -> io::Result<UdpSocket> {
    match addr {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0"),
    }
}

fn report_tcp_failure(engine: EngineHandle, handle: u64, err: io::Error) {
    let reason = CString::new(err.to_string()).unwrap_or_default();
    unsafe {
        BridgeEngineOnDialResult(engine.as_ptr(), handle, false, reason.as_ptr());
    }
}

fn start_tcp_workers(
    state: Arc<StandaloneState>,
    engine: EngineHandle,
    handle: u64,
    stream: TcpStream,
) {
    let reader = match stream.try_clone() {
        Ok(reader) => reader,
        Err(err) => {
            report_tcp_failure(engine, handle, err);
            return;
        }
    };
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    state.insert_tcp(handle, TcpEntry { tx: tx.clone() });
    unsafe {
        BridgeEngineOnDialResult(engine.as_ptr(), handle, true, ptr::null());
    }

    let writer_engine = engine;
    thread::spawn(move || {
        let mut writer = stream;
        while let Ok(payload) = rx.recv() {
            if payload.is_empty() {
                break;
            }
            if let Err(err) = writer.write_all(&payload) {
                eprintln!("[standalone][tcp writer] handle {handle} error: {err}");
                break;
            }
        }
        let _ = writer.shutdown(std::net::Shutdown::Both);
        unsafe {
            BridgeEngineOnTcpClose(writer_engine.as_ptr(), handle);
        }
    });

    let reader_state = Arc::clone(&state);
    thread::spawn(move || {
        let mut reader = reader;
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => unsafe {
                    BridgeEngineOnTcpReceive(engine.as_ptr(), handle, buf.as_ptr(), n);
                },
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    eprintln!("[standalone][tcp reader] handle {handle} error: {err}");
                    break;
                }
            }
        }
        reader_state.remove_tcp(handle);
        unsafe {
            BridgeEngineOnTcpClose(engine.as_ptr(), handle);
        }
    });
}

fn start_udp_workers(
    state: Arc<StandaloneState>,
    engine: EngineHandle,
    handle: u64,
    socket: UdpSocket,
) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    state.insert_udp(handle, UdpEntry { tx: tx.clone() });
    unsafe {
        BridgeEngineOnDialResult(engine.as_ptr(), handle, true, ptr::null());
    }

    let writer_socket = match socket.try_clone() {
        Ok(sock) => sock,
        Err(err) => {
            report_tcp_failure(engine, handle, err);
            return;
        }
    };
    thread::spawn(move || {
        let mut sock = writer_socket;
        while let Ok(payload) = rx.recv() {
            if payload.is_empty() {
                break;
            }
            if let Err(err) = sock.send(&payload) {
                eprintln!("[standalone][udp writer] handle {handle} error: {err}");
                break;
            }
        }
    });

    let reader_state = Arc::clone(&state);
    thread::spawn(move || {
        let mut sock = socket;
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv(&mut buf) {
                Ok(0) => continue,
                Ok(n) => unsafe {
                    BridgeEngineOnUdpReceive(engine.as_ptr(), handle, buf.as_ptr(), n);
                },
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    eprintln!("[standalone][udp reader] handle {handle} error: {err}");
                    break;
                }
            }
        }
        reader_state.remove_udp(handle);
        unsafe {
            BridgeEngineOnUdpClose(engine.as_ptr(), handle);
        }
    });
}

fn tun_reader_loop(engine: EngineHandle, reader: &mut std::fs::File) {
    let mut buf = vec![0u8; 65540];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => continue,
            Ok(n) if n > 4 => {
                let proto = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let payload = &buf[4..n];
                unsafe {
                    BridgeEngineHandlePacket(
                        engine.as_ptr(),
                        payload.as_ptr(),
                        payload.len(),
                        proto,
                    );
                }
            }
            Ok(_) => continue,
            Err(err) => {
                eprintln!("[standalone][tun reader] error: {err}");
                break;
            }
        }
    }
}

fn tun_writer_loop(writer: &mut std::fs::File, rx: mpsc::Receiver<Vec<u8>>) {
    loop {
        match rx.recv() {
            Ok(frame) => {
                if frame.is_empty() {
                    continue;
                }
                let proto = infer_protocol(&frame);
                let mut packet = Vec::with_capacity(frame.len() + 4);
                packet.extend_from_slice(&proto.to_be_bytes());
                packet.extend_from_slice(&frame);
                if let Err(err) = writer.write_all(&packet) {
                    eprintln!("[standalone][tun writer] error: {err}");
                    break;
                }
            }
            Err(_) => break,
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
