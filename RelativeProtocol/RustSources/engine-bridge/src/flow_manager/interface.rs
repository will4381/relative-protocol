use super::state::{SocketBudget, UDP_PACKET_METADATA};
use super::*;

/// Build the network interface with an empty socket set.
/// Sockets are allocated dynamically as flows are admitted.
pub(super) fn build_interface(mut device: TunDevice) -> (TunDevice, Interface, SocketSet<'static>) {
    let ipv4_addr = Ipv4Address::new(10, 0, 0, 1);
    let ipv6_addr = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = 0;
    let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
    interface.set_any_ip(true);
    interface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv4(ipv4_addr), 24));
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv6(ipv6_addr), 64));
    });
    {
        let routes = interface.routes_mut();
        routes.add_default_ipv4_route(ipv4_addr).ok();
        routes.add_default_ipv6_route(ipv6_addr).ok();
    }

    let sockets = SocketSet::new(Vec::new());
    (device, interface, sockets)
}

/// Allocate a new TCP socket with the given buffer sizes.
pub(super) fn allocate_tcp_socket(
    sockets: &mut SocketSet<'static>,
    budget: &SocketBudget,
) -> SocketHandle {
    let socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0; budget.tcp_rx_buffer_size]),
        TcpSocketBuffer::new(vec![0; budget.tcp_tx_buffer_size]),
    );
    sockets.add(socket)
}

/// Allocate a new UDP socket with the given buffer size.
pub(super) fn allocate_udp_socket(
    sockets: &mut SocketSet<'static>,
    budget: &SocketBudget,
) -> SocketHandle {
    let rx_meta = vec![PacketMetadata::EMPTY; UDP_PACKET_METADATA];
    let tx_meta = vec![PacketMetadata::EMPTY; UDP_PACKET_METADATA];
    let socket = UdpSocket::new(
        PacketBuffer::new(rx_meta, vec![0; budget.udp_buffer_size]),
        PacketBuffer::new(tx_meta, vec![0; budget.udp_buffer_size]),
    );
    sockets.add(socket)
}

// Thread-local buffers for emit_frames to avoid repeated allocations
thread_local! {
    static EMIT_PTRS: std::cell::RefCell<Vec<*const u8>> = std::cell::RefCell::new(Vec::with_capacity(64));
    static EMIT_SIZES: std::cell::RefCell<Vec<usize>> = std::cell::RefCell::new(Vec::with_capacity(64));
    static EMIT_PROTOCOLS: std::cell::RefCell<Vec<u32>> = std::cell::RefCell::new(Vec::with_capacity(64));
}

pub(super) fn emit_frames(callbacks: BridgeCallbacks, frames: Vec<Vec<u8>>) {
    if frames.is_empty() {
        return;
    }

    EMIT_PTRS.with(|ptrs| {
        EMIT_SIZES.with(|sizes| {
            EMIT_PROTOCOLS.with(|protocols| {
                let mut ptrs = ptrs.borrow_mut();
                let mut sizes = sizes.borrow_mut();
                let mut protocols = protocols.borrow_mut();

                ptrs.clear();
                sizes.clear();
                protocols.clear();

                for frame in &frames {
                    ptrs.push(frame.as_ptr());
                    sizes.push(frame.len());
                    protocols.push(protocol_number(frame));
                }

                unsafe {
                    (callbacks.emit_packets)(
                        ptrs.as_ptr(),
                        sizes.as_ptr(),
                        protocols.as_ptr(),
                        ptrs.len(),
                        callbacks.context,
                    );
                }
            });
        });
    });
}

fn protocol_number(frame: &[u8]) -> u32 {
    if frame.first().map(|byte| (byte >> 4) == 6).unwrap_or(false) {
        AF_INET6 as u32
    } else {
        AF_INET as u32
    }
}
