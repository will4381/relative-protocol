use super::state::{
    TCP_RX_BUFFER_SIZE, TCP_SOCKET_COUNT, TCP_TX_BUFFER_SIZE, UDP_BUFFER_SIZE, UDP_PACKET_METADATA,
    UDP_SOCKET_COUNT,
};
use super::*;

pub(super) fn build_interface_and_sockets(
    mut device: TunDevice,
) -> (
    TunDevice,
    Interface,
    SocketSet<'static>,
    Vec<SocketHandle>,
    Vec<SocketHandle>,
) {
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

    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_pool = Vec::with_capacity(TCP_SOCKET_COUNT);
    for _ in 0..TCP_SOCKET_COUNT {
        let socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0; TCP_RX_BUFFER_SIZE]),
            TcpSocketBuffer::new(vec![0; TCP_TX_BUFFER_SIZE]),
        );
        let handle = sockets.add(socket);
        tcp_pool.push(handle);
    }

    let mut udp_pool = Vec::with_capacity(UDP_SOCKET_COUNT);
    for _ in 0..UDP_SOCKET_COUNT {
        let rx_meta = vec![PacketMetadata::EMPTY; UDP_PACKET_METADATA];
        let tx_meta = vec![PacketMetadata::EMPTY; UDP_PACKET_METADATA];
        let socket = UdpSocket::new(
            PacketBuffer::new(rx_meta, vec![0; UDP_BUFFER_SIZE]),
            PacketBuffer::new(tx_meta, vec![0; UDP_BUFFER_SIZE]),
        );
        let handle = sockets.add(socket);
        udp_pool.push(handle);
    }

    (device, interface, sockets, tcp_pool, udp_pool)
}

pub(super) fn emit_frames(callbacks: BridgeCallbacks, frames: Vec<Vec<u8>>) {
    if frames.is_empty() {
        return;
    }
    let mut packet_ptrs: Vec<*const u8> = Vec::with_capacity(frames.len());
    let mut sizes: Vec<usize> = Vec::with_capacity(frames.len());
    let mut protocols: Vec<u32> = Vec::with_capacity(frames.len());
    for frame in &frames {
        packet_ptrs.push(frame.as_ptr());
        sizes.push(frame.len());
        protocols.push(protocol_number(frame));
    }

    unsafe {
        (callbacks.emit_packets)(
            packet_ptrs.as_ptr(),
            sizes.as_ptr(),
            protocols.as_ptr(),
            packet_ptrs.len(),
            callbacks.context,
        );
    }
}

fn protocol_number(frame: &[u8]) -> u32 {
    if frame.first().map(|byte| (byte >> 4) == 6).unwrap_or(false) {
        AF_INET6 as u32
    } else {
        AF_INET as u32
    }
}
