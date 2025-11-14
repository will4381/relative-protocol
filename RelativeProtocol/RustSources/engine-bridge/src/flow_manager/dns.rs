use super::*;
use crate::dns::{parse_response, DnsMapping};

impl FlowManager {
    pub(super) fn observe_dns(&self, packet: &UdpPacket<'_>) {
        if packet.src_port != 53 && packet.dst_port != 53 {
            return;
        }
        let Some(callbacks) = self.callbacks else {
            return;
        };
        let mappings = parse_response(packet.payload);
        if mappings.is_empty() {
            return;
        }
        for mapping in mappings {
            self.policy
                .observe_dns_mapping(mapping.host.as_str(), &mapping.addresses, mapping.ttl);
            self.emit_dns_mapping(callbacks, &mapping);
        }
    }

    fn emit_dns_mapping(&self, callbacks: BridgeCallbacks, mapping: &DnsMapping) {
        if mapping.addresses.is_empty() {
            return;
        }
        let ttl = mapping.ttl.unwrap_or(60).min(u32::MAX);
        let c_host = match CString::new(mapping.host.as_str()) {
            Ok(value) => value,
            Err(_) => return,
        };
        let mut c_addresses: Vec<CString> = Vec::with_capacity(mapping.addresses.len());
        let mut ptrs: Vec<*const i8> = Vec::with_capacity(mapping.addresses.len());
        for addr in &mapping.addresses {
            let addr_text = addr.to_string();
            if let Ok(c_string) = CString::new(addr_text.as_str()) {
                ptrs.push(c_string.as_ptr());
                c_addresses.push(c_string);
            }
        }
        if ptrs.is_empty() {
            return;
        }
        unsafe {
            (callbacks.record_dns)(
                c_host.as_ptr(),
                ptrs.as_ptr(),
                ptrs.len(),
                ttl,
                callbacks.context,
            );
        }
        logger::breadcrumb(
            BreadcrumbFlags::DNS,
            format!(
                "DNS {} -> {:?} (ttl {}s)",
                mapping.host,
                mapping
                    .addresses
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>(),
                ttl
            ),
        );
    }
}
