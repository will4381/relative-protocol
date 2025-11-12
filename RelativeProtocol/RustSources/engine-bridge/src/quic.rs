//! QUIC inspection helpers that look for TLS ClientHello payloads inside UDP.

#[allow(dead_code)]
pub fn extract_sni(packet: &[u8]) -> Option<String> {
    // QUIC Initial packets encapsulate TLS ClientHello records. We make a best
    // effort attempt to locate the TLS record at the beginning of the payload.
    if packet.len() < 5 {
        return None;
    }
    // TLS record type must be handshake (0x16).
    if packet[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    if record_len + 5 > packet.len() {
        return None;
    }
    if packet[5] != 0x01 {
        return None;
    }
    let _handshake_len =
        ((packet[6] as usize) << 16) | ((packet[7] as usize) << 8) | packet[8] as usize;
    let mut cursor = 9;
    if cursor + 2 > packet.len() {
        return None;
    }
    // client version
    cursor += 2;
    // random
    cursor += 32;
    if cursor >= packet.len() {
        return None;
    }
    let session_len = packet[cursor] as usize;
    cursor += 1 + session_len;
    if cursor + 2 > packet.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]) as usize;
    cursor += 2 + cipher_len;
    if cursor + 1 > packet.len() {
        return None;
    }
    let compression_len = packet[cursor] as usize;
    cursor += 1 + compression_len;
    if cursor + 2 > packet.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]) as usize;
    cursor += 2;
    let extensions_end = cursor + extensions_len.min(packet.len() - cursor);
    while cursor + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let extension_len = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + extension_len > extensions_end {
            break;
        }
        if extension_type == 0x0000 {
            return parse_sni_extension(&packet[cursor..cursor + extension_len]);
        }
        cursor += extension_len;
    }
    None
}

#[allow(dead_code)]
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return None;
    }
    let mut cursor = 2;
    while cursor + 3 <= data.len() {
        let name_type = data[cursor];
        let name_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        cursor += 3;
        if cursor + name_len > data.len() {
            return None;
        }
        if name_type == 0 {
            if let Ok(host) = std::str::from_utf8(&data[cursor..cursor + name_len]) {
                return Some(host.to_string());
            }
            return None;
        }
        cursor += name_len;
    }
    None
}
