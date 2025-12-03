use super::*;

fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

#[test]
fn parse_response_maps_addresses_to_question_name() {
    let question = "v16.us.tiktok.com";
    let cname = "edge.example.net";
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x12, 0x34]); // id
    payload.extend_from_slice(&[0x81, 0x80]); // standard response
    payload.extend_from_slice(&[0x00, 0x01]); // qdcount
    payload.extend_from_slice(&[0x00, 0x02]); // ancount
    payload.extend_from_slice(&[0x00, 0x00]); // nscount
    payload.extend_from_slice(&[0x00, 0x00]); // arcount
    payload.extend_from_slice(&encode_name(question));
    payload.extend_from_slice(&[0x00, 0x01]); // type A
    payload.extend_from_slice(&[0x00, 0x01]); // class IN
    payload.extend_from_slice(&encode_name(question)); // answer name
    payload.extend_from_slice(&[0x00, 0x05]); // CNAME
    payload.extend_from_slice(&[0x00, 0x01]); // class IN
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
    let cname_encoded = encode_name(cname);
    payload.extend_from_slice(&[
        ((cname_encoded.len() as u16) >> 8) as u8,
        (cname_encoded.len() as u16 & 0xFF) as u8,
    ]);
    payload.extend_from_slice(&cname_encoded);
    payload.extend_from_slice(&encode_name(cname));
    payload.extend_from_slice(&[0x00, 0x01]); // type A
    payload.extend_from_slice(&[0x00, 0x01]); // class IN
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
    payload.extend_from_slice(&[0x00, 0x04]); // rdlength
    payload.extend_from_slice(&[1, 2, 3, 4]); // IPv4 addr

    let mappings = parse_response(&payload);
    assert_eq!(mappings.len(), 1);
    let mapping = &mappings[0];
    assert_eq!(mapping.host, question);
    assert_eq!(
        mapping.addresses,
        vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
    );
}
