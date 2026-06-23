// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

@testable import Analytics
import Foundation
import XCTest

/// Known-answer coverage for QUIC Initial header unprotection and payload decryption.
/// The vector is the protected Client Initial from RFC 9001 Appendix A.2 (DCID 0x8394c8f03e515708),
/// whose decrypted CRYPTO frame carries a TLS ClientHello with SNI `example.com`.
/// Docs: https://www.rfc-editor.org/rfc/rfc9001#appendix-A.2
final class PacketParserQuicInitialTests: XCTestCase {
    /// Full 1200-byte protected datagram from RFC 9001 A.2, "The resulting protected packet is:".
    private static let rfc9001ClientInitialHex =
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c" +
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89" +
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e" +
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7" +
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7" +
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf" +
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2" +
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd" +
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07" +
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d" +
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723" +
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd" +
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934"

    /// Exposes the vetted RFC vector to sibling fuzz tests so the bytes live in exactly one place.
    static func rfc9001ClientInitialPayload() -> Data? {
        data(fromHex: rfc9001ClientInitialHex)
    }

    func testDecryptsRFC9001ClientInitialServerName() throws {
        let quicPayload = try XCTUnwrap(Self.data(fromHex: Self.rfc9001ClientInitialHex))
        XCTAssertEqual(quicPayload.count, 1_200)

        let packet = Self.makeIPv4UDPPacket(
            sourcePort: 50_000,
            destinationPort: 443,
            payload: quicPayload
        )

        let metadata = try XCTUnwrap(PacketParser.parse(packet, ipVersionHint: nil))
        XCTAssertEqual(metadata.transport, .udp)
        XCTAssertEqual(metadata.quicVersion, 0x0000_0001)
        XCTAssertEqual(metadata.quicPacketType, .initial)
        XCTAssertEqual(metadata.quicDestinationConnectionId, "8394c8f03e515708")
#if canImport(CryptoKit)
        XCTAssertEqual(metadata.tlsServerName, "example.com")
        XCTAssertEqual(metadata.registrableDomain, "example.com")
#endif
    }

    func testTruncatedRFC9001ClientInitialFailsClosed() throws {
        let quicPayload = try XCTUnwrap(Self.data(fromHex: Self.rfc9001ClientInitialHex))

        // Every truncation point must parse to either `nil` metadata or metadata without an SNI;
        // it must never crash or fabricate a server name from a partial AEAD payload.
        for keptBytes in [27, 50, 100, 600, 1_199] {
            let truncated = quicPayload.prefix(keptBytes)
            let packet = Self.makeIPv4UDPPacket(
                sourcePort: 50_000,
                destinationPort: 443,
                payload: Data(truncated)
            )
            let metadata = PacketParser.parse(packet, ipVersionHint: nil)
            XCTAssertNil(metadata?.tlsServerName, "truncation at \(keptBytes) bytes must not produce an SNI")
        }
    }

    func testCorruptedRFC9001ClientInitialFailsAuthentication() throws {
        var quicPayload = try XCTUnwrap(Self.data(fromHex: Self.rfc9001ClientInitialHex))
        // Flip one ciphertext bit; AES-GCM authentication must reject the payload.
        quicPayload[600] ^= 0x01

        let packet = Self.makeIPv4UDPPacket(
            sourcePort: 50_000,
            destinationPort: 443,
            payload: quicPayload
        )
        let metadata = PacketParser.parse(packet, ipVersionHint: nil)
        XCTAssertNil(metadata?.tlsServerName)
    }

    private static func makeIPv4UDPPacket(sourcePort: UInt16, destinationPort: UInt16, payload: Data) -> Data {
        let udpLength = 8 + payload.count
        let totalLength = 20 + udpLength

        var packet = Data(capacity: totalLength)
        packet.append(0x45) // version 4, IHL 5
        packet.append(0x00)
        packet.append(UInt8((totalLength >> 8) & 0xFF))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // identification + flags/fragment
        packet.append(0x40) // TTL
        packet.append(17) // UDP
        packet.append(contentsOf: [0x00, 0x00]) // header checksum (unchecked by parser)
        packet.append(contentsOf: [10, 0, 0, 2]) // source address
        packet.append(contentsOf: [93, 184, 216, 34]) // destination address
        packet.append(UInt8((sourcePort >> 8) & 0xFF))
        packet.append(UInt8(sourcePort & 0xFF))
        packet.append(UInt8((destinationPort >> 8) & 0xFF))
        packet.append(UInt8(destinationPort & 0xFF))
        packet.append(UInt8((udpLength >> 8) & 0xFF))
        packet.append(UInt8(udpLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00]) // UDP checksum (unchecked by parser)
        packet.append(payload)
        return packet
    }

    private static func data(fromHex hex: String) -> Data? {
        guard hex.count % 2 == 0 else {
            return nil
        }
        var data = Data(capacity: hex.count / 2)
        var iterator = hex.unicodeScalars.makeIterator()
        while let high = iterator.next() {
            guard let low = iterator.next(),
                  let highValue = high.hexDigitValue,
                  let lowValue = low.hexDigitValue else {
                return nil
            }
            data.append(UInt8(highValue << 4 | lowValue))
        }
        return data
    }
}

private extension Unicode.Scalar {
    var hexDigitValue: Int? {
        Character(self).hexDigitValue
    }
}
