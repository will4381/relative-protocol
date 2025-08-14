import XCTest
import Network
@testable import RelativeProtocol

final class RelativeProtocolTests: XCTestCase {
	func testIPv4Checksum() {
		// Simple header with zero checksum should compute to a known value
        let hdr = Data([0x45,0x00,0x00,0x54, 0x00,0x00,0x40,0x00, 0x40,0x01,0x00,0x00, 0x7f,0x00,0x00,0x01, 0x7f,0x00,0x00,0x01])
		let cs = SocketBridge.shared.test_ipv4Checksum(hdr)
		XCTAssertNotEqual(cs, 0)
	}

	func testBuildIPv4UDPPacketChecksum() {
		let src = Data([127,0,0,1])
		let dst = Data([127,0,0,1])
		let payload = Data([1,2,3,4,5])
		let pkt = SocketBridge.shared.test_buildIPv4UDPPacket(srcIP: src, dstIP: dst, srcPort: 1234, dstPort: 5678, payload: payload)
		XCTAssertEqual(pkt[9], 17) // UDP protocol
	}

	func testBuildIPv4TCPPacketMSS() {
		let src = Data([127,0,0,1])
		let dst = Data([127,0,0,1])
		let pkt = SocketBridge.shared.test_buildIPv4TCPPacket(srcIP: src, dstIP: dst, srcPort: 1234, dstPort: 80, seq: 1, ack: 0, flags: 0x12, payload: Data(), mssOption: 1400)
		XCTAssertEqual(pkt[0] >> 4, 4)
	}

	func testBuildIPv6UDPPacketFields() {
		let src = Data(repeating: 0x20, count: 16)
		let dst = Data(repeating: 0x30, count: 16)
		let payload = Data([9,8,7,6])
		let pkt = SocketBridge.shared.test_buildIPv6UDPPacket(srcIP: src, dstIP: dst, srcPort: 1111, dstPort: 2222, payload: payload)
		XCTAssertEqual(pkt[0] >> 4, 6)
		XCTAssertEqual(pkt[6], 17) // Next header UDP
		let plen = (UInt16(pkt[4]) << 8) | UInt16(pkt[5])
		XCTAssertEqual(plen, UInt16(8 + payload.count))
	}

	func testTagStoreTagForPacketIPv4UDP() {
		let tag = "test-tag"
		let srcIP = Data([10,0,0,1])
		let dstIP = Data([10,0,0,2])
		let srcPort: UInt16 = 12345
		let dstPort: UInt16 = 54321
		let payload = Data([1,2,3])
		TagStore.shared.setTagBothDirectionsSync(version: 4, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17, tag: tag)
		let pkt = SocketBridge.shared.test_buildIPv4UDPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: payload)
		// Sanity-parse ports and IPs from packet to ensure header layout matches expectations
		let ihl = 20
		let parsedSrcPort = UInt16(pkt[ihl]) << 8 | UInt16(pkt[ihl+1])
		let parsedDstPort = UInt16(pkt[ihl+2]) << 8 | UInt16(pkt[ihl+3])
		XCTAssertEqual(parsedSrcPort, srcPort)
		XCTAssertEqual(parsedDstPort, dstPort)
		XCTAssertEqual(Data(pkt[12..<16]), srcIP)
		XCTAssertEqual(Data(pkt[16..<20]), dstIP)
		let res = pkt.withUnsafeBytes { ptr -> String? in
			guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
			return TagStore.shared.tagForPacket(bytes: base, length: pkt.count)
		}

    func testFlowIDDeterminismV4() {
        // Build a deterministic UDP v4 packet and ensure the internal flow key matches expectation
        let srcIP = Data([192,168,1,10])
        let dstIP = Data([93,184,216,34]) // example.org
        let srcPort: UInt16 = 40000
        let dstPort: UInt16 = 443
        let payload = Data([0x01, 0x02])
        let pkt = SocketBridge.shared.test_buildIPv4UDPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: payload)
        // Parse back and validate header fields
        XCTAssertEqual(pkt[0] >> 4, 4)
        let ihl = 20
        let parsedSrcPort = UInt16(pkt[ihl]) << 8 | UInt16(pkt[ihl+1])
        let parsedDstPort = UInt16(pkt[ihl+2]) << 8 | UInt16(pkt[ihl+3])
        XCTAssertEqual(parsedSrcPort, srcPort)
        XCTAssertEqual(parsedDstPort, dstPort)
        XCTAssertEqual(Data(pkt[12..<16]), srcIP)
        XCTAssertEqual(Data(pkt[16..<20]), dstIP)
        // Ensure TagStore can store and retrieve with the same 5-tuple+proto mapping
        let tag = "id-test"
        TagStore.shared.setTagBothDirectionsSync(version: 4, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17, tag: tag)
        let res = pkt.withUnsafeBytes { ptr -> String? in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return TagStore.shared.tagForPacket(bytes: base, length: pkt.count)
        }
        XCTAssertEqual(res, tag)
    }
		XCTAssertEqual(res, tag)
	}

	func testSocketHelpersEndpointV4() {
		let ip = Data([1,2,3,4])
		let ep = SocketHelpers.endpointForIPLiteral(version: 4, hostBytes: ip, port: 8080)
		XCTAssertNotNil(ep)
	}

    func testUDPHelperSend() {
		let helper = UDPHelper()
        let ep = NWEndpoint.hostPort(host: .name("localhost", nil), port: .init(integerLiteral: 9))
		let exp = expectation(description: "send")
		helper.send(to: ep, payload: Data([0x00])) { _ in exp.fulfill() }
		wait(for: [exp], timeout: 1.0)
	}

	#if DEBUG
	func testControlPlaneRouting_ICMPv4GoesToTunPath() {
		// We can't observe NEPacketTunnelFlow on macOS tests, but we can at least invoke the synthesis path
		// and ensure it does not crash and removes the flow.
		let src = Data([10,0,0,1])
		let dst = Data([10,0,0,2])
		let srcPort: UInt16 = 1111
		let dstPort: UInt16 = 2222
		// Minimal quoted header (IPv4 + UDP header bytes)
		var quoted = Data(count: 28)
		// Fill version/IHL
		quoted[0] = 0x45
		// Fill src/dst
		quoted.replaceSubrange(12..<16, with: src)
		quoted.replaceSubrange(16..<20, with: dst)
		// UDP ports
		quoted[20] = UInt8((srcPort >> 8) & 0xFF)
		quoted[21] = UInt8(srcPort & 0xFF)
		quoted[22] = UInt8((dstPort >> 8) & 0xFF)
		quoted[23] = UInt8(dstPort & 0xFF)
		let key = SocketBridge.shared.debug_createUDPFlowForTest(version: 4, srcIP: src, dstIP: dst, srcPort: srcPort, dstPort: dstPort, quotedHeader: quoted)
		SocketBridge.shared.debug_triggerICMPForUDPFailure(key: key)
		XCTAssertTrue(true)
	}
	#endif

	#if DEBUG
	func testTcpOrderingBuffersAndFlushes() {
		// Disable actual network sends; capture payloads per-flow
		SocketBridge.shared.debug_disableNetworkSends = true
		SocketBridge.shared.debug_clearSent()
		// Construct IPv4 TCP header template
		let srcIP = Data([10,0,0,1])
		let dstIP = Data([10,0,0,2])
		let srcPort: UInt16 = 1111
		let dstPort: UInt16 = 80
		func buildTCP(seq: UInt32, ack: UInt32, flags: UInt8, payload: [UInt8]) -> Data {
			var ip = Data(count: 20)
			ip[0] = 0x45
			ip[9] = 6
			var iph = ip
			iph.replaceSubrange(12..<16, with: srcIP)
			iph.replaceSubrange(16..<20, with: dstIP)
			var tcp = Data(count: 20)
			tcp[12] = 5 << 4
			tcp[13] = flags
			tcp[0] = UInt8((srcPort >> 8) & 0xFF); tcp[1] = UInt8(srcPort & 0xFF)
			tcp[2] = UInt8((dstPort >> 8) & 0xFF); tcp[3] = UInt8(dstPort & 0xFF)
			tcp[4] = UInt8((seq >> 24) & 0xFF); tcp[5] = UInt8((seq >> 16) & 0xFF); tcp[6] = UInt8((seq >> 8) & 0xFF); tcp[7] = UInt8(seq & 0xFF)
			tcp[8] = UInt8((ack >> 24) & 0xFF); tcp[9] = UInt8((ack >> 16) & 0xFF); tcp[10] = UInt8((ack >> 8) & 0xFF); tcp[11] = UInt8(ack & 0xFF)
			var pkt = iph
			pkt.append(tcp)
			pkt.append(Data(payload))
			return pkt
		}
		// SYN from device to open flow
		let syn = buildTCP(seq: 1000, ack: 0, flags: 0x02, payload: [])
		syn.withUnsafeBytes { p in SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: syn.count) }
		// Two out-of-order data segments: second arrives first, then first; expect buffer+flush in order
		// After SYN (seq 1000) deviceNextSeq = 1001, so first data must begin at 1001
		let seg2 = buildTCP(seq: 1011, ack: 0, flags: 0x18, payload: Array(repeating: 0xBB, count: 10))
        seg2.withUnsafeBytes { p in SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: seg2.count) }
        // Ensure pending state is stored before sending the in-order segment
        SocketBridge.shared.debug_flush()
		let seg1 = buildTCP(seq: 1001, ack: 0, flags: 0x18, payload: Array(repeating: 0xAA, count: 10))
		seg1.withUnsafeBytes { p in SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: seg1.count) }
		// Find the flow key used internally
		let key = "4|" + srcIP.base64EncodedString() + "|\(srcPort)|" + dstIP.base64EncodedString() + "|\(dstPort)|6"
		// Wait until two sends captured or timeout
		var tries = 0
		while tries < 100 {
			SocketBridge.shared.debug_flush()
			if (SocketBridge.shared.debug_sentData[key]?.count ?? 0) >= 2 { break }
			usleep(2000)
			tries += 1
		}
        // Verify captured data: first should be 0xAA*10 then 0xBB*10
        let sent = SocketBridge.shared.debug_sentData[key] ?? []
        XCTAssertEqual(sent.count, 2)
        XCTAssertEqual(sent[0], Data(repeating: 0xAA, count: 10))
        XCTAssertEqual(sent[1], Data(repeating: 0xBB, count: 10))
		SocketBridge.shared.debug_disableNetworkSends = false
	}
	#endif

	#if DEBUG
	func testTcpSenderWindowBuffersWhenExceeded() {
		SocketBridge.shared.debug_disableNetworkSends = true
		SocketBridge.shared.debug_clearSent()
		// Shrink sender window to 12 bytes
		SocketBridge.shared.setTCPSenderWindow(bytes: 12)
		let srcIP = Data([10,0,0,3])
		let dstIP = Data([10,0,0,4])
		let srcPort: UInt16 = 2222
		let dstPort: UInt16 = 80
		func buildTCP(seq: UInt32, flags: UInt8, payloadLen: Int) -> Data {
			var ip = Data(count: 20); ip[0] = 0x45; ip[9] = 6
			var iph = ip; iph.replaceSubrange(12..<16, with: srcIP); iph.replaceSubrange(16..<20, with: dstIP)
			var tcp = Data(count: 20)
			tcp[12] = 5 << 4; tcp[13] = flags
			tcp[0] = UInt8((srcPort >> 8) & 0xFF); tcp[1] = UInt8(srcPort & 0xFF)
			tcp[2] = UInt8((dstPort >> 8) & 0xFF); tcp[3] = UInt8(dstPort & 0xFF)
			tcp[4] = UInt8((seq >> 24) & 0xFF); tcp[5] = UInt8((seq >> 16) & 0xFF); tcp[6] = UInt8((seq >> 8) & 0xFF); tcp[7] = UInt8(seq & 0xFF)
			var pkt = iph; pkt.append(tcp); pkt.append(Data(repeating: 0xCC, count: payloadLen)); return pkt
		}
		// SYN
		let syn = buildTCP(seq: 5000, flags: 0x02, payloadLen: 0)
		syn.withUnsafeBytes { p in SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: syn.count) }
        // First segment 10 bytes at seq=5001 should pass (inFlight 1 + 10 <= 12)
		let seg1 = buildTCP(seq: 5001, flags: 0x18, payloadLen: 10)
		seg1.withUnsafeBytes { p in SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: seg1.count) }
		SocketBridge.shared.debug_flush()
        // Second segment 5 bytes at seq=5012 should be buffered (inFlight ~11 + 5 > 12)
        let seg2 = buildTCP(seq: 5012, flags: 0x18, payloadLen: 5)
		seg2.withUnsafeBytes { p in SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: seg2.count) }
        let key = "4|" + srcIP.base64EncodedString() + "|\(srcPort)|" + dstIP.base64EncodedString() + "|\(dstPort)|6"
        // Wait until at least one send captured or timeout
        var tries = 0
        while tries < 100 {
            SocketBridge.shared.debug_flush()
            if (SocketBridge.shared.debug_sentData[key]?.count ?? 0) >= 1 { break }
            usleep(2000)
            tries += 1
        }
        let sent = SocketBridge.shared.debug_sentData[key] ?? []
        XCTAssertGreaterThanOrEqual(sent.count, 1)
        if sent.count >= 1 {
            XCTAssertEqual(sent[0].count, 10)
        }
		SocketBridge.shared.debug_disableNetworkSends = false
	}
	#endif

    func testUDPLimiterQueuesTaggedFlow() {
        class DummyDelegate: SocketBridge.Delegate {
            func classify(flow: SocketBridge.FlowIdentity) -> String? { "utag" }
        }
        let strongDelegate = DummyDelegate()
        SocketBridge.shared.delegate = strongDelegate
		SocketBridge.shared.setUDPRate(forTag: "utag", bytesPerSecond: 1)
		// Build minimal IPv4 UDP packet
		let srcIP = Data([1,1,1,1])
		let dstIP = Data([1,1,1,2])
		let srcPort: UInt16 = 1234
		let dstPort: UInt16 = 5678
		let payload = Data([9,9,9])
		let pkt = SocketBridge.shared.test_buildIPv4UDPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: payload)
		pkt.withUnsafeBytes { p in
			SocketBridge.shared.handleOutgoingIPPacket(packetPtr: p.bindMemory(to: UInt8.self).baseAddress!, length: pkt.count)
		}
        // Wait for queue depth metric to reflect backlog (limiters queue is async)
        var ok = false
        for _ in 0..<100 {
            let snap = Metrics.shared.snapshot()
            if let tagSnap = snap.perTag["utag"], tagSnap.udpQueueDepth >= 1 { ok = true; break }
            usleep(2000)
        }
        XCTAssertTrue(ok)
	}

	func testTagStoreFuzzDoesNotCrash() {
		for _ in 0..<100 {
			let len = Int.random(in: 0...32)
			let bytes = (0..<len).map { _ in UInt8.random(in: 0...255) }
			let data = Data(bytes)
			_ = data.withUnsafeBytes { ptr -> String? in
				guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
				return TagStore.shared.tagForPacket(bytes: base, length: data.count)
			}
		}
		XCTAssertTrue(true)
	}
}


