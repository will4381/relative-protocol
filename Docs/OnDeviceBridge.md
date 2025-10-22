# On-Device VPN Bridge Prototype

This checklist captures the standing work and the decisions baked into the prototype target.

## Checklist Progress

- [x] Choose a Tun Engine – gomobile-compatible `xjasonlyu/tun2socks` vendored in `ThirdParty/tun2socks`; adapter exposes NE connection factories.
- [x] Create a Sandbox Xcode Target – `PacketTunnel` Network Extension target + entitlements keep the prototype isolated from the shipping app.
- [x] Implement the Bridge Prototype – `PacketTunnelProvider`, `Tun2SocksAdapter`, and the gomobile-backed engine move packets between `packetFlow` and the Go core.
- [x] Add Hook Points – `BridgeMetrics` batches packet counters and logs at five second intervals; adapter logs block-list decisions.
- [x] Configuration Flow – `BridgeConfiguration` defines MTU/DNS/blocked hosts, defaults, and conversion to `providerConfiguration`.
- [x] Local Validation Strategy – `BridgeHarness.runEchoSimulation` replays packets against the adapter; macOS debug notes cover the entitlement toggles.
- [ ] Cleanup & Packaging – Need end-to-end doc once gomobile bindings ship and migration plan back into main app.

## Tun Engine

- Engine: [`xjasonlyu/tun2socks`](https://github.com/xjasonlyu/tun2socks) pulled into `ThirdParty/tun2socks`.
- Integration path: gomobile `bind` -> `Tun2Socks.xcframework` consumed by the `PacketTunnel` target.
- Hooks: `Tun2SocksAdapter` exposes `NWConnection` dialers backed by the provider's packet tunnel flow. `GoTun2SocksEngine` bridges gomobile callbacks into those TCP/UDP connections.

## Xcode Targets

- `PacketTunnel` (Network Extension) target referenced from the existing workspace. The extension is self-contained and does not impact the shipping app target.
- Entitlements: `com.apple.developer.networking.networkextension` → `packet-tunnel-provider`. Provisioning profiles will need to be regenerated to include the entitlement.
- Shared container: both host app and extension include `group.vpn-bridge` in their application groups so they can exchange configuration and logs.

## Bridge Implementation

- `PacketTunnelProvider` sets up `NEPacketTunnelNetworkSettings` from a `BridgeConfiguration` payload (defaults hard-coded for now).
- `Tun2SocksAdapter` moves packets between `packetFlow` and the tun2socks engine and provides block-list enforcement + instrumentation hooks.
- `BridgeMetrics` batches directional packet counters and logs a heartbeat every five seconds by default.
- `GoTun2SocksEngine` (gomobile) binds the Go stack, emitting packets back to `packetFlow` and dialing outbound TCP/UDP via `NEPacketTunnelProvider` factories.

## Configuration Flow

- `BridgeConfiguration` is `Codable` and converts to/from `providerConfiguration` dictionaries.
- Defaults: `MTU=1500`, DNS servers `1.1.1.1`/`8.8.8.8`, IPv4 address `10.0.0.2`.
- Blocklists: simple substring filter on destination host names before invoking the `NWConnection` dialers.

## Local Validation

- The `NoOpTun2SocksEngine` feeds packets straight back through `packetFlow` to confirm the plumbing works without Go bindings.
- `BridgeHarness.runEchoSimulation` (debug-only) runs the adapter against mocked flows so we can replay packets headlessly.
- macOS-only debug: ensure the host app owns the `NetworkExtension` debug entitlement. Use Xcode's "Allow Debugging" toggle or install via `systemextensionsctl developer on`.
- For headless checks, the adapter emits metric logs (`PacketTunnel` subsystem), so `log stream --predicate 'subsystem == "PacketTunnel"'` keeps an eye on runtime behaviour.

## Build & Packaging

1. Install gomobile once: `go install golang.org/x/mobile/cmd/gomobile@latest`.
2. Regenerate the bindings any time you touch the Go bridge: `./Scripts/build-tun2socks.sh` (drops `Tun2Socks.xcframework` in `Build/Tun2Socks/`).
3. Open `VPN Bridge.xcodeproj` in Xcode – the `PacketTunnel` Network Extension target already links and embeds the xcframework from that path.
4. Clean the build folder (`Shift` + `Cmd` + `K`), then build the host app + extension to pick up the fresh framework.
5. Run on a physical device, tap **Connect** in the app to enable the tunnel, and verify traffic still flows end-to-end.

> If you relocate the xcframework, update the project reference (`Build/Tun2Socks/Tun2Socks.xcframework`) or rerun the build script to repopulate it before compiling.

## Next Steps

- Expand block-listing to IP matching and rule-based policies.
- Layer in latency injection hooks and structured logging (e.g. `MetricKit`) to evaluate performance under load.
- Build a lightweight traffic harness and scripted tests to stress the on-device bridge across TCP/UDP edge cases.
