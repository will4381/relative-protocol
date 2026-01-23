# AGENTS.md

## Project intent
- Build an on-device VPN-like proxy for iOS only.
- Proxy packets entirely on-device; no external relay servers and no long-lived on-device background server (iOS suspends/kills them).
- Consumer download only; no MDM, supervised-device, or enterprise management approach.
- Screen Time / ManagedSettings APIs are not acceptable for this approach.
- Follow the same general approach Opal used before the Screen Time API was made public.

## Opal backstory (context, non-binding)
- Before Apple's Screen Time APIs (ManagedSettings) were public, Opal's iOS app reportedly relied on a VPN-based, on-device approach to measure usage and block apps.
- After Screen Time APIs became available, Opal reportedly shifted to Screen Time/ManagedSettings and removed the VPN requirement.

## Working expectations
- iOS networking is notoriously difficult; write unit and integration tests as you go.
- Use the MCPs regularly to ground decisions in facts, not memory:
  - `apple-doc-mcp` for Apple documentation.
  - `XcodeBuildMCP` for Xcode commands and features.
- Before making changes, verify with the user; only begin edits after approval.
- Build and run tests after every change, even minor ones.
- Keep the public surface minimal; the package should do nearly all of the heavy lifting.

## Testing constraints
- Use the Example project in this monorepo to test package functionality on device.
- Network Extension APIs do not work on the simulator; have the user test on a device via the Example app.

## Logging and diagnostics
- Add detailed logging throughout to trace issues such as:
  - Packets not making it out of the tunnel.
  - Packets sent but still no internet connectivity.
  - Other common tunnel and routing failures.

## Target outcomes
- Full internet connectivity on the device.
- Low battery usage.
- A solid packet stream we can read from.
- Ideally, DNS hostnames when possible.
