# RelativeProtocol

Reusable Swift Package that bundles the RelativeProtocol tunnel engine and gomobile-based Tun2Socks bindings for iOS Network Extension projects.

## Package Layout

- `RelativeProtocol/` – SwiftPM package containing two targets:
  - `RelativeProtocolCore`: configuration models, hooks, metrics types.
  - `RelativeProtocolTunnel`: Network Extension glue and the embedded Tun2Socks xcframework.
- `RelativeProtocol/Binary/Tun2Socks.xcframework` – prebuilt gomobile framework shipped with the repo.
- `Scripts/` – helper scripts (e.g. `build-tun2socks.sh`) to regenerate the xcframework when the Go sources change.
- `ThirdParty/tun2socks/` – vendored Go sources from `xjasonlyu/tun2socks` used to rebuild the binary.

## Using the Package

1. Add this repository as a Swift Package dependency in Xcode or `Package.swift`.
2. Link `RelativeProtocolCore` to your host app target.
3. Link `RelativeProtocolTunnel` to your `NEPacketTunnelProvider` target and adopt `RelativeProtocolTunnel.ProviderController`.
4. Configure and start the tunnel with `RelativeProtocol.Configuration` and optional hooks/metrics callbacks.

## Regenerating Tun2Socks

If you modify the Go bridge sources:

```sh
./Scripts/build.sh
```

The script rebuilds the xcframework into `Build/Tun2Socks/` and syncs `RelativeProtocol/Binary/Tun2Socks.xcframework` in place. Commit the updated binary alongside your changes.

## License

See upstream license files in `ThirdParty/tun2socks`. Project-level licensing TBD.
