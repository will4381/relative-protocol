# License and Usage Notes

This package is infrastructure. Its compliance story depends on how a host product uses it.

## License Status

This repository uses the custom source-available license in [`../LICENSE`](../LICENSE).

Treat the package as private/product-scoped code. It is not an OSI open-source license and it does not grant broad redistribution, commercial-use, or sublicensing rights.

At a high level:

- personal, non-commercial evaluation is allowed under the license terms
- commercial use requires prior written permission from Relative Companies
- source or binary redistribution requires prior written permission
- incorporation into a paid product or service requires prior written permission
- AI training, fine-tuning, benchmarking, agentic copying, or model-assisted generation of substitute implementations from this code or documentation is prohibited without prior written permission

The root `LICENSE` file is authoritative. This page summarizes intent for integrators and reviewers.

## Privacy and Data Minimization

The package is shaped to minimize retained data:

- rolling live tap is memory-only
- detector outputs are compact and explicit
- persisted detector snapshots are privacy-redacted, file-protected, and excluded from backup
- continuous raw packet logging is not enabled by default

Host apps should preserve that model. Persist only the detector outputs or operational breadcrumbs that the product actually needs.

## Source-App Attribution

Bundle-id attribution is sensitive.

`NEPacketTunnelProvider` packet data alone does not expose another app's bundle identifier.
If a product adds a Content Filter extension to observe `NEFilterFlow.sourceAppIdentifier`, the product should treat that as cross-app behavior and disclose it clearly.

Operationally:

- use a separate `NEFilterDataProvider` extension target
- keep the filter passive with `.allow()` when attribution is the only goal
- persist compact attribution records, not raw flow histories
- document the behavior in privacy disclosures and App Review notes

## App Review Notes

If your product infers cross-app behavior, your privacy disclosures and App Review notes need to describe that accurately.

Do not describe the package as only a generic VPN if the host app also uses detector outputs to infer app usage, social-video activity, or source-app identity.

## Apple Documentation

Relevant Apple documentation:

- [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [Content Filter Providers](https://developer.apple.com/documentation/networkextension/content-filter-providers)
- [NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)
- [NEFilterManager](https://developer.apple.com/documentation/networkextension/nefiltermanager)
- [NETunnelProviderSession.sendProviderMessage(_:responseHandler:)](https://developer.apple.com/documentation/networkextension/netunnelprovidersession/sendprovidermessage(_:responsehandler:))
