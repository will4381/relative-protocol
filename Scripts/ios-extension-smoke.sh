#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  VPN_BRIDGE_IOS_PROJECT=/path/App.xcodeproj \
  VPN_BRIDGE_IOS_SCHEME='AppScheme' \
  Scripts/ios-extension-smoke.sh

Optional:
  VPN_BRIDGE_IOS_DESTINATION='generic/platform=iOS'

This script is intentionally project-driven because the Swift package alone
cannot prove NetworkExtension entitlement, embedding, or device build behavior.
EOF
}

PROJECT_PATH="${VPN_BRIDGE_IOS_PROJECT:-}"
SCHEME="${VPN_BRIDGE_IOS_SCHEME:-}"
DESTINATION="${VPN_BRIDGE_IOS_DESTINATION:-generic/platform=iOS}"

if [[ -z "$PROJECT_PATH" || -z "$SCHEME" ]]; then
  usage
  exit 64
fi

if [[ ! -e "$PROJECT_PATH" ]]; then
  echo "iOS project not found: $PROJECT_PATH" >&2
  exit 66
fi

xcodebuild \
  -project "$PROJECT_PATH" \
  -scheme "$SCHEME" \
  -destination "$DESTINATION" \
  CODE_SIGNING_ALLOWED=NO \
  build
