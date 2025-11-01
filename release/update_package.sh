#!/bin/bash
# Updates Package.swift with the provided Leaf XCFramework URL and checksum.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <xcframework-url> <sha256>" >&2
  exit 1
fi

XCFRAMEWORK_URL="$1"
XCFRAMEWORK_SHA="$2"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_SWIFT="${ROOT_DIR}/Package.swift"

if [[ ! -f "${PACKAGE_SWIFT}" ]]; then
  echo "Package.swift not found at ${PACKAGE_SWIFT}" >&2
  exit 1
fi

python3 - "$XCFRAMEWORK_URL" "$XCFRAMEWORK_SHA" "$PACKAGE_SWIFT" <<'PYTHON'
import io
import os
import re
import sys

if len(sys.argv) != 4:
    sys.exit("Usage: script url sha package.swift")

url, sha, package_path = sys.argv[1:4]

with open(package_path, "r", encoding="utf-8") as fh:
    contents = fh.read()

url_pattern = re.compile(r'(let leafArchiveURL = environment\["LEAF_XCFRAMEWORK_URL"\]\n    \?\? ")[^"]+("\n)', re.MULTILINE)
checksum_pattern = re.compile(r'(let leafArchiveChecksum = environment\["LEAF_XCFRAMEWORK_CHECKSUM"\]\n    \?\? ")[^"]+("\n)', re.MULTILINE)

new_contents, url_subs = url_pattern.subn(r'\1' + url + r'\2', contents, count=1)
if url_subs == 0:
    raise SystemExit("Could not update leafArchiveURL in Package.swift")

new_contents, checksum_subs = checksum_pattern.subn(r'\1' + sha + r'\2', new_contents, count=1)
if checksum_subs == 0:
    raise SystemExit("Could not update leafArchiveChecksum in Package.swift")

with open(package_path, "w", encoding="utf-8") as fh:
    fh.write(new_contents)
PYTHON

echo "Updated Package.swift with URL=${XCFRAMEWORK_URL} and SHA=${XCFRAMEWORK_SHA}"
