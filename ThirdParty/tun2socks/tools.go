//go:build tools

// Package tools keeps track of toolchain dependencies that are required at
// build time (e.g. gomobile/gobind) but not imported by the tun2socks code.
package tools

import (
	_ "golang.org/x/mobile/bind"
)
