// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// want +1 `invalid go version \"go1.20.1\" in build constraint`
//go:build go1.20.1
// want +1 `[+]build line is no longer needed` `invalid go version \"go1.20.1\" in build constraint`
// +build go1.20.1

package b
