// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unitchecker_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/passes/assign"
	"golang.org/x/tools/go/analysis/passes/findcall"
	"golang.org/x/tools/go/analysis/passes/printf"
	"golang.org/x/tools/go/analysis/unitchecker"
	"golang.org/x/tools/internal/testenv"
	"golang.org/x/tools/internal/testfiles"
	"golang.org/x/tools/txtar"
)

func TestMain(m *testing.M) {
	// child process?
	switch os.Getenv("ENTRYPOINT") {
	case "vet":
		vet()
		panic("unreachable")
	case "minivet":
		minivet()
		panic("unreachable")
	case "worker":
		worker() // see ExampleSeparateAnalysis
		panic("unreachable")
	}

	// test process
	flag.Parse()
	os.Exit(m.Run())
}

// minivet is a vet-like tool with a few analyzers, for testing.
func minivet() {
	unitchecker.Main(
		findcall.Analyzer,
		printf.Analyzer,
		assign.Analyzer,
	)
}

// This is a very basic integration test of modular
// analysis with facts using unitchecker under "go vet".
// It fork/execs the main function above.
func TestIntegration(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping fork/exec test on this platform")
	}

	const src = `
-- go.mod --
module golang.org/fake
go 1.18

-- a/a.go --
package a

func _() {
	MyFunc123()
}

func MyFunc123() {}

-- b/b.go --
package b

import "golang.org/fake/a"

func _() {
	a.MyFunc123()
	MyFunc123()
}

func MyFunc123() {}

-- c/c.go --
package c

func _() {
    i := 5
    i = i
}
`
	// Expand archive into tmp tree.
	fs, err := txtar.FS(txtar.Parse([]byte(src)))
	if err != nil {
		t.Fatal(err)
	}
	tmpdir := testfiles.CopyToTmp(t, fs)

	// -- operators --

	// vet runs "go vet" with the specified arguments (plus -findcall.name=MyFunc123).
	vet := func(t *testing.T, args ...string) (exitcode int, stdout, stderr string) {
		cmd := exec.Command("go", "vet", "-vettool="+os.Args[0], "-findcall.name=MyFunc123")
		cmd.Stdout = new(strings.Builder)
		cmd.Stderr = new(strings.Builder)
		cmd.Args = append(cmd.Args, args...)
		cmd.Env = append(os.Environ(), "ENTRYPOINT=minivet")
		cmd.Dir = tmpdir
		if err := cmd.Run(); err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("couldn't exec %v: %v", cmd, err)
			}
			exitcode = exitErr.ExitCode()
		}

		// Sanitize filenames; this is imperfect due to
		// (e.g.) /private/tmp -> /tmp symlink on macOS.
		stdout = strings.ReplaceAll(fmt.Sprint(cmd.Stdout), tmpdir, "TMPDIR")
		stderr = strings.ReplaceAll(fmt.Sprint(cmd.Stderr), tmpdir, "TMPDIR")

		// Show vet information on failure.
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("command: %v", cmd)
				t.Logf("exit code: %d", exitcode)
				t.Logf("stdout: %s", stdout)
				t.Logf("stderr: %s", stderr)
			}
		})
		return
	}

	// exitcode asserts that the exit code was "want".
	exitcode := func(t *testing.T, got, want int) {
		if got != want {
			t.Fatalf("vet tool exit code was %d", got)
		}
	}

	// parseJSON parses the JSON diagnostics into a simple line-oriented form.
	parseJSON := func(t *testing.T, stdout string) string {
		var v map[string]map[string][]map[string]any
		if err := json.Unmarshal([]byte(stdout), &v); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		var res strings.Builder
		for pkgpath, v := range v {
			for analyzer, v := range v {
				for _, v := range v {
					fmt.Fprintf(&res, "%s: [%s@%s] %v\n",
						v["posn"],
						analyzer, pkgpath,
						v["message"])
				}
			}
		}
		// Show parsed JSON information on failure.
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("json: %s", &res)
			}
		})
		return res.String()
	}

	// substring asserts that the labeled output contained the substring.
	substring := func(t *testing.T, label, output, substr string) {
		if !strings.Contains(output, substr) {
			t.Fatalf("%s: expected substring %q", label, substr)
		}
	}

	// -- scenarios --

	t.Run("a", func(t *testing.T) {
		code, _, stderr := vet(t, "golang.org/fake/a")
		if false {
			exitcode(t, code, 1) // changing to 0 in go1.25; TODO(adonovan): re-enable
		}
		substring(t, "stderr", stderr, "a/a.go:4:11: call of MyFunc123")
	})
	t.Run("b", func(t *testing.T) {
		code, _, stderr := vet(t, "golang.org/fake/b")
		if false {
			exitcode(t, code, 1) // changing to 0 in go1.25; TODO(adonovan): re-enable
		}
		substring(t, "stderr", stderr, "b/b.go:6:13: call of MyFunc123")
		substring(t, "stderr", stderr, "b/b.go:7:11: call of MyFunc123")
	})
	t.Run("c", func(t *testing.T) {
		code, _, stderr := vet(t, "golang.org/fake/c")
		if false {
			exitcode(t, code, 1) // changing to 0 in go1.25; TODO(adonovan): re-enable
		}
		substring(t, "stderr", stderr, "c/c.go:5:5: self-assignment of i")
	})
	t.Run("ab", func(t *testing.T) {
		code, _, stderr := vet(t, "golang.org/fake/a", "golang.org/fake/b")
		if false {
			exitcode(t, code, 1) // changing to 0 in go1.25; TODO(adonovan): re-enable
		}
		substring(t, "stderr", stderr, "a/a.go:4:11: call of MyFunc123")
		substring(t, "stderr", stderr, "b/b.go:6:13: call of MyFunc123")
		substring(t, "stderr", stderr, "b/b.go:7:11: call of MyFunc123")
	})
	t.Run("a-json", func(t *testing.T) {
		code, stdout, _ := vet(t, "-json", "golang.org/fake/a")
		exitcode(t, code, 0)
		testenv.NeedsGo1Point(t, 26) // depends on CL 702815 (go vet -json => stdout)
		json := parseJSON(t, stdout)
		substring(t, "json", json, "a/a.go:4:11: [findcall@golang.org/fake/a] call of MyFunc123")
	})
	t.Run("c-json", func(t *testing.T) {
		code, stdout, _ := vet(t, "-json", "golang.org/fake/c")
		exitcode(t, code, 0)
		testenv.NeedsGo1Point(t, 26) // depends on CL 702815 (go vet -json => stdout)
		json := parseJSON(t, stdout)
		substring(t, "json", json, "c/c.go:5:5: [assign@golang.org/fake/c] self-assignment of i")
	})
	t.Run("a-context", func(t *testing.T) {
		code, _, stderr := vet(t, "-c=0", "golang.org/fake/a")
		if false {
			exitcode(t, code, 1) // changing to 0 in go1.25; TODO(adonovan): re-enable
		}
		substring(t, "stderr", stderr, "a/a.go:4:11: call of MyFunc123")
		substring(t, "stderr", stderr, "4		MyFunc123")
	})
}
