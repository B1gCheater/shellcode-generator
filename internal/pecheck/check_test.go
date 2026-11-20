package pecheck

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/B1gCheater/shellcode-generator/internal/testpe"
	"github.com/B1gCheater/shellcode-lib-go/donut"
)

func inputFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metadata.data")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArchitectureMatrixAndModuleType(t *testing.T) {
	for _, x86 := range []bool{false, true} {
		for _, dll := range []bool{false, true} {
			data, _ := testpe.Image(x86, dll)
			path := inputFile(t, data)
			payload, module := "x64", "exe"
			if x86 {
				payload = "x86"
			}
			if dll {
				module = "dll"
			}
			for _, arch := range []string{"auto", "x86", "x64", "dual"} {
				t.Run(payload+"/"+module+"/"+arch, func(t *testing.T) {
					got, problem := (Checker{}).Scan(path, arch, false)
					if arch != "auto" && arch != "dual" && arch != payload {
						if problem == nil || problem.Code != "arch_mismatch" || problem.Exit != 3 {
							t.Fatalf("mismatch: result=%+v error=%v", got, problem)
						}
						return
					}
					if problem != nil {
						t.Fatal(problem)
					}
					if got.ModuleType != module || got.PayloadArch != payload || !got.ReadComplete || got.InputBytes != 1024 {
						t.Fatalf("unexpected metadata: %+v", got)
					}
					wantLoader := arch
					if arch == "auto" {
						wantLoader = payload
					}
				if got.LoaderArch != wantLoader || got.Issues == nil {
					t.Fatalf("unexpected result: %+v", got)
				}
				for _, issue := range got.Issues {
					if issue.Level == "block" || issue.Level == "warning" {
						t.Fatalf("unexpected blocking or warning issue: %+v", got)
					}
				}
				})
			}
		}
	}
}

func TestReadFailures(t *testing.T) {
	valid, _ := testpe.Image(false, false)
	cases := []struct {
		name, path, code string
		limit            int64
	}{
		{"missing", filepath.Join(t.TempDir(), "absent"), "input_not_found", 0},
		{"directory", t.TempDir(), "input_not_regular", 0},
		{"URL", "https://example.invalid/sample.exe", "input_url", 0},
		{"over-limit", inputFile(t, valid), "input_too_large", 1023},
		{"empty", inputFile(t, nil), "invalid_pe", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, problem := (Checker{limit: tc.limit}).Scan(tc.path, "auto", false)
			if problem == nil || problem.Code != tc.code || problem.Exit != 2 {
				t.Fatalf("error=%v; want %s exit2", problem, tc.code)
			}
		})
	}
	if _, problem := (Checker{limit: 1024}).Scan(inputFile(t, valid), "auto", false); problem != nil {
		t.Fatalf("limit boundary: %v", problem)
	}
}

func TestUnsupportedAndMalformedPE(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func([]byte, int)
	}{
		{"managed", "managed_image", func(b []byte, dir int) { binary.LittleEndian.PutUint32(b[dir+14*8:], 0x1100) }},
		{"arm64", "invalid_pe", func(b []byte, _ int) { binary.LittleEndian.PutUint16(b[0x84:], 0xaa64) }},
		{"bad-nt-offset", "invalid_pe", func(b []byte, _ int) { binary.LittleEndian.PutUint32(b[0x3c:], 0xffffffff) }},
		{"raw-section-overflow", "invalid_pe", func(b []byte, _ int) { binary.LittleEndian.PutUint32(b[0x188+20:], 0xfffffff0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, dir := testpe.Image(false, false)
			tc.change(b, dir)
			_, problem := (Checker{}).Scan(inputFile(t, b), "auto", false)
			if problem == nil || problem.Code != tc.code {
				t.Fatalf("got %v, want %s", problem, tc.code)
			}
		})
	}
}

func TestCompatibilityPolicyAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		policy     bool
		change     func([]byte, int)
	}{
		{"no-entry", "compatibility_blocked", false, func(b []byte, _ int) { binary.LittleEndian.PutUint32(b[0x98+16:], 0) }},
		{"warning-allowed", "", false, func(b []byte, dir int) { binary.LittleEndian.PutUint32(b[dir+5*8:], 0) }},
		{"warning-rejected", "warnings_as_errors", true, func(b []byte, dir int) { binary.LittleEndian.PutUint32(b[dir+5*8:], 0) }},
		{"info-is-not-warning", "", true, func(b []byte, _ int) { binary.LittleEndian.PutUint32(b[0x188+36:], 0xe0000020) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, dir := testpe.Image(false, false)
			tc.change(b, dir)
			path := inputFile(t, b)
			got, problem := (Checker{}).Scan(path, "auto", tc.policy)
			if tc.code == "" && problem != nil {
				t.Fatal(problem)
			}
			if tc.code != "" && (problem == nil || problem.Code != tc.code || problem.Exit != 3) {
				t.Fatalf("got %v, want %s", problem, tc.code)
			}
			if len(got.Issues) == 0 {
				t.Fatal("missing findings")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, b) {
				t.Fatal("input changed", err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("unexpected output file", err)
			}
		})
	}
}

type failingBackend struct{ panicInspect, inspectError bool }

func (b failingBackend) Inspect([]byte) (donut.Info, error) {
	if b.panicInspect {
		panic("not for diagnostics")
	}
	if b.inspectError {
		return donut.Info{}, donut.ErrFileInvalid
	}
	return donut.Info{Type: donut.ModuleEXE, Arch: donut.ArchX64}, nil
}
func (b failingBackend) Compat([]byte) (donut.CompatIssues, error) {
	if b.inspectError {
		panic("Compat must not be called after Inspect fails")
	}
	return nil, errors.New("not for diagnostics")
}

func TestBackendFailuresAreContained(t *testing.T) {
	for _, tc := range []struct {
		b    failingBackend
		code string
	}{
		{failingBackend{panicInspect: true}, "inspection_failed"},
		{failingBackend{inspectError: true}, "invalid_pe"},
		{failingBackend{}, "inspection_failed"},
	} {
		_, _, problem := analyze(tc.b, []byte("fixture"))
		if problem == nil || problem.Code != tc.code {
			t.Fatalf("unexpected error: %v", problem)
		}
	}
}

func TestArchitectureMismatchRetainsFindings(t *testing.T) {
	data, dir := testpe.Image(false, false)
	binary.LittleEndian.PutUint32(data[dir+5*8:], 0)
	binary.LittleEndian.PutUint32(data[0x98+16:], 0)
	result, problem := (Checker{}).Scan(inputFile(t, data), "x86", false)
	if problem == nil || problem.Code != "arch_mismatch" || len(result.Issues) != 2 {
		t.Fatalf("lost findings on architecture mismatch: %+v %v", result, problem)
	}
}

func FuzzStaticPE(f *testing.F) {
	x64, _ := testpe.Image(false, false)
	x86, _ := testpe.Image(true, true)
	f.Add(x64)
	f.Add(x86)
	f.Add([]byte("MZ"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		original := bytes.Clone(data)
		analyze(library{}, data)
		if !bytes.Equal(data, original) {
			t.Fatal("parser modified input")
		}
	})
}
