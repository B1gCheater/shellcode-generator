package cli

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B1gCheater/shellcode-generator/internal/testpe"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := Run(args, &out, &err)
	return code, out.String(), err.String()
}

func fixture(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "非 ASCII 文件名.data")
	data, _ := testpe.Image(false, false)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func jsonReport(t *testing.T, out string) Report {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(out))
	var report Report
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err, out)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("extra stdout data: %s", out)
	}
	return report
}

func TestJSONCheckAndNoWrites(t *testing.T) {
	path, before := fixture(t)
	code, out, errOut := run(t, "--input", path, "--check", "--json")
	report := jsonReport(t, out)
	if code != 0 || errOut != "" || report.Status != "checked" || report.Error != nil {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	if report.SchemaVersion != 1 || report.RuntimeVerified || report.Output != nil || report.OutputBytes != nil || report.SHA256 != nil || report.Compression != nil {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Input == nil || *report.Input != path || report.InputBytes == nil || *report.InputBytes != 1024 || report.Issues == nil {
		t.Fatalf("unexpected report: %+v", report)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input changed", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("unexpected new file", err)
	}
}

func TestGeneration(t *testing.T) {
	path, before := fixture(t)
	dir := filepath.Dir(path)
	output := filepath.Join(dir, "out.bin")

	// The happy path: defaults generate a file and report every runtime choice.
	code, out, errOut := run(t, "--input", path, "--output", output, "--json")
	r := jsonReport(t, out)
	if code != 0 || errOut != "" || r.Status != "generated" || r.Error != nil {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	if r.Output == nil || *r.Output != output || r.OutputBytes == nil || *r.OutputBytes == 0 || r.SHA256 == nil {
		t.Fatalf("unexpected generation report: %+v", r)
	}
	if r.Bypass == nil || *r.Bypass != "continue" || r.Entropy == nil || *r.Entropy != "none" ||
		r.Headers == nil || *r.Headers != "overwrite" || r.Wide == nil || *r.Wide ||
		r.Entry == nil || *r.Entry != "direct" || r.Exit == nil || *r.Exit != "thread" {
		t.Fatalf("unexpected runtime fields: %+v", r)
	}
	written, err := os.ReadFile(output)
	if err != nil || len(written) != int(*r.OutputBytes) {
		t.Fatalf("output unreadable: %v", err)
	}
	// A minimum loader pair makes the output far larger than the header-only
	// input; a size in that ballpark proves real shellcode, not a stub.
	if len(written) < 4096 {
		t.Fatalf("suspiciously small payload: %d bytes", len(written))
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input changed", err)
	}

	// entropy none is deterministic: same input, same bytes, same hash.
	first := *r.SHA256
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(t, "--input", path, "--output", output, "--json")
	r2 := jsonReport(t, out)
	if code != 0 || r2.SHA256 == nil || *r2.SHA256 != first {
		t.Fatalf("output not reproducible: %s vs %s", first, deref(r2.SHA256))
	}

	// An existing output refuses without --force and is replaced with it.
	code, out, errOut = run(t, "--input", path, "--output", output, "--json")
	r = jsonReport(t, out)
	if code != 5 || r.Error == nil || r.Error.Code != "output_exists" {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	code, out, errOut = run(t, "--input", path, "--output", output, "--force", "--json")
	r = jsonReport(t, out)
	if code != 0 || r.Status != "generated" {
		t.Fatalf("%d %s %s", code, out, errOut)
	}

	// Output equal to input is refused even with --force.
	code, out, _ = run(t, "-i", path, "-o", path, "--force", "--json")
	r = jsonReport(t, out)
	if code != 5 || r.Error == nil || r.Error.Code != "output_is_input" {
		t.Fatalf("%d %s", code, out)
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input overwritten")
	}

	// The temporary write leaves nothing behind in the output directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".shellcode-generator-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestGenerationRuntimeOptionsAndDefaults(t *testing.T) {
	path, _ := fixture(t)
	dir := filepath.Dir(path)

	// Explicit runtime options land in the report.
	output := filepath.Join(dir, "tuned.bin")
	code, out, errOut := run(t, "-i", path, "-o", output, "--json",
		"--bypass", "abort", "--entropy", "full", "--headers", "keep", "--wide")
	r := jsonReport(t, out)
	if code != 0 || r.Status != "generated" {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	if *r.Bypass != "abort" || *r.Entropy != "full" || *r.Headers != "keep" || !*r.Wide {
		t.Fatalf("runtime options not propagated: %+v", r)
	}
	// Encrypted output is nondeterministic by design.
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(t, "-i", path, "-o", output, "--json", "--entropy", "full")
	r2 := jsonReport(t, out)
	if code != 0 || r2.SHA256 == nil || *r2.SHA256 == *r.SHA256 {
		t.Fatal("entropy full produced identical output")
	}

	// The default output name is <input base>.bin in the working directory.
	wd := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(oldWd) })
	code, out, errOut = run(t, "--input", path, "--json")
	r = jsonReport(t, out)
	if code != 0 || r.Status != "generated" || r.Output == nil || filepath.Base(*r.Output) != "非 ASCII 文件名.bin" {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(wd, "非 ASCII 文件名.bin")); err != nil {
		t.Fatalf("default output missing: %v", err)
	}
}

func TestErrorContracts(t *testing.T) {
	path, _ := fixture(t)
	for _, tc := range []struct {
		name      string
		args      []string
		exit      int
		errorCode string
	}{
		{"no-input", []string{"--check", "--json"}, 1, "invalid_arguments"},
		{"unknown-before-json", []string{"--bad", "--json"}, 1, "invalid_arguments"},
		{"json-quiet-conflict", []string{"--json", "--quiet", "--check", "-i", path}, 1, "invalid_arguments"},
		{"explicit-default-in-check", []string{"-i", path, "--check", "--compress=none", "--json"}, 1, "invalid_arguments"},
		{"missing-file", []string{"-i", filepath.Join(t.TempDir(), "missing"), "--check", "--json"}, 2, "input_not_found"},
		{"wrong-arch", []string{"-i", path, "--check", "--arch=x86", "--json"}, 3, "arch_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := run(t, tc.args...)
			r := jsonReport(t, out)
			if code != tc.exit || errOut != "" || r.Status != "error" || r.Error == nil || r.Error.Code != tc.errorCode || r.Issues == nil || r.RuntimeVerified {
				t.Fatalf("%d %s %s", code, out, errOut)
			}
		})
	}
}

func TestParamPrivacyAndHelpAsValue(t *testing.T) {
	secret := strings.Repeat("PRIVATE_PARAMETER", 30)
	code, out, errOut := run(t, "--input", "unused", "--params", secret, "--json")
	if code != 1 || strings.Contains(out+errOut, "PRIVATE_PARAMETER") {
		t.Fatalf("parameter disclosure: %d %s %s", code, out, errOut)
	}
	// The token after --params belongs to it even when it names a flag; the run
	// then fails on the missing input instead of showing help or JSON.
	code, out, errOut = run(t, "--input", "unused", "--params", "--help", "--json")
	if code != 2 || out == "" || strings.Contains(out+errOut, "Usage:") {
		t.Fatalf("help value misparsed: %d %s %s", code, out, errOut)
	}
	r := jsonReport(t, out)
	if r.Error == nil || r.Error.Code != "input_not_found" {
		t.Fatalf("expected input_not_found: %+v", r)
	}
	code, _, errOut = run(t, "--input", "unused", "--params", "--json")
	if code != 2 || !strings.Contains(errOut, "input_not_found") {
		t.Fatalf("json value misparsed: %d %s", code, errOut)
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, mode := range []string{"help", "version"} {
		code, out, errOut := run(t, "--"+mode)
		if code != 0 || out == "" || errOut != "" {
			t.Fatalf("%d %s %s", code, out, errOut)
		}
		code, out, errOut = run(t, "--"+mode, "--json")
		r := jsonReport(t, out)
		if code != 0 || errOut != "" || r.Status != mode || r.ProgramVersion != Version || r.RuntimeVerified {
			t.Fatalf("%d %s %s", code, out, errOut)
		}
		if mode == "version" && (r.LibraryVersion != pinnedVersion || r.LibraryModule != dependency) {
			t.Fatalf("wrong dependency info: %+v", r)
		}
	}
}

func TestQuietPreservesWarnings(t *testing.T) {
	path, data := fixture(t)
	// Missing relocation metadata yields a warning in the fixed dependency.
	binary.LittleEndian.PutUint32(data[0x98+112+5*8:], 0)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "-i", path, "--check", "--quiet")
	if code != 0 || out != "" || !strings.Contains(errOut, "no_relocations") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	code, out, errOut = run(t, "-i", path, "--check", "--quiet", "--warnings-as-errors")
	if code != 3 || out != "" || !strings.Contains(errOut, "warnings_as_errors") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReportWriteFailures(t *testing.T) {
	var errOut bytes.Buffer
	if code := Run([]string{"--version", "--json"}, brokenWriter{}, &errOut); code != 5 || !strings.Contains(errOut.String(), "report_write") {
		t.Fatalf("%d %s", code, errOut.String())
	}
	errOut.Reset()
	if code := Run([]string{"--help"}, brokenWriter{}, &errOut); code != 5 {
		t.Fatalf("exit=%d", code)
	}
	if code := Run([]string{}, io.Discard, brokenWriter{}); code != 5 {
		t.Fatalf("exit=%d", code)
	}
}
