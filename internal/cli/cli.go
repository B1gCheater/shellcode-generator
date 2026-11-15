// Package cli coordinates parsing, static inspection, payload generation and
// report formatting. It writes files only: loading and executing the result is
// the caller's business.
package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/B1gCheater/shellcode-lib-go/donut"

	"github.com/B1gCheater/shellcode-generator/internal/options"
	"github.com/B1gCheater/shellcode-generator/internal/pecheck"
)

const (
	Version       = "0.1.0"
	dependency    = "github.com/B1gCheater/shellcode-lib-go"
	pinnedVersion = "v0.0.0-20261114201049-a921e080cff3"
)

// Report is the versioned machine interface. Nonapplicable fields are null;
// issues is always an array, including on parser errors.
type Report struct {
	SchemaVersion   int             `json:"schema_version"`
	Status          string          `json:"status"`
	Input           *string         `json:"input"`
	Output          *string         `json:"output"`
	ModuleType      *string         `json:"module_type"`
	PayloadArch     *string         `json:"payload_arch"`
	LoaderArch      *string         `json:"loader_arch"`
	Compression     *string         `json:"compression"`
	Bypass          *string         `json:"bypass"`
	Entropy         *string         `json:"entropy"`
	Headers         *string         `json:"headers"`
	Wide            *bool           `json:"wide"`
	Entry           *string         `json:"entry"`
	Exit            *string         `json:"exit"`
	InputBytes      *int64          `json:"input_bytes"`
	OutputBytes     *int64          `json:"output_bytes"`
	SHA256          *string         `json:"sha256"`
	Issues          []pecheck.Issue `json:"issues"`
	RuntimeVerified bool            `json:"runtime_verified"`
	Error           *pecheck.Error  `json:"error"`
	ProgramVersion  string          `json:"program_version,omitempty"`
	LibraryModule   string          `json:"library_module,omitempty"`
	LibraryVersion  string          `json:"library_version,omitempty"`
	Help            string          `json:"help,omitempty"`
}

func newReport() Report {
	return Report{SchemaVersion: 1, Status: "error", Issues: make([]pecheck.Issue, 0)}
}

// Run never loads or executes its input.
func Run(args []string, stdout, stderr io.Writer) int {
	opts, err := options.Parse(args)
	report := newReport()
	jsonMode := opts.JSON
	if err != nil {
		jsonMode = options.RequestedJSON(args)
		report.Error = &pecheck.Error{Code: "invalid_arguments", Message: err.Error(), Exit: 1}
		return emit(report, jsonMode, false, stdout, stderr)
	}
	if opts.Help {
		report.Status = "help"
		report.ProgramVersion = Version
		report.Help = options.Help
		return emit(report, jsonMode, false, stdout, stderr)
	}
	if opts.Version {
		report.Status = "version"
		report.ProgramVersion = Version
		report.LibraryModule = dependency
		report.LibraryVersion = libraryVersion()
		return emit(report, jsonMode, false, stdout, stderr)
	}
	if opts.Check {
		result, problem := (pecheck.Checker{}).Scan(opts.Input, opts.Arch, opts.WarningsAsErrors)
		report.Input = stringPointer(result.Input)
		report.ModuleType = stringPointer(result.ModuleType)
		report.PayloadArch = stringPointer(result.PayloadArch)
		report.LoaderArch = stringPointer(result.LoaderArch)
		if result.ReadComplete {
			report.InputBytes = &result.InputBytes
		}
		report.Issues = result.Issues
		report.Error = problem
		if problem == nil {
			report.Status = "checked"
		}
		return emit(report, jsonMode, opts.Quiet, stdout, stderr)
	}
	return generate(opts, &report, jsonMode, stdout, stderr)
}

// generate inspects the input, builds the payload and writes it atomically.
func generate(opts options.Options, report *Report, jsonMode bool, stdout, stderr io.Writer) int {
	result, problem := (pecheck.Checker{}).Scan(opts.Input, opts.Arch, opts.WarningsAsErrors)
	applyScan(report, result)
	report.Issues = result.Issues
	if problem != nil {
		report.Error = problem
		return emit(*report, jsonMode, opts.Quiet, stdout, stderr)
	}

	// The scan already refuses known blockers and, requested, warnings; Strict
	// makes the library refuse the same set as a second gate.
	cfg := donutConfig(opts, result)
	report.Compression = stringPointer(opts.Compress)
	report.Bypass = stringPointer(opts.Bypass)
	report.Entropy = stringPointer(opts.Entropy)
	report.Headers = stringPointer(opts.Headers)
	report.Entry = stringPointer(opts.Entry)
	report.Exit = stringPointer(opts.Exit)
	wide := opts.Wide
	report.Wide = &wide
	pic, err := donut.Build(cfg)
	if err != nil {
		report.Error = buildError(err)
		return emit(*report, jsonMode, opts.Quiet, stdout, stderr)
	}
	if lost := cfg.TruncatedFields(); len(lost) > 0 {
		// Unreachable while the CLI rejects over-long input itself; kept as a
		// belt-and-braces refusal instead of a silent truncation.
		report.Error = &pecheck.Error{Code: "params_too_long", Exit: 4,
			Message: "parameters exceed the library's field width; refused instead of truncated"}
		return emit(*report, jsonMode, opts.Quiet, stdout, stderr)
	}

	target, problem := resolveOutput(opts, result.Input)
	if problem != nil {
		report.Error = problem
		return emit(*report, jsonMode, opts.Quiet, stdout, stderr)
	}
	if problem := writeAtomic(target, pic); problem != nil {
		report.Error = problem
		return emit(*report, jsonMode, opts.Quiet, stdout, stderr)
	}

	sum := sha256.Sum256(pic)
	outputBytes := int64(len(pic))
	output := target
	report.Status = "generated"
	report.Output = &output
	report.OutputBytes = &outputBytes
	report.SHA256 = stringPointer(fmt.Sprintf("%x", sum))
	report.Error = nil
	return emit(*report, jsonMode, opts.Quiet, stdout, stderr)
}

// applyScan copies the inspection half of the result into the report.
func applyScan(report *Report, result pecheck.Result) {
	report.Input = stringPointer(result.Input)
	report.ModuleType = stringPointer(result.ModuleType)
	report.PayloadArch = stringPointer(result.PayloadArch)
	report.LoaderArch = stringPointer(result.LoaderArch)
	report.Compression = nil
	if result.ReadComplete {
		report.InputBytes = &result.InputBytes
	}
}

// donutConfig maps CLI option names onto library constants. Every field is set
// explicitly; nothing relies on the library's own defaults.
func donutConfig(opts options.Options, result pecheck.Result) donut.Config {
	cfg := donut.DefaultConfig(result.Data)
	cfg.Strict = true
	switch opts.Arch {
	case "x86":
		cfg.Arch = donut.ArchX86
	case "x64":
		cfg.Arch = donut.ArchX64
	case "dual":
		cfg.Arch = donut.ArchX84
	default:
		cfg.Arch = donut.ArchX64
		if result.PayloadArch == "x86" {
			cfg.Arch = donut.ArchX86
		}
	}
	switch opts.Compress {
	case "lznt1":
		cfg.Compress = donut.CompressLZNT1
	case "xpress":
		cfg.Compress = donut.CompressXpress
	default:
		cfg.Compress = donut.CompressNone
	}
	switch opts.Bypass {
	case "none":
		cfg.Bypass = donut.BypassNone
	case "abort":
		cfg.Bypass = donut.BypassAbort
	default:
		cfg.Bypass = donut.BypassContinue
	}
	switch opts.Entropy {
	case "random":
		cfg.Entropy = donut.EntropyRandom
	case "full":
		cfg.Entropy = donut.EntropyDefault
	default:
		cfg.Entropy = donut.EntropyNone
	}
	switch opts.Headers {
	case "keep":
		cfg.Headers = donut.HeadersKeep
	default:
		cfg.Headers = donut.HeadersOverwrite
	}
	switch opts.Exit {
	case "process":
		cfg.ExitOpt = donut.ExitProcess
	default:
		cfg.ExitOpt = donut.ExitThread
	}
	if opts.Entry == "thread" && result.ModuleType == "exe" {
		cfg.Thread = 1
	}
	cfg.Method = opts.Method
	cfg.Args = opts.Params
	cfg.ArgsWide = opts.Wide
	return cfg
}

// buildError maps library failures onto the documented exit codes.
func buildError(err error) *pecheck.Error {
	switch {
	case errors.Is(err, donut.ErrDLLFunction):
		return &pecheck.Error{Code: "export_not_found", Exit: 4,
			Message: "the named DLL export does not exist (names are case sensitive)"}
	case errors.Is(err, donut.ErrDLLParam):
		return &pecheck.Error{Code: "params_without_method", Exit: 4,
			Message: "parameters were given for a DLL without --method; there is no export to receive them"}
	case errors.Is(err, donut.ErrArchMismatch):
		return &pecheck.Error{Code: "arch_mismatch", Exit: 3,
			Message: "the target architecture cannot host the input's bitness"}
	case errors.Is(err, donut.ErrCompression):
		return &pecheck.Error{Code: "compression_failed", Exit: 4, Message: err.Error()}
	case errors.Is(err, donut.ErrIncompatiblePayload):
		return &pecheck.Error{Code: "compatibility_blocked", Exit: 3, Message: err.Error()}
	default:
		return &pecheck.Error{Code: "build_failed", Exit: 4, Message: err.Error()}
	}
}

// resolveOutput decides where the payload goes and whether it may go there.
func resolveOutput(opts options.Options, input string) (string, *pecheck.Error) {
	target := opts.Output
	if target == "" {
		base := filepath.Base(input)
		target = strings.TrimSuffix(base, filepath.Ext(base)) + ".bin"
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return "", &pecheck.Error{Code: "output_path", Exit: 5, Message: "cannot resolve the output path"}
	}
	target = filepath.Clean(absolute)

	if strings.EqualFold(target, input) {
		return "", &pecheck.Error{Code: "output_is_input", Exit: 5,
			Message: "the output path is the same as the input file; refusing to overwrite the input"}
	}
	if dir := filepath.Dir(target); dir != "" {
		if _, err := os.Stat(dir); err != nil {
			return "", &pecheck.Error{Code: "output_dir_missing", Exit: 5,
				Message: "the output directory does not exist; create it first"}
		}
	}
	if _, err := os.Stat(target); err == nil && !opts.Force {
		return "", &pecheck.Error{Code: "output_exists", Exit: 5,
			Message: "output file already exists: " + target + "; pass --force to overwrite"}
	}
	return target, nil
}

// writeAtomic writes through a same-directory temporary file so a failure
// never leaves a half-written payload behind or damages an existing one. The
// final rename replaces an existing --force target non-atomically on Windows;
// the content is complete by then, so no half-payload is ever observable.
func writeAtomic(target string, pic []byte) *pecheck.Error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".shellcode-generator-*.tmp")
	if err != nil {
		return &pecheck.Error{Code: "output_write", Exit: 5, Message: "cannot create a temporary output file"}
	}
	name := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(name) }
	if _, err := tmp.Write(pic); err != nil {
		cleanup()
		return &pecheck.Error{Code: "output_write", Exit: 5, Message: "cannot write the temporary output file"}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return &pecheck.Error{Code: "output_write", Exit: 5, Message: "cannot write the temporary output file"}
	}
	if _, err := os.Stat(target); err == nil {
		if err := os.Remove(target); err != nil {
			os.Remove(name)
			return &pecheck.Error{Code: "output_replace", Exit: 5, Message: "cannot replace the existing output file"}
		}
	}
	if err := os.Rename(name, target); err != nil {
		os.Remove(name)
		return &pecheck.Error{Code: "output_write", Exit: 5, Message: "cannot write the output file: " + target}
	}
	return nil
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func libraryVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == dependency {
				if dep.Replace != nil {
					return dep.Version + " (replaced)"
				}
				return dep.Version
			}
		}
	}
	// The Go test executable may omit dependency build metadata.
	return pinnedVersion
}

func emit(report Report, jsonMode, quiet bool, stdout, stderr io.Writer) int {
	exit := 0
	if report.Error != nil {
		exit = report.Error.Exit
	}
	if jsonMode {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(stderr, "error [report_write] cannot write the JSON report")
			return 5
		}
		return exit
	}
	for _, issue := range report.Issues {
		if issue.Level == "info" && quiet {
			continue
		}
		if _, err := fmt.Fprintf(stderr, "%s [%s] %s\n", issue.Level, issue.Code, issue.Message); err != nil {
			return 5
		}
	}
	if report.Error != nil {
		if _, err := fmt.Fprintf(stderr, "error [%s] %s\n", report.Error.Code, report.Error.Message); err != nil {
			return 5
		}
		return exit
	}
	if quiet {
		return exit
	}
	var err error
	switch report.Status {
	case "help":
		_, err = fmt.Fprintf(stdout, "shellcode-generator %s\n\n%s", Version, report.Help)
	case "version":
		_, err = fmt.Fprintf(stdout, "shellcode-generator %s\n%s %s\n", Version, report.LibraryModule, report.LibraryVersion)
	case "checked":
		_, err = fmt.Fprintf(stdout, "Check complete: %s\nModule: %s; PE arch: %s; requested arch: %s\nInput: %d bytes; static issues: %d\nRuntime compatibility: not verified.\n",
			*report.Input, *report.ModuleType, *report.PayloadArch, *report.LoaderArch, *report.InputBytes, len(report.Issues))
	case "generated":
		err = emitGenerated(report, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error [report_write] cannot write the report")
		return 5
	}
	return exit
}

// emitGenerated prints the human-readable generation summary.
func emitGenerated(report Report, stdout io.Writer) error {
	lines := [][2]string{
		{"Input", *report.Input},
		{"Module", *report.ModuleType + " / " + *report.PayloadArch},
		{"Output arch", *report.LoaderArch},
		{"Compression", deref(report.Compression)},
		{"Entry", deref(report.Entry)},
		{"Exit", deref(report.Exit)},
		{"PE headers", deref(report.Headers)},
		{"Bypass", deref(report.Bypass)},
		{"Entropy", deref(report.Entropy)},
		{"Params enc", ansiOrWide(report.Wide)},
	}
	for _, l := range lines {
		if _, err := fmt.Fprintf(stdout, "%-12s %s\n", l[0], l[1]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "%-12s %d blockers, %d warnings\n", "Compat", countLevel(report.Issues, "block"), countLevel(report.Issues, "warning")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%-12s %s\n", "Generated", deref(report.Output)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%-12s %d bytes\n", "Input size", *report.InputBytes); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%-12s %d bytes\n", "Output size", *report.OutputBytes); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%-12s %s\n", "SHA-256", deref(report.SHA256)); err != nil {
		return err
	}
	_, err := fmt.Fprint(stdout, "\nNote: file generated; runtime compatibility is not verified.\n")
	return err
}

func deref(value *string) string {
	if value == nil {
		return "-"
	}
	return *value
}

func ansiOrWide(wide *bool) string {
	if wide != nil && *wide {
		return "UTF-16 (--wide)"
	}
	return "ANSI"
}

func countLevel(issues []pecheck.Issue, level string) int {
	count := 0
	for _, issue := range issues {
		if issue.Level == level {
			count++
		}
	}
	return count
}
