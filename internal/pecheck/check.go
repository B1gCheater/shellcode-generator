// Package pecheck reads PE metadata without loading, modifying or executing it.
package pecheck

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/B1gCheater/shellcode-lib-go/donut"
)

// MaxInputBytes bounds memory use before a file is read into memory.
const MaxInputBytes int64 = 256 << 20

type Issue struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Result struct {
	Input        string
	ModuleType   string
	PayloadArch  string
	LoaderArch   string
	InputBytes   int64
	ReadComplete bool
	Data         []byte
	Issues       []Issue
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Exit    int    `json:"-"`
}

func (e *Error) Error() string { return e.Message }

// backend deliberately exposes only the library's static inspection API.
type backend interface {
	Inspect([]byte) (donut.Info, error)
	Compat([]byte) (donut.CompatIssues, error)
}

type library struct{}

func (library) Inspect(data []byte) (donut.Info, error)        { return donut.Inspect(data) }
func (library) Compat(data []byte) (donut.CompatIssues, error) { return donut.Compat(data) }

// Checker's zero value is ready for use. The limit and backend are test seams.
type Checker struct {
	backend backend
	limit   int64
}

func failure(code, message string, exit int) *Error {
	return &Error{Code: code, Message: message, Exit: exit}
}

// Scan returns known static findings. A successful scan does not verify runtime
// compatibility, and never constructs an executable payload.
func (c Checker) Scan(path, arch string, warningsAsErrors bool) (Result, *Error) {
	result := Result{Issues: make([]Issue, 0)}
	if strings.Contains(path, "://") {
		return result, failure("input_url", "input must be a local file path, not a URL", 2)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return result, failure("input_path", "cannot resolve the input path", 2)
	}
	result.Input = filepath.Clean(absolute)
	// Reject nonregular objects before opening, including pipes and devices.
	before, err := os.Stat(result.Input)
	if err != nil {
		return result, readError(err)
	}
	if !before.Mode().IsRegular() {
		return result, failure("input_not_regular", "input must be a regular file", 2)
	}
	f, err := os.Open(result.Input)
	if err != nil {
		return result, readError(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return result, readError(err)
	}
	if !stat.Mode().IsRegular() {
		return result, failure("input_not_regular", "input must be a regular file", 2)
	}
	if !os.SameFile(before, stat) {
		return result, failure("input_changed", "the input file was replaced during inspection; please retry", 2)
	}
	limit := c.limit
	if limit <= 0 {
		limit = MaxInputBytes
	}
	if stat.Size() > limit {
		return result, failure("input_too_large", "input exceeds the maximum file size (256 MiB)", 2)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return result, readError(err)
	}
	if int64(len(data)) > limit {
		return result, failure("input_too_large", "input exceeds the maximum file size (256 MiB)", 2)
	}
	after, err := f.Stat()
	if err != nil {
		return result, readError(err)
	}
	if stat.Size() != after.Size() || stat.ModTime() != after.ModTime() || after.Size() != int64(len(data)) {
		return result, failure("input_changed", "the input content changed during inspection; please retry", 2)
	}
	result.InputBytes = int64(len(data))
	result.ReadComplete = true
	result.Data = data
	b := c.backend
	if b == nil {
		b = library{}
	}
	info, issues, inspectionError := analyze(b, data)
	if inspectionError != nil {
		return result, inspectionError
	}
	result.ModuleType = "exe"
	if info.Type == donut.ModuleDLL {
		result.ModuleType = "dll"
	}
	result.PayloadArch = "x64"
	if info.Arch == donut.ArchX86 {
		result.PayloadArch = "x86"
	}
	result.LoaderArch = arch
	if arch == "auto" {
		result.LoaderArch = result.PayloadArch
	}
	blockers, warnings := 0, 0
	for _, issue := range issues {
		result.Issues = append(result.Issues, Issue{
			Level: issue.Level.String(), Code: string(issue.Code), Message: issue.Detail,
		})
		switch issue.Level {
		case donut.CompatBlock:
			blockers++
		case donut.CompatWarning:
			warnings++
		}
	}
	if arch != "auto" && arch != "dual" && arch != result.PayloadArch {
		return result, failure("arch_mismatch", "the requested architecture does not match the input PE", 3)
	}
	if blockers > 0 {
		return result, failure("compatibility_blocked", "static inspection found known blocking issues", 3)
	}
	if warningsAsErrors && warnings > 0 {
		return result, failure("warnings_as_errors", "compatibility warnings treated as failures by the current policy", 3)
	}
	return result, nil
}

func readError(err error) *Error {
	if errors.Is(err, os.ErrNotExist) {
		return failure("input_not_found", "input file does not exist", 2)
	}
	if errors.Is(err, os.ErrPermission) {
		return failure("input_permission", "permission denied reading the input file", 2)
	}
	return failure("input_read", "cannot read the input file", 2)
}

func analyze(b backend, data []byte) (info donut.Info, issues donut.CompatIssues, problem *Error) {
	// Isolate an unexpected parser panic as an input failure without disclosing
	// memory, file contents or application arguments in diagnostics.
	defer func() {
		if recover() != nil {
			problem = failure("inspection_failed", "the library failed to parse this file safely", 2)
		}
	}()
	var err error
	info, err = b.Inspect(data)
	if err != nil {
		if errors.Is(err, donut.ErrManagedImage) {
			return info, nil, failure("managed_image", "only native PE images are supported; .NET assemblies are not", 2)
		}
		return info, nil, failure("invalid_pe", "the input is not a supported native x86/x64 PE file, or the file is corrupt", 2)
	}
	issues, err = b.Compat(data)
	if err != nil {
		return info, nil, failure("inspection_failed", "the library could not complete the static compatibility inspection", 2)
	}
	return info, issues, nil
}
