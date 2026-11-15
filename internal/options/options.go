// Package options parses and validates the public command-line interface.
package options

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Options contains user input. Set records explicitly supplied flags using their
// canonical long names, including flags explicitly set to their default values.
type Options struct {
	Input            string
	Output           string
	Arch             string
	Compress         string
	Method           string
	Params           string
	Entry            string
	Exit             string
	Bypass           string
	Entropy          string
	Headers          string
	Wide             bool
	Force            bool
	Check            bool
	WarningsAsErrors bool
	JSON             bool
	Quiet            bool
	Help             bool
	Version          bool
	Set              map[string]bool
}

var aliases = map[string]string{
	"i": "input", "o": "output", "a": "arch", "z": "compress",
	"m": "method", "p": "params", "c": "check", "q": "quiet",
	"b": "bypass", "e": "entropy", "k": "headers", "w": "wide",
	"h": "help", "v": "version",
}

var stringFlags = map[string]bool{
	"input": true, "output": true, "arch": true, "compress": true,
	"method": true, "params": true, "entry": true, "exit": true,
	"bypass": true, "entropy": true, "headers": true,
}

func canonical(name string) string {
	if long, ok := aliases[name]; ok {
		return long
	}
	return name
}

// Parse parses flags without reading files or performing any generation.
// Errors never include supplied module parameter text.
func Parse(args []string) (Options, error) {
	opts := Options{
		Arch: "auto", Compress: "none", Entry: "thread", Exit: "thread",
		Bypass: "continue", Entropy: "none", Headers: "overwrite",
		Set: make(map[string]bool),
	}
	fs := flag.NewFlagSet("shellcode-generator", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addString := func(target *string, long, short string) {
		fs.StringVar(target, long, *target, "")
		if short != "" {
			fs.StringVar(target, short, *target, "")
		}
	}
	addBool := func(target *bool, long, short string) {
		fs.BoolVar(target, long, false, "")
		if short != "" {
			fs.BoolVar(target, short, false, "")
		}
	}
	addString(&opts.Input, "input", "i")
	addString(&opts.Output, "output", "o")
	addString(&opts.Arch, "arch", "a")
	addString(&opts.Compress, "compress", "z")
	addString(&opts.Method, "method", "m")
	addString(&opts.Params, "params", "p")
	addString(&opts.Entry, "entry", "")
	addString(&opts.Exit, "exit", "")
	addString(&opts.Bypass, "bypass", "b")
	addString(&opts.Entropy, "entropy", "e")
	addString(&opts.Headers, "headers", "k")
	addBool(&opts.Wide, "wide", "w")
	addBool(&opts.Force, "force", "")
	addBool(&opts.Check, "check", "c")
	addBool(&opts.WarningsAsErrors, "warnings-as-errors", "")
	addBool(&opts.JSON, "json", "")
	addBool(&opts.Quiet, "quiet", "q")
	addBool(&opts.Help, "help", "h")
	addBool(&opts.Version, "version", "v")

	parseErr := fs.Parse(args)
	fs.Visit(func(f *flag.Flag) { opts.Set[canonical(f.Name)] = true })
	if parseErr != nil {
		return opts, syntaxError(parseErr)
	}
	if fs.NArg() != 0 {
		return opts, errors.New("positional arguments and subcommands are not accepted; use --input to name the input file")
	}
	if err := validate(opts); err != nil {
		return opts, err
	}
	return opts, nil
}

func syntaxError(err error) error {
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "flag needs an argument:"):
		return errors.New("invalid arguments: an option is missing its value; use --help for usage")
	case strings.HasPrefix(message, "flag provided but not defined:"):
		return errors.New("invalid arguments: unknown option; use --help for the supported options")
	default:
		return errors.New("invalid arguments: bad option value; boolean options accept true or false")
	}
}

func validate(opts Options) error {
	for _, field := range []struct{ name, value string }{
		{"input", opts.Input}, {"output", opts.Output},
		{"method", opts.Method}, {"params", opts.Params},
	} {
		if strings.IndexByte(field.value, 0) >= 0 {
			return fmt.Errorf("--%s must not contain NUL bytes", field.name)
		}
	}
	for _, enum := range []struct {
		name, value string
		allowed     []string
	}{
		{"arch", opts.Arch, []string{"auto", "x86", "x64", "dual"}},
		{"compress", opts.Compress, []string{"none", "lznt1", "xpress"}},
		{"entry", opts.Entry, []string{"thread", "direct"}},
		{"exit", opts.Exit, []string{"thread", "process"}},
		{"bypass", opts.Bypass, []string{"none", "abort", "continue"}},
		{"entropy", opts.Entropy, []string{"none", "random", "full"}},
		{"headers", opts.Headers, []string{"overwrite", "keep"}},
	} {
		valid := false
		for _, value := range enum.allowed {
			valid = valid || enum.value == value
		}
		if !valid {
			return fmt.Errorf("--%s accepts only: %s", enum.name, strings.Join(enum.allowed, " | "))
		}
	}
	if opts.JSON && opts.Quiet {
		return errors.New("--json and --quiet cannot be combined")
	}
	if opts.Set["input"] && opts.Input == "" {
		return errors.New("--input must not be empty")
	}
	if opts.Set["output"] && opts.Output == "" {
		return errors.New("--output must not be empty")
	}
	if opts.Set["method"] && opts.Method == "" {
		return errors.New("--method must not be empty")
	}
	if len(opts.Method) > 255 {
		return errors.New("--method allows at most 255 bytes; nothing is silently truncated")
	}
	if !isASCII(opts.Method) {
		return errors.New("--method accepts ASCII export names only")
	}
	if opts.Set["params"] && opts.Params == "" {
		return errors.New("the library cannot distinguish an empty --params from no --params; omit --params or pass a non-empty value")
	}
	if len(opts.Params) > 250 {
		return errors.New("--params allows at most 250 bytes; nothing is silently truncated")
	}
	if !isASCII(opts.Params) {
		return errors.New("the library does not fully support Unicode parameters yet; --params accepts ASCII text only for now")
	}
	if opts.Check {
		for _, name := range []string{"output", "force", "compress", "method", "params", "entry", "exit", "bypass", "entropy", "headers", "wide"} {
			if opts.Set[name] {
				return fmt.Errorf("--check cannot be combined with an explicit --%s", name)
			}
		}
	}
	if opts.Input == "" && !opts.Help && !opts.Version {
		return errors.New("missing input file: use --input <file>, or --help for usage")
	}
	return nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

// RequestedJSON discovers the requested error format even if parsing failed
// before --json was reached. Known string options consume their next token,
// including tokens that look like flags. A bare -- ends option processing.
func RequestedJSON(args []string) bool {
	requested := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			break
		}
		name := strings.TrimPrefix(arg, "-")
		name = strings.TrimPrefix(name, "-")
		name, value, inline := strings.Cut(name, "=")
		name = canonical(name)
		if stringFlags[name] {
			if !inline && i+1 < len(args) {
				i++
			}
			continue
		}
		if name == "json" {
			if !inline {
				requested = true
				continue
			}
			parsed, err := strconv.ParseBool(value)
			// An invalid JSON switch still requests a structured parse error.
			requested = err != nil || parsed
		}
	}
	return requested
}

// Help describes the implemented interface.
const Help = `shellcode-generator
Convert a native Windows EXE / DLL into position independent binary shellcode.

Usage:
  shellcode-generator.exe --input <file> [options]
  shellcode-generator.exe --input <file> --check [report options]
  shellcode-generator.exe --help
  shellcode-generator.exe --version

Input and output:
  -i, --input <file>           input native PE file (required)
  -o, --output <file>          output path; default: <input name>.bin in the
                               current directory
  -a, --arch <arch>            auto | x86 | x64 | dual (default: auto)
  -z, --compress <mode>        none | lznt1 | xpress (default: none)
      --force                  overwrite an existing output file

Module parameters:
  -m, --method <export>        DLL export to call, case sensitive
  -p, --params <text>          EXE command line, or the DLL export's single
                               string argument
      --entry <mode>           EXE entry: thread | direct (default: thread)
      --exit <mode>            after the module returns: thread | process
                               (default: thread; process terminates the host)
  -w, --wide                   pass params to the DLL export as UTF-16
                               instead of ANSI

Runtime behaviour:
  -b, --bypass <policy>        AMSI/WLDP/ETW: none | abort | continue
                               (default: continue; failures do not stop load)
  -e, --entropy <level>        none | random | full (default: none)
                               none:   no randomisation, no encryption;
                                       reproducible output, hash-comparable
                               random: randomise the command-line placeholder
                               full:   placeholder randomisation plus
                                       instance encryption
  -k, --headers <mode>         mapped PE headers: overwrite | keep
                               (default: overwrite)

Inspection and reporting:
  -c, --check                  inspect only; no output file is written
      --warnings-as-errors     treat compatibility warnings as failures
      --json                   emit a JSON report for machine consumption
  -q, --quiet                  hide the regular summary; warnings and errors
                               still print

Other:
  -h, --help                   show this help and exit
  -v, --version                show program and library versions and exit

Examples:
  shellcode-generator.exe -i demo.exe
  shellcode-generator.exe -i demo.exe -o output\demo.bin --force
  shellcode-generator.exe -i demo.exe --check
  shellcode-generator.exe -i demo.dll --method Start --params "mode=test" -w
  shellcode-generator.exe -i demo.exe --compress lznt1 --entropy full
  shellcode-generator.exe -i demo.exe --bypass none --headers keep --json

Notes:
  Only native EXE / DLL images are supported; .NET assemblies, scripts and
  URLs are not. auto picks the architecture from the PE content; dual does
  not convert the module's bitness. Known blocking issues refuse generation;
  no blockers do not guarantee runtime compatibility. Over-long parameters
  are rejected, never silently truncated; ASCII text only for now. The
  generator only writes files; it never loads or executes its output.
  --check cannot be combined with generation options, even at their default
  values. --json and --quiet are mutually exclusive. Positional arguments
  are not accepted.
`
