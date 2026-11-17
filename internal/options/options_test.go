package options

import (
	"reflect"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	got, err := Parse([]string{"-i", "demo.exe"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Input != "demo.exe" || got.Output != "" || got.Arch != "auto" || got.Compress != "none" || got.Entry != "direct" || got.Exit != "thread" {
		t.Fatalf("unexpected defaults: %+v", got)
	}
	if got.Bypass != "continue" || got.Entropy != "none" || got.Headers != "overwrite" || got.Wide {
		t.Fatalf("unexpected runtime defaults: %+v", got)
	}
	if !reflect.DeepEqual(got.Set, map[string]bool{"input": true}) {
		t.Fatalf("unexpected explicit flags: %v", got.Set)
	}
}

func TestAliasesAndExplicitDefaults(t *testing.T) {
	got, err := Parse([]string{"--input=demo.dll", "-o", "demo.bin", "-a=x64", "-z", "lznt1", "-m", "Start", "-p", "--help", "--entry=direct", "--exit", "process", "--force=false", "--warnings-as-errors", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Params != "--help" || got.Help || got.Arch != "x64" || got.Compress != "lznt1" || got.Method != "Start" || got.Entry != "direct" || got.Exit != "process" || got.Force || !got.WarningsAsErrors || !got.JSON {
		t.Fatalf("unexpected parsed options: %+v", got)
	}
	for _, name := range []string{"input", "output", "arch", "compress", "method", "params", "entry", "exit", "force", "warnings-as-errors", "json"} {
		if !got.Set[name] {
			t.Errorf("missing canonical explicit flag %q", name)
		}
	}
	for short := range aliases {
		if got.Set[short] {
			t.Errorf("recorded short alias %q", short)
		}
	}
}

func TestCheckConflictsWithExplicitGenerationFlags(t *testing.T) {
	for _, flag := range []string{"--output=out.bin", "--force=false", "--compress=none", "--method=Start", "--params=test", "--entry=thread", "--exit=thread", "-z=none", "-o=out.bin", "-m=Start", "-p=test", "--bypass=continue", "--entropy=none", "--headers=overwrite", "--wide=false", "-b=none", "-e=full", "-k=keep", "-w"} {
		t.Run(flag, func(t *testing.T) {
			_, err := Parse([]string{"-i", "demo.exe", "-c", flag})
			if err == nil || !strings.Contains(err.Error(), "--check") {
				t.Fatalf("expected check conflict, got %v", err)
			}
		})
	}
	for _, reportFlag := range []string{"--json", "-q"} {
		_, err := Parse([]string{"-i", "demo.exe", "-c", "--arch=x64", "--warnings-as-errors", reportFlag})
		if err != nil {
			t.Fatalf("valid check options: %v", err)
		}
	}
}

func TestInvalidArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing input", nil, "missing input"},
		{"empty input", []string{"--input="}, "--input must not be empty"},
		{"empty output", []string{"-i=x", "--output="}, "--output must not be empty"},
		{"empty method", []string{"-i=x", "--method="}, "--method must not be empty"},
		{"missing value", []string{"--input"}, "missing its value"},
		{"unknown flag", []string{"--inject"}, "unknown option"},
		{"invalid bool", []string{"--json=broken"}, "bad option value"},
		{"positional", []string{"demo.exe"}, "positional"},
		{"subcommand", []string{"generate", "-i=x"}, "subcommands"},
		{"terminator", []string{"--", "--json"}, "positional"},
		{"arch", []string{"-i=x", "--arch=amd64"}, "auto | x86 | x64 | dual"},
		{"compress", []string{"-i=x", "--compress=zip"}, "none | lznt1 | xpress"},
		{"entry", []string{"-i=x", "--entry=process"}, "thread | direct"},
		{"exit", []string{"-i=x", "--exit=direct"}, "thread | process"},
		{"bypass", []string{"-i=x", "--bypass=patch"}, "none | abort | continue"},
		{"entropy", []string{"-i=x", "--entropy=secure"}, "none | random | full"},
		{"headers", []string{"-i=x", "--headers=wipe"}, "overwrite | keep"},
		{"json quiet", []string{"-i=x", "--json", "-q"}, "--json and --quiet"},
		{"input nul", []string{"--input=x\x00.exe"}, "NUL"},
		{"output nul", []string{"-i=x", "--output=x\x00.bin"}, "NUL"},
		{"params nul", []string{"-i=x", "-p=a\x00b"}, "NUL"},
		{"method nul", []string{"-i=x", "-m=a\x00b"}, "NUL"},
		{"params empty", []string{"-i=x", "--params="}, "cannot distinguish"},
		{"params nonascii", []string{"-i=x", "--params=秘密内容"}, "ASCII"},
		{"method nonascii", []string{"-i=x", "--method=启动"}, "ASCII"},
		{"params long", []string{"-i=x", "--params=" + strings.Repeat("a", 251)}, "250"},
		{"method long", []string{"-i=x", "--method=" + strings.Repeat("a", 256)}, "255"},
		{"help syntax", []string{"--help", "--unknown"}, "unknown option"},
		{"help enum", []string{"--help", "--arch=invalid"}, "--arch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
			if strings.Contains(err.Error(), "秘密内容") || strings.Contains(err.Error(), "启动") {
				t.Fatalf("error exposed module parameter text: %v", err)
			}
		})
	}
}

func TestMaximumASCIILengths(t *testing.T) {
	got, err := Parse([]string{"-i=x", "--params=" + strings.Repeat("p", 250), "--method=" + strings.Repeat("m", 255)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Params) != 250 || len(got.Method) != 255 {
		t.Fatal("parser truncated a field")
	}
}

func TestHelpAndVersionSkipRequiredInput(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "-v", "--version"} {
		got, err := Parse([]string{arg})
		if err != nil || (!got.Help && !got.Version) {
			t.Fatalf("%s: %+v, %v", arg, got, err)
		}
	}
}

func TestRepeatedAliasesFollowArgumentOrder(t *testing.T) {
	got, err := Parse([]string{"--input=first.exe", "-i=last.exe", "--json", "--json=false", "--quiet=false"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Input != "last.exe" || got.JSON || !got.Set["json"] || !got.Set["quiet"] {
		t.Fatalf("unexpected repeated flag handling: %+v", got)
	}
}

func TestRequestedJSON(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"demo.exe", "--json"}, false},
		{[]string{"-", "--json"}, false},
		{[]string{"--json", "demo.exe", "--json=false"}, true},
		{[]string{"--unknown", "--json"}, true},
		{[]string{"--unknown", "--json=true"}, true},
		{[]string{"--json", "--json=false"}, false},
		{[]string{"--json=invalid"}, true},
		{[]string{"--json=1"}, true},
		{[]string{"--json=0"}, false},
		{[]string{"--params", "--json"}, false},
		{[]string{"-p", "--json"}, false},
		{[]string{"-p=--json"}, false},
		{[]string{"--params=--json"}, false},
		{[]string{"--input", "--json"}, false},
		{[]string{"--input", "--json", "--json"}, true},
		{[]string{"--params", "--", "--json"}, true},
		{[]string{"--", "--json"}, false},
		{[]string{"--json", "--", "--json=false"}, true},
		{[]string{"--output=--json", "--help"}, false},
		{[]string{"-json"}, true},
	}
	for _, tt := range tests {
		if got := RequestedJSON(tt.args); got != tt.want {
			t.Errorf("RequestedJSON(%q) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestHelpDescribesImplementedScope(t *testing.T) {
	for _, text := range []string{"shellcode-generator.exe", "Convert a native Windows EXE / DLL into position independent binary shellcode", "--bypass", "--entropy", "--headers", "--wide", "--compress", "--check", "ASCII", "never loads or executes its output"} {
		if !strings.Contains(Help, text) {
			t.Errorf("help missing %q", text)
		}
	}
}
