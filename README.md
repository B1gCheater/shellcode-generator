# shellcode-generator

Convert a native Windows EXE / DLL into position independent binary shellcode.

Built on the full feature set of [shellcode-lib-go](https://github.com/B1gCheater/shellcode-lib-go):
architecture selection, LZNT1/XPRESS compression, AMSI/WLDP/ETW bypass policy,
instance randomisation and encryption, PE header handling, thread entry, exit
semantics and wide-character parameters.

The generator runs on Windows and Linux; the payload it produces always targets
Windows only.

## Build

Release scripts build both platform binaries into `./release` and print their
SHA-256 sums (static builds, `CGO_ENABLED=0`):

```powershell
.\build-release.ps1   # Windows
./build-release.sh    # Linux / macOS / WSL
```

Manual build and checks:

```powershell
go build -trimpath -ldflags "-s -w" -o shellcode-generator.exe .
go test ./...
go vet ./...
```

## Usage

```text
shellcode-generator.exe -i payload.exe
shellcode-generator.exe -i payload.exe -o sc.bin --force
shellcode-generator.exe -i c2.dll -m RunIt -p "target" -w
shellcode-generator.exe -i payload.exe --compress lznt1 --entropy full
shellcode-generator.exe -i payload.exe --check
```

Run `--help` for the full list. Highlights:

| Option | Default | Meaning |
|---|---|---|
| `-i, --input` | required | native PE file, identified by content, not by extension |
| `-o, --output` | `./<input name>.bin` | existing files need `--force` to overwrite |
| `-a, --arch` | `auto` | `auto \| x86 \| x64 \| dual`, picked from the PE content |
| `-z, --compress` | `none` | `none \| lznt1 \| xpress`; lznt1 generates on any host, xpress on Windows only |
| `-b, --bypass` | `continue` | `none \| abort \| continue`; AMSI/WLDP/ETW policy |
| `-e, --entropy` | `none` | `none \| random \| full`; none is reproducible and hash-comparable, full adds instance encryption |
| `-k, --headers` | `overwrite` | `overwrite \| keep`; mapped PE headers |
| `-m, --method` | none | DLL export to call, case sensitive, verified at build time |
| `-p, --params` | none | EXE command line / DLL export argument; over-long values are rejected, never silently truncated |
| `-w, --wide` | off | deliver params to the DLL export as UTF-16 |
| `--entry` | `thread` | EXE entry: `thread \| direct` |
| `--exit` | `thread` | after the module returns: `thread \| process` |
| `-c, --check` | — | static inspection only (Inspect + Compat report), no output file |

## Design principles

- **Reproducibility first**: the default `entropy=none` produces identical bytes
  for identical input, so SHA-256 comparisons work; opt into encryption with
  `--entropy full`.
- **No silent degradation**: over-long parameters, arch conflicts, missing
  exports and blocking compatibility issues are errors, never guesses.
- **Atomic writes**: output lands through a same-directory temporary file; a
  failure leaves no half-written payload and never damages a previous one.
- **Machine readable**: `--json` emits a schema_version 1 object including all
  runtime options and the output SHA-256; warnings and errors go to stderr.
- **The generator only writes files**: it never loads, executes or injects its
  output; verification belongs to the caller.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (generation / clean check / help / version) |
| 1 | invalid arguments or conflicting options |
| 2 | input read failure, not a valid PE, or unsupported type |
| 3 | compatibility blocker, or warnings treated as failures |
| 4 | library build failure (missing export, compression failure, ...) |
| 5 | output conflict or write failure |

## Dependencies

`github.com/B1gCheater/shellcode-lib-go/donut`, pinned to commit `a921e08`.
License and attribution notes live in `THIRD_PARTY_NOTICES.md`.

## Testing

`test/loader.py` is a minimal shellcode loader (VirtualAlloc + execute) for
manually verifying generated payloads:

```powershell
python test\loader.py payload.bin
```

`go test ./...` covers argument parsing, the generation path, overwrite
protection, determinism, the JSON contract and exit codes.
