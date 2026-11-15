# shellcode-generator

将原生 Windows EXE / DLL 转换为位置无关的二进制载荷（shellcode）。

基于 [shellcode-lib-go](https://github.com/B1gCheater/shellcode-lib-go) 库的完整功能：
架构选择、LZNT1/XPRESS 压缩、AMSI/WLDP/ETW bypass 策略、实例随机化与加密、
PE 头处理、线程入口、退出语义、宽字符参数。

## 构建

```powershell
go build -o shellcode-generator.exe .
go test ./...
go vet ./...
```

## 用法

```text
shellcode-generator.exe -i payload.exe
shellcode-generator.exe -i payload.exe -o sc.bin --force
shellcode-generator.exe -i c2.dll -m RunIt -p "target" -w
shellcode-generator.exe -i payload.exe --compress lznt1 --entropy full
shellcode-generator.exe -i payload.exe --check
```

完整选项见 `--help`。要点：

| 选项 | 默认 | 说明 |
|---|---|---|
| `-i, --input` | 必填 | 原生 PE 文件，按内容识别，不靠扩展名 |
| `-o, --output` | `./<输入名>.bin` | 已存在时需 `--force` 才覆盖 |
| `-a, --arch` | `auto` | `auto \| x86 \| x64 \| dual`，按 PE 内容自动选择 |
| `-z, --compress` | `none` | `none \| lznt1 \| xpress`；lznt1 任意平台可生成 |
| `-b, --bypass` | `continue` | `none \| abort \| continue`，AMSI/WLDP/ETW 策略 |
| `-e, --entropy` | `none` | `none \| random \| full`；none 产物可复现可哈希比对，full 加实例加密 |
| `-k, --headers` | `overwrite` | `overwrite \| keep`，映射后 PE 头 |
| `-m, --method` | 无 | DLL 导出名，区分大小写，构建时校验存在性 |
| `-p, --params` | 无 | EXE 命令行 / DLL 导出参数；超长直接报错，不静默截断 |
| `-w, --wide` | 关 | 参数以 UTF-16 交付给 DLL 导出 |
| `--entry` | `thread` | EXE 入口：`thread \| direct` |
| `--exit` | `thread` | 模块返回后：`thread \| process` |
| `-c, --check` | — | 仅静态检查（Inspect + Compat 报告），不生成 |

### 设计原则

- **确定性优先**：默认 `entropy=none`，同输入同产物，SHA-256 可比对；要加密显式 `--entropy full`。
- **不静默降级**：参数超长、架构冲突、导出不存在、阻断性兼容问题，全部报错而非猜测。
- **原子写入**：输出经同目录临时文件落盘，失败不残留半成品，不破坏旧产物。
- **机器可读**：`--json` 输出 schema_version 1 的完整对象（含 bypass/entropy/headers/wide/entry/exit 与 SHA-256）；警告与错误走 stderr。
- **生成器只写文件**：不加载、不执行、不注入产物；验证由调用方完成。

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功（生成 / 检查通过 / 帮助 / 版本） |
| 1 | 参数错误或组合冲突 |
| 2 | 输入读取失败、非有效 PE 或类型不支持 |
| 3 | 兼容性阻断，或警告按策略视为失败 |
| 4 | 库构建失败（导出不存在、压缩失败等） |
| 5 | 输出冲突或写入失败 |

## 依赖

`github.com/B1gCheater/shellcode-lib-go/donut`，锁定提交 `a921e08`。
库的许可证与归属见 `THIRD_PARTY_NOTICES.md`。

## 测试

`test/loader.py` 是一个最小 shellcode 加载器（VirtualAlloc + 执行），
用于人工验证生成产物：

```powershell
python test\loader.py payload.bin
```

`go test ./...` 覆盖参数解析、生成路径、覆盖保护、确定性、JSON 契约与错误码。
