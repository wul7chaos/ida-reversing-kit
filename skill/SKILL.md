---
name: ida-reversing
description: 用本地 IDA Pro 9.x 做二进制逆向工程：静态分析、反编译、交叉引用、字符串/符号提取、调用图、加壳识别、批量扫描。当用户要求分析 ELF / PE / Mach-O / .so / .dll / 固件 / 恶意样本，反编译某个函数，问"这个二进制在干什么"、"这个函数做什么"、"谁调用了它"，或涉及 reverse engineering / disassembly / decompilation / 脱壳 / 漏洞分析 时使用。统一入口 idaq（只输出 JSON）。
whenToUse: 涉及二进制/固件/.so/.dll 的逆向、反汇编、反编译、交叉引用分析、脱壳、漏洞挖掘、恶意样本分析时
---

# IDA 逆向工作流

## 环境

| 项 | 说明 |
|---|---|
| 依赖 | IDA Pro **9.0+**（`idalib` 是 9.0 引入的），授权已激活，且**至少启动过一次 IDA**（接受 EULA） |
| 入口 | `idaq` —— 在 `PATH` 里，或 `<repo>/bin/idaq` |
| 路径探测 | `idaq` 自动找 IDA 安装目录：`$IDA_DIR` → `~/.idapro/ida-config.json` → `~/ida-pro-9.4` → `/opt/idapro-9.4` …… 都不对就显式 `export IDA_DIR=/your/ida` |
| 语言 | 系统 `python3` ≥ 3.12（IDA 9.4 的绑定按 3.14 配置） |

**不需要**设 `PYTHONPATH`——`idaq` 自己处理 `idalib` 与 vendored SEMZ 的加载路径。想省掉每次写 `-b`，可先 `export IDAQ_BIN=/path/to/target`。

---

## 六条铁律

1. **先 `analyze`，再反复查询。** 首次分析 10–40 秒（2–7 MB 二进制），之后每次 0.2–0.5 秒。不要每次调用都重新分析。
2. **永远只吃 JSON，绝不把原始 listing 倒进上下文。** 实测一个 2.3 MB 的 libc 用 `idat -B` 生成 24.5 MB 的 `.asm`（约 600 万 token，必然爆上下文）。`idaq` 所有列表输出都已分页。
3. **伪代码优先。** 正常代码用 `decompile`（语义密度最高）。但**混淆代码（OLLVM 平坦化 / VMP）上 Hex-Rays 会给你看着像正常逻辑、实际是错的伪代码** —— 那时必须降到 `disasm` / `semz` 层，信指令不信伪代码。
4. **分页，不要贪。** 默认 `--limit` 就够；需要更多显式加，一次不要超 200 条。
5. **改动要 `--save`。** 用 `exec` 改名/加注释必须带 `--save`，否则下一轮全丢。
6. **`resolved_by` 要检查。** 值为 `name-fuzzy-*` 或带 `"ambiguous": true` 时说明是猜的，先看 `candidates` 确认。

---

## 标准工作流

```bash
IDAQ=idaq   # 或 /path/to/ida-reversing-kit/bin/idaq

# 1. 摸底（首次会自动分析并落盘 .i64）
$IDAQ -b target.bin analyze
$IDAQ -b target.bin info            # 架构/位数/入口/段数/函数数/字符串数

# 2. 定位感兴趣的代码
$IDAQ -b target.bin strings --minlen 8 --filter 'password' --limit 20
$IDAQ -b target.bin names   --filter 'crypt'  --limit 20
$IDAQ -b target.bin funcs   --limit 50

# 3. 顺着交叉引用爬
$IDAQ -b target.bin xrefs 0x3242 --direction to      # 谁调用了它
$IDAQ -b target.bin xrefs 0x3242 --direction from    # 它调用了谁

# 4. 读语义
$IDAQ -b target.bin decompile 0x3242             # 伪代码（首选）
$IDAQ -b target.bin disasm    0x3242 --limit 60  # 伪代码看不懂/混淆时

# 5. 大范围扫描 → 压缩后再喂给自己
$IDAQ -b target.bin semz 0x3242 --level safe
```

`disasm` 的 `--offset/--limit` 是行级分页；`--span` 用于「地址不属于任何函数」时手工圈定扫描长度。

**逃生舱**：`idaq` 没覆盖到的任何 IDAPython 都能跑。

```bash
$IDAQ -b target.bin exec '
import idautils, idc
result = [idc.get_func_name(e) for e in idautils.Functions()][:5]
'
# 原地修改（改名/注释/加结构体）记得 --save
$IDAQ -b target.bin exec 'import idc; idc.set_name(0x3242, "my_error", idc.SN_NOWARN)' --save
```

`exec` 里 `print()` 的内容会出现在返回值的 `stdout` 字段，**不会**污染 JSON。设变量 `result` 可结构化返回。

---

## SEMZ 压缩：什么时候用，用哪级

**为什么需要**：批量扫描几十个函数时，原始反汇编会把上下文吃光。SEMZ 把它压成短 DSL（字典化助记符/寄存器表 + 常量池 + 指令序列宏 + 基本块标签 + 保守死代码消除）。

实测（glibc x86-64，40 个真实函数，152 KB 输入）：

| level | 压缩后 | 节省 | 死代码删除 |
|---|---|---|---|
| `safe` | 55.3% | 44.7% | **0** |
| `full` | 55.4% | 44.6% | 9 条 (0.18%) |
| `max` | 54.0% | 46.0% | 89 条 (1.80%) |
| **`ultra`** | **37.4%** | **62.6%** | 9 条 (0.18%) |

**选级规则：**

- **默认 `safe`** —— 零删除，任何场景都可信
- **`ultra`** —— 只在「正常编译产物的代码 + 大范围批量扫描/传输」时用，收益最大
- **混淆代码 / 对抗样本分析：一律 `safe`**。`full`/`max`/`ultra` 的 DCE 建立在活跃变量分析上，OLLVM 平坦化、VMP、手写汇编下这个假设**不成立**，会真的删掉有效指令
- **小文本别压** —— 实测 6 条指令的片段压完反而变成 115%（表头开销 > 收益）。大概 **几千字符以上**才划算

**读压缩输出需要词表**：`ultra` 用全局固定词表，输出里**故意不带** `#MN`/`#RG` 表头（这正是压缩率的来源）。所以：

- 要解读压缩输出 → 读 `references/SEMZ.md`（解码手册 + 系统提示模板）
- 不想引入词表依赖 → 改用 `--level safe`（输出自带表头，自解释）或干脆用 `disasm`
- 加 `--with-map` 拿到 `L0/L1/...` 标签到地址的映射
- 加 `--arch x64|arm64|x86` 强制架构（默认 `auto` 启发式判断）

压缩输出自带 `#summary` 行（块数/宏数/常量数/间接跳转数/栈帧大小），可以先用它判断要不要看细节。

`semz` 也支持完全不碰 IDA 的纯文本模式：

```bash
$IDAQ semz --text-file dump.txt --level ultra
cat trace.txt | $IDAQ semz --stdin --arch arm64
```

---

## 常见陷阱

- **`analyze` 报 skipped 但函数数变了**：说明 `.i64` 已存在且被复用。要重建用 `--force`。
- **`decompile` 报「反编译失败」**：混淆/VM 保护的典型表现。不要反复重试，直接转 `disasm` 或 `semz`。
- **`decompile` 报「不在任何函数内」**：地址可能落在数据段或未识别的代码。先 `disasm --span 0x100` 看一段，或在 `exec` 里手动 `ida_funcs.add_func(ea)`。
- **ELF 的 `entrypoints` 很杂**：IDA 的 entry API 对 ELF 会把动态符号表也列进来，里面有 `optarg`、`stdout` 这类数据符号。别当成真正的入口点，真正的入口看 `start` / `_start`。
- **`names --filter` 会命中字符串常量名**：像 `aUsageSOptionFi`、`aSnprintf` 是 IDA 给字符串自动起的名字，不是函数。用 `xrefs` 的 `is_function` 字段或 `funcs` 确认。
- **`.i64` 与输入同目录**：`analyze` 在 `<binary>.i64` 落盘。只读场景想避免污染目录，用 `--db /tmp/xxx.i64`。
- **别信单点结论**：`decompile` 出来的变量名是 IDA 猜的（`v3`、`sub_31DD`），要结合 `strings` / `xrefs` 交叉验证。

---

## 参考

- `references/SEMZ.md` —— SEMZ 解码手册（ARM64/x86/x64 固定表、ultra 语法、工作规则）+ 系统提示模板。**只在需要解读压缩输出时读**，平时不要加载（约 15 KB，省着用）。
- 仓库 README 有完整命令参考、实现说明与实测数据。
