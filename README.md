# ida-reversing-kit

**让 AI 编码 agent 能真正用起 IDA Pro 的一套最小工具链。**

一个 JSON-first 的 IDA 命令行封装（`idaq`）+ 一份可移植的 agent skill + 一个反汇编压缩引擎。
没有 MCP、没有常驻服务、没有必须开着的 GUI 窗口。

```bash
idaq -b target.bin analyze                  # 一次性分析，落盘 .i64
idaq -b target.bin info                     # 架构 / 入口 / 函数数 / 字符串数
idaq -b target.bin strings --minlen 8 --filter password
idaq -b target.bin xrefs 0x3242 --direction to
idaq -b target.bin decompile 0x3242         # Hex-Rays 伪代码
idaq -b target.bin semz 0x3242 --level ultra  # 压缩反汇编（省 62.6%）
```

---

## 它解决什么问题

用 AI 做二进制逆向时，真正的瓶颈不是"AI 会不会用 IDA"，而是**上下文**。

实测一个 **2.3 MB 的 libc**：

| 做法 | 产物体量 | 估算 token |
|---|---|---|
| `idat -B` 生成完整反汇编 | **24.5 MB** | ~6,100,000 |
| `idaq` 一次典型会话（info + funcs + strings + names + decompile） | **14.3 KB** | ~3,564 |

（不是严格同口径——全量 `.asm` 包含一切，`idaq` 只给定向子集。但结论很清楚：**纪律性的定向查询 vs 倾倒**。）

三个设计决定对应三个问题：

1. **输出永远是 JSON** → AI 不需要解析 IDA 的日志文本。C 层的 IDA 噪声被重定向到 `/dev/null`，Python 层的 `--help` 和报错另接真 stdout，两者彻底隔离。
2. **列表一律分页** → 不存在"一不小心读了 5000 个函数"。
3. **分析一次、复用 `.i64`** → 首次 10–40 秒，之后每次 0.2–0.5 秒。

---

## 三层结构

```
ida-reversing-kit/
├── bin/idaq                 # 启动器（可安全 symlink）
├── src/idaq.py              # 全部实现，11 个子命令
├── skill/
│   ├── SKILL.md             # agent skill：description 常驻，正文按需加载
│   └── references/SEMZ.md   # SEMZ 解码手册（最重，最后才读）
└── vendor/semz/             # 反汇编压缩引擎（第三方，见下方致谢）
```

**为什么是「薄 CLI + skill」而不是一个 MCP 服务器？**

- 2026 年的 IDA MCP 服务器（[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)、[ida-mcp 2.0](https://jtsylve.blog/post/2026/03/25/Announcing-ida-mcp-2)）底层**也是 idalib**——差异在接口层，不在能力层。
- 能写代码/跑 shell 的 agent 不需要 MCP 那层协议；它需要的是「知道有这个东西 + 知道怎么用」。
- MCP 的代价：常驻 GUI IDA + gateway 进程 + 几十个工具的 schema 每轮都进上下文。实测 `idaq` 复用 `.i64` 冷启动只要 **0.28–0.48 秒**，对比一轮 LLM 推理几秒，不值那层负担。

`SKILL.md` 的 `description` 只占几十 token 常驻，正文在 agent 真正开始逆向时才加载。DSH 用户把它放进 `~/.dsh/skills/` 会被**自动发现**（有 watcher，改完即时生效，无需重启）。其他平台可把正文粘进 system prompt 或按需投喂。

---

## 安装

### 依赖

- **IDA Pro 9.0+**（`idalib` 自 9.0 引入），授权已激活，且**至少启动过一次 IDA** 接受 EULA
- Python ≥ 3.12
- 反编译需要 Hex-Rays 授权

### 步骤

```bash
git clone https://github.com/wul7chaos/ida-reversing-kit.git
cd ida-reversing-kit
./install.sh
```

`install.sh` 会（无构建步骤，纯符号链接 + 文件复制）：

1. 探测 IDA 安装目录（`$IDA_DIR` → `~/.idapro/ida-config.json` → 常见路径）
2. 把 `bin/idaq` 链到 **`~/.local/bin/idaq`**（不污染 IDA 安装目录；`--bin-dir` 可改）
3. 把 skill 复制到 `~/.dsh/skills/ida-reversing/`（非 DSH 用户加 `--no-skill`）
4. 做一次自检：跑 `idaq --help` + 对 `/bin/true` 调一次 `info`

```bash
./install.sh --no-skill          # 只装 CLI
./install.sh --bin-dir /usr/local/bin
./install.sh --uninstall         # 移除链接与 skill（不删仓库、不删 .i64）
```

安装后 `idaq` 就是个普通命令：

```bash
idaq -b /bin/ls analyze && idaq -b /bin/ls info
```

手动安装也可以——`idaq` 无任何构建步骤：

```bash
export IDA_DIR=/path/to/ida-pro-9.4
./bin/idaq -b /bin/ls info
```

**路径探测顺序**（不用配就能跑）：`$IDA_DIR` → `~/.idapro/ida-config.json` 里的 `ida-install-dir` → `~/ida-pro-9.4` → `~/idapro-9.4` → `/opt/idapro-9.4` → `/opt/ida`。

---

## 命令参考

全局：`-b/--binary`（或用 `IDAQ_BIN`）、`--db`（自定义 `.i64` 路径，默认 `<binary>.i64`）。

| 命令 | 说明 | 关键参数 |
|---|---|---|
| `analyze` | 建/更新 `.i64` | `--force` 强制重建 |
| `info` | 文件类型、架构、位数、镜像基址、入口点、段/函数/字符串计数 | |
| `funcs` | 函数列表 | `--filter` `--offset` `--limit` |
| `decompile` | Hex-Rays 伪代码 | `<0xADDR\|name>` |
| `disasm` | 反汇编（行级分页） | `--span` `--offset` `--limit` |
| `xrefs` | 交叉引用 | `--direction to\|from` `--limit` |
| `strings` | 字符串 | `--minlen` `--filter` `--offset` `--limit` |
| `names` | 符号搜索 | `--filter` `--offset` `--limit` |
| `segments` | 段列表（含权限/位数/大小） | |
| `semz` | SEMZ 压缩 | `--level` `--arch` `--with-map` `--text-file` `--stdin` |
| `exec` | 逃生舱：任意 IDAPython | `--save`（写回数据库） |

**目标解析**：接受 `0xADDR` 或符号名。模糊匹配优先函数，并在返回值里给出置信度：

```json
{ "resolved_by": "name-fuzzy-func", "matched_name": "usage", "ambiguous": true,
  "candidates": ["usage", "usage_error"] }
```

看到 `name-fuzzy-*` 或 `ambiguous` 就该先确认再往下走。

**错误处理**：永远返回纯 JSON + 退出码 2，绝不静默。

```json
{ "error": "找不到目标 'zzznotexist'", "candidates": [] }
```

---

## SEMZ 压缩

> **压缩引擎来自第三方项目，见下方[致谢](#致谢与许可)。** 本仓库只是把它 vendored 进来并接上 CLI。

实测（glibc x86-64，40 个真实函数，152 KB 输入）：

| level | 压缩后 | 节省 | 死代码删除 |
|---|---|---|---|
| `safe` | 55.3% | 44.7% | **0** |
| `full` | 55.4% | 44.6% | 9 条 (0.18%) |
| `max` | 54.0% | 46.0% | 89 条 (1.80%) |
| **`ultra`** | **37.4%** | **62.6%** | 9 条 (0.18%) |

**关键结论：那 62.6% 几乎全部来自字典编码，不是靠删代码。** 真实编译产物上 DCE 只删 0.18%。

**选级：**

- **默认 `safe`** —— 零删除，任何场景都可信
- **`ultra`** —— 正常编译产物 + 大范围批量扫描时收益最大
- ⚠️ **混淆代码 / 对抗样本分析一律用 `safe`**。`full`/`max`/`ultra` 的死代码消除建立在活跃变量分析上，OLLVM 平坦化、VMP、手写汇编下这个假设**不成立**，会真的删掉有效指令
- ⚠️ **小文本别压** —— 实测 6 条指令的片段压完变成 115%（表头开销 > 收益）。几千字符以上才划算

**`ultra` 的输出需要词表才能读**（固定词表故意不随输出传输，这正是压缩率的来源）。
要解读就加载 `skill/references/SEMZ.md`；不想引入词表依赖就用 `--level safe`（自带表头，自解释）或 `disasm`。

---

## 实测数据汇总

在你自己的机器上复现（Arch / CachyOS，IDA Pro 9.4，glibc）：

| 操作 | 耗时 |
|---|---|
| 全新分析 `libc.so.6`（2.3 MB，3510 函数） | **10.3 s** → `.i64` 21 MB |
| 全新分析 `libpython3.14.so`（6.4 MB，2.8×） | **38 s** → `.i64` 60 MB |
| `idaq` 复用 `.i64` 跑一次查询 | **276 ms** / **475 ms** |
| `idalib` 直接打开已有 `.i64` | **104 ms** |
| 会话内查询（`idalib` 常驻） | 0–21 ms |

体积涨 2.8 倍、分析时间涨 3.7 倍——**所以「分析一次、复用」是这个工具链的核心纪律**。

---

## 已知限制

- **必须装 IDA Pro**：`idalib` 是商业组件，本仓库不含也不绕过任何授权。
- **单线程**：idalib 官方要求所有库调用在同一线程，所以 `idaq` 是「一个进程一次调用」。要并发就并行起多个进程（`idalib` 每个进程独占一个数据库）。
- **`exec` 是全权逃生舱**：能跑任意 IDAPython。给不受信 agent 用时需要你自己在外面加限制。
- **只读查询默认不写回**：`exec` 的改动必须显式 `--save`，否则丢弃。
- **skill 格式针对 DSH 的 `dsh-skill-filesystem`**（`<name>/SKILL.md` + YAML frontmatter）。其他平台需要自己适配格式，正文内容可直接复用。

---

## 致谢与许可

### 反汇编压缩引擎 —— 来自第三方项目

`vendor/semz/` **不是本项目的原创代码**，它是以下项目的 **SEMZ v1 语义压缩引擎**：

| | |
|---|---|
| 来源仓库 | **[CatMeow-233/IDA-MCP](https://github.com/CatMeow-233/IDA-MCP)** |
| 上游仓库 | [Captain-AI-Hub/IDA-MCP](https://github.com/Captain-AI-Hub/IDA-MCP)（CatMeow-233 的仓库是它的 fork，SEMZ 是 fork 新增的核心特性） |
| 原始路径 | `ida_mcp/compress/` |
| 取用范围 | 仅 `compress/` 目录（11 个模块，纯 Python，零 IDA SDK 依赖），改名为 `semz` 以便独立 import |
| 未取用 | MCP 服务器、IDA 插件、gateway、以及该项目的其他工具 |
| 许可证 | **GNU GPL v3** |

`skill/references/SEMZ.md` 同样来自该项目（原文件 `instructor/LLM_INSTRUCTOR.md`），是 SEMZ 的解码手册 + 系统提示模板。

**我们对 vendored 代码未做任何修改。** 移除它只需删掉 `vendor/semz/` 与 `skill/references/SEMZ.md`，代价是失去 `semz` 子命令（其余功能不受影响）。

### 本项目的其余部分

除 `vendor/semz/` 与 `skill/references/SEMZ.md` 外，`idaq`、`SKILL.md`、`install.sh`、README 为本项目原创。

### 许可证

因为 vendored 了 GPL-3.0 代码，**本仓库整体以 [GPL-3.0](LICENSE) 发布**。
若要采用 MIT 等更宽松的许可，需要先把 SEMZ 拆成独立依赖（例如作为 submodule 或 pip 包），而不是 vendored 进来。

---

## 相关项目

- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) —— 走 MCP 路线的话看这个（基于 idalib 的 supervisor + worker 架构）
- [CatMeow-233/IDA-MCP](https://github.com/CatMeow-233/IDA-MCP) —— SEMZ 的来源；它的壳分析/Unicorn 模拟/OLLVM 检测也值得看
- [Hex-Rays: IDALib 实践](https://hex-rays.com/blog/4-powerful-applications-of-idalib-headless-ida-in-action)
