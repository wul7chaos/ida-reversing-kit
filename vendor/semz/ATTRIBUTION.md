# 来源与许可声明

本目录（`vendor/semz/`）**不是本项目的原创代码**，它是第三方项目的 vendored 副本。

| 项 | 内容 |
|---|---|
| 组件 | **SEMZ v1 语义压缩引擎**（反汇编 → 紧凑 DSL，供 LLM 消费） |
| 来源仓库 | **[https://github.com/CatMeow-233/IDA-MCP](https://github.com/CatMeow-233/IDA-MCP)** |
| 上游仓库 | [https://github.com/Captain-AI-Hub/IDA-MCP](https://github.com/Captain-AI-Hub/IDA-MCP) —— CatMeow-233 的仓库是它的 fork，SEMZ 是该 fork 新增的核心特性（上游 README 完全未提及压缩） |
| 原始路径 | `ida_mcp/compress/` |
| 取用范围 | 仅 `compress/` 目录下 11 个模块；**未修改任何一行源码**，仅把目录名改为 `semz` 以便作为独立包 import |
| 未取用 | 该项目的 MCP 服务器、IDA 插件、gateway、`api_*.py` 等其余部分 |

## 本目录内的文件清单

```
cfg.py  dsl.py  extract.py  global_table.py  __init__.py
layers.py  liveness.py  model.py  normalize.py  parse.py  pipeline.py
```

这些模块为**纯 Python**，对 IDA SDK 零依赖（源码中没有 `import idaapi` / `ida_*`），因此可以脱离 MCP 独立使用——这也是本项目能把它接进普通 CLI 的前提。

## 许可证：GNU GPL v3

上游以 **GPL-3.0** 发布。这意味着：

- 分发本仓库（含本目录）时，**必须**保留本声明与许可证
- 因为本仓库把 GPL-3.0 代码 vendored 进来，**整个仓库需以 GPL-3.0 发布**（见仓库根目录 `LICENSE`）
- 若要改用 MIT 等宽松许可，必须先把本目录拆成独立依赖（git submodule / pip 包 / 运行时下载），而不是 vendored 进源码树

移除本目录即可去掉 GPL 约束，代价是失去 `semz` 子命令——`idaq` 的其余功能（`analyze` / `info` / `funcs` / `decompile` / `disasm` / `xrefs` / `strings` / `names` / `segments` / `exec`）不受影响。
`src/idaq.py` 的 `_find_semz_parent()` 找不到 `semz/` 时不会崩溃，只在调用 `semz` 子命令时报错。
