#!/usr/bin/env bash
# install.sh — 把 idaq 接到 IDA 安装目录，并把 skill 装进 DSH 技能目录。
#
# 用法:
#   ./install.sh                    # 自动探测
#   IDA_DIR=/opt/idapro-9.4 ./install.sh
#   ./install.sh --bin-dir ~/.local/bin        # 链到别处（而非 $IDA_DIR/tools）
#   ./install.sh --skill-dir ~/.dsh/skills     # 自定义 skill 根
#   ./install.sh --no-skill                    # 只装 CLI
#   ./install.sh --uninstall
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR=""
SKILL_ROOT="${HOME}/.dsh/skills"
SKILL_NAME="ida-reversing"
DO_SKILL=1
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir)    BIN_DIR="${2:?}"; shift 2 ;;
    --skill-dir)  SKILL_ROOT="${2:?}"; shift 2 ;;
    --no-skill)   DO_SKILL=0; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    -h|--help)    sed -n '2,12p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

# ---------- 探测 IDA ----------
find_ida() {
  local c
  for c in "${IDA_DIR:-}" \
           "$(python3 - <<'PY' 2>/dev/null || true
import json,os
try:
    p=json.load(open(os.path.expanduser("~/.idapro/ida-config.json")))
    print((p.get("Paths") or {}).get("ida-install-dir","") or "")
except Exception: pass
PY
)" \
           "$HOME/ida-pro-9.4" "$HOME/idapro-9.4" "$HOME/ida-9.4" \
           /opt/idapro-9.4 /opt/ida-pro-9.4 /opt/ida; do
    [ -n "$c" ] && [ -d "$c/idalib/python" ] && { echo "$c"; return 0; }
  done
  return 1
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------- 卸载 ----------
if [ "$UNINSTALL" = 1 ]; then
  echo "== 卸载 =="
  if IDA="$(find_ida)"; then
    for p in "$IDA/tools/idaq" "$HOME/.local/bin/idaq"; do
      [ -L "$p" ] && rm -f "$p" && echo "  移除链接 $p"
    done
  fi
  [ -d "$SKILL_ROOT/$SKILL_NAME" ] && rm -rf "$SKILL_ROOT/$SKILL_NAME" \
    && echo "  移除 skill $SKILL_ROOT/$SKILL_NAME"
  echo "完成。注意：未删除仓库本身与任何 .i64 文件。"
  exit 0
fi

# ---------- 安装 ----------
echo "== ida-reversing-kit 安装 =="
echo "仓库: $REPO"

if ! has_cmd python3; then
  echo "错误: 找不到 python3" >&2; exit 1
fi
echo "python3: $(python3 --version 2>&1)"

if IDA="$(find_ida)"; then
  echo "IDA 安装目录: $IDA"
else
  echo "警告: 未探测到 IDA 安装目录（需含 idalib/python）。" >&2
  echo "      CLI 仍会安装，但运行前需 export IDA_DIR=/your/ida" >&2
  IDA=""
fi

# 目标 bin 目录 —— 默认 ~/.local/bin（通常已在 PATH，且不污染 IDA 安装目录）
if [ -z "$BIN_DIR" ]; then
  BIN_DIR="$HOME/.local/bin"
fi
mkdir -p "$BIN_DIR"
chmod +x "$REPO/bin/idaq" "$REPO/src/idaq.py"

LINK="$BIN_DIR/idaq"
ln -sfn "$REPO/bin/idaq" "$LINK"
echo "链接: $LINK -> $REPO/bin/idaq"

# 清理旧版遗留（早期版本会往 $IDA/tools 拷 idaq.py / semz/，并链一个 idaq）
if [ -n "$IDA" ] && [ -d "$IDA/tools" ]; then
  for stale in "$IDA/tools/idaq.py" "$IDA/tools/semz"; do
    if [ -e "$stale" ] && [ ! -L "$stale" ]; then
      echo "  发现旧版副本: $stale（现由仓库统一提供，可安全删除）"
    fi
  done
  if [ -L "$IDA/tools/idaq" ] && [ "$BIN_DIR" != "$IDA/tools" ]; then
    echo "  发现旧版链接: $IDA/tools/idaq（建议删除，避免两个入口）"
  fi
fi

# PATH 提醒
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "提示: $BIN_DIR 不在 PATH 中，加一行到 ~/.bashrc:"
     echo "      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

# ---------- skill ----------
if [ "$DO_SKILL" = 1 ]; then
  TARGET="$SKILL_ROOT/$SKILL_NAME"
  mkdir -p "$TARGET/references"
  cp "$REPO/skill/SKILL.md" "$TARGET/SKILL.md"
  cp "$REPO/skill/references/SEMZ.md" "$TARGET/references/SEMZ.md"
  echo "skill: $TARGET"
  echo "       （DSH 会通过 dsh-skill-filesystem 自动发现，无需重启）"
else
  echo "skill: 已跳过（--no-skill）"
fi

# ---------- 自检 ----------
if [ -n "$IDA" ]; then
  echo
  echo "== 自检 =="
  if "$REPO/bin/idaq" --help >/dev/null 2>&1; then
    echo "  idaq 可执行 ✓"
  else
    echo "  idaq 执行失败 ✗" >&2; exit 1
  fi
  TMPB="$(mktemp -d)/probe.bin"
  if [ -x /bin/true ]; then cp /bin/true "$TMPB"; else head -c 4096 /dev/urandom > "$TMPB"; fi
  if "$REPO/bin/idaq" -b "$TMPB" info >/dev/null 2>&1; then
    echo "  IDA / idalib 链路 ✓"
  else
    echo "  idalib 调用失败——请确认 IDA 已至少启动过一次并接受 EULA" >&2
  fi
  rm -rf "$(dirname "$TMPB")"
fi

echo
echo "完成。试一下："
echo "  idaq -b /bin/ls analyze && idaq -b /bin/ls info"
