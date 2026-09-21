#!/usr/bin/env python3
"""
idaq — JSON-first CLI over IDA Pro 9.4 (idalib) + SEMZ disassembly compression.

设计原则（给调用方 AI 的契约）：
  1. stdout 永远是**一个 JSON 对象**，绝无 IDA 噪声污染。
  2. 所有列表类输出都分页（--offset / --limit），绝不倾倒全量。
  3. 首次调用自动分析并落盘 .i64，之后复用（10~40s → 0.3~0.5s）。
  4. 出错时输出 {"error": ...} 且退出码非 0，绝不静默。
  5. 只读查询默认不写回数据库；写操作（exec）需显式 --save。

用法:
  idaq -b TARGET analyze                     建/更新 .i64
  idaq -b TARGET info                        元信息
  idaq -b TARGET funcs   [--filter S] [--offset N] [--limit N]
  idaq -b TARGET decompile <0xADDR|name>
  idaq -b TARGET disasm    <0xADDR|name> [--offset N] [--limit N]
  idaq -b TARGET xrefs     <0xADDR|name> [--direction to|from]
  idaq -b TARGET strings   [--minlen N] [--filter S] [--offset N] [--limit N]
  idaq -b TARGET names     [--filter S] [--offset N] [--limit N]
  idaq -b TARGET segments
  idaq -b TARGET semz      <0xADDR|name> [--level safe|full|max|ultra]
  idaq -b TARGET semz      --text-file F | --stdin
  idaq -b TARGET exec      '<IDAPython code>'   [--save]      逃生舱

环境变量:
  IDA_DIR     IDA 安装根目录（含 idalib/python）。不设则依次尝试
              ~/.idapro/ida-config.json → ~/ida-pro-9.4 → ~/idapro-9.4 → /opt/idapro-9.4 ...
  IDAQ_SEMZ   含 semz/ 的目录（默认自动在仓库内查找）
  IDAQ_BIN    等价于 -b，省去每次重复
"""

import argparse
import json
import os
import re
import sys
import warnings

warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
IDA_DIR = None  # 惰性解析，见 _find_ida_dir()

# --------------------------------------------------------------------------
# stdout 保护：C 层（IDA/idalib 的 printf）写到 fd 1 → 被 /dev/null 吞掉；
# Python 层（argparse help、报错）另行指向真 stdout，保证 --help 可见。
# 所有 JSON 都经 _real_fd 写出，与 IDA 噪声彻底隔离。
# --------------------------------------------------------------------------
_real_fd = os.dup(1)
_devnull_fd = os.open(os.devnull, os.O_WRONLY)
os.dup2(_devnull_fd, 1)
sys.stdout = os.fdopen(os.dup(_real_fd), "w", buffering=1)


def emit(obj, code=0):
    """写出唯一的一份 JSON 并退出。os._exit 避免 IDA atexit 再喷东西。"""
    try:
        payload = json.dumps(obj, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        payload = json.dumps({"_raw": repr(obj)}, ensure_ascii=False, indent=2)
    try:
        try:
            sys.stdout.flush()
        except Exception:
            pass
        os.write(_real_fd, payload.encode("utf-8", "replace") + b"\n")
    finally:
        os._exit(code)


def fail(msg, code=2, **extra):
    d = {"error": str(msg)}
    d.update(extra)
    emit(d, code)


def clamp(limit, default=100, hard_max=2000):
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = default
    return max(0, min(n, hard_max))


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def arch_info():
    """跨版本稳健地取架构信息。"""
    import ida_ida

    proc = _safe(ida_ida.inf_get_procname, "?") or "?"
    bits = _safe(lambda: 64 if ida_ida.inf_is_64bit() else 32)
    family = {"metapc": "x86", "ARM": "arm", "arm": "arm",
              "RISCV": "riscv", "PPC": "ppc", "mips": "mips"}.get(proc, proc)
    return {"processor": proc, "bits": bits, "family": family}


def file_type_name():
    import ida_loader

    return _safe(ida_loader.get_file_type_name)


def _find_ida_dir():
    """按优先级定位 IDA 安装目录（必须含 idalib/python）。"""
    cands = []
    if os.environ.get("IDA_DIR"):
        cands.append(os.environ["IDA_DIR"])
    idausr = os.environ.get("IDAUSR") or os.path.expanduser("~/.idapro")
    try:
        with open(os.path.join(idausr, "ida-config.json")) as f:
            p = (json.load(f).get("Paths") or {}).get("ida-install-dir")
            if p:
                cands.append(p)
    except Exception:
        pass
    cands += [os.path.expanduser(x) for x in
              ("~/ida-pro-9.4", "~/idapro-9.4", "~/ida-9.4",
               "/opt/idapro-9.4", "/opt/ida-pro-9.4", "/opt/ida")]
    for c in cands:
        if c:
            c = os.path.abspath(os.path.expanduser(c))
            if os.path.isdir(os.path.join(c, "idalib", "python")):
                return c
    fail("找不到 IDA 安装目录（需含 idalib/python）。请设置 IDA_DIR 环境变量。\n"
         "已尝试: %s" % ", ".join(repr(c) for c in cands if c))


def _find_semz_parent():
    """定位 vendored SEMZ 引擎的父目录（即含 semz/ 的那一层）。"""
    cands = []
    if os.environ.get("IDAQ_SEMZ"):
        cands.append(os.environ["IDAQ_SEMZ"])
    if os.environ.get("IDAQ_HOME"):
        cands.append(os.path.join(os.environ["IDAQ_HOME"], "vendor"))
    cands += [
        HERE,                                            # 与 idaq.py 同级的 semz/
        os.path.normpath(os.path.join(HERE, os.pardir, "vendor")),   # <repo>/src -> <repo>/vendor
        os.path.normpath(os.path.join(HERE, os.pardir, os.pardir, "vendor")),
    ]
    for c in cands:
        if c and os.path.isdir(os.path.join(c, "semz")):
            return os.path.abspath(c)
    return None


def load_semz(fn_name="compress_text"):
    parent = _find_semz_parent()
    if parent and parent not in sys.path:
        sys.path.insert(0, parent)
    try:
        import semz
    except Exception as e:
        fail("无法加载 SEMZ 压缩引擎（找过: %s）。设置 IDAQ_SEMZ 指向含 semz/ 的目录。"
             "原始错误: %s" % (_find_semz_parent(), e))
    fn = getattr(semz, fn_name, None)
    if fn is None:
        fail("semz 模块缺少 %s" % fn_name)
    return fn


# --------------------------------------------------------------------------
# 数据库管理
# --------------------------------------------------------------------------
def load_idapro():
    """惰性定位 IDA 安装目录并加载 idalib。"""
    global IDA_DIR
    if IDA_DIR is None:
        IDA_DIR = _find_ida_dir()
        sys.path.insert(0, os.path.join(IDA_DIR, "idalib", "python"))
    try:
        import idapro
    except Exception as e:
        fail(
            "无法加载 idalib。IDA_DIR=%s，请确认该目录含 idalib/python，"
            "且 ~/.idapro/ida-config.json 指向同一安装（先启动一次 IDA 以激活授权）。"
            "原始错误: %s" % (IDA_DIR, e)
        )
    return idapro


def db_path_for(binary, explicit):
    return explicit if explicit else binary + ".i64"


def db_exists(db):
    """同时兼容打包(.i64)与未打包(.id0)两种落盘形态。"""
    if os.path.exists(db):
        return True
    base = db[:-4] if db.endswith(".i64") else db
    return os.path.exists(base + ".id0")


class Session:
    """打开数据库；退出时按需保存。**不要**在 with 内部调用 emit/os._exit，
    否则 __exit__ 被跳过、close_database 不会执行（曾因此丢失 .i64）。"""

    def __init__(self, binary, db, save):
        self.idapro = load_idapro()
        self.binary = binary
        self.db = db
        self.save = save
        self.fresh = not db_exists(db)
        self.closed = False

    def __enter__(self):
        if self.fresh:
            rc = self.idapro.open_database(self.binary, True)
            if rc != 0:
                fail("open_database 失败 (rc=%d)：%s" % (rc, self.binary))
        else:
            target = self.db if os.path.exists(self.db) else self.binary
            rc = self.idapro.open_database(target, False)
            if rc != 0:
                fail("打开已有数据库失败 (rc=%d)：%s" % (rc, target))
        return self

    def __exit__(self, exc_type, exc, tb):
        # 新建的库必须落盘；已有库仅在显式 --save 时写回
        want_save = bool((self.save or self.fresh) and exc_type is None)
        try:
            self.idapro.close_database(save=want_save)
        except Exception:
            pass
        self.closed = True
        return False


def need_binary(args):
    b = getattr(args, "binary", None) or os.environ.get("IDAQ_BIN")
    if not b:
        fail("缺少目标二进制：用 -b/--binary 指定，或设置 IDAQ_BIN 环境变量")
    b = os.path.abspath(os.path.expanduser(b))
    if not os.path.exists(b):
        fail("文件不存在: %s" % b)
    return b


# --------------------------------------------------------------------------
# 目标解析
# --------------------------------------------------------------------------
def resolve_target(target):
    """返回 (ea, info)。info 含 resolved_by 与（若有歧义）candidates。
    调用方应把 info 合进自己的返回 dict，让 AI 能看到解析置信度。"""
    import idaapi
    import idc

    t = (target or "").strip()
    if not t:
        fail("缺少目标（需要地址或符号名）")

    bad = getattr(idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", t) or re.fullmatch(r"[0-9a-fA-F]{4,}", t):
        ea = int(t, 16)
        if ea != bad:
            return ea, {"resolved_by": "addr"}

    ea = idc.get_name_ea_simple(t)
    if ea != bad:
        return ea, {"resolved_by": "name"}

    import idautils

    needle = t.lower()
    exact, fns, others = None, [], []
    for _ea, n in idautils.Names():
        ln = n.lower()
        if ln == needle and exact is None:
            exact = n
            continue
        if needle in ln:
            ea2 = idc.get_name_ea_simple(n)
            if ea2 == bad:
                continue
            (fns if idc.get_func_name(ea2) else others).append((len(n), n, ea2))

    if exact:
        ea = idc.get_name_ea_simple(exact)
        if ea != bad:
            return ea, {"resolved_by": "name-exact-ci"}

    for pool, label in ((fns, "name-fuzzy-func"), (others, "name-fuzzy")):
        if not pool:
            continue
        pool.sort()
        _ln, n, ea = pool[0]
        extra = {"resolved_by": label, "matched_name": n}
        if len(pool) > 1:
            extra["ambiguous"] = True
            extra["candidates"] = [p[1] for p in pool[:20]]
        return ea, extra

    fail("找不到目标 %r" % t, candidates=[])


def name_of(ea):
    import idc

    return idc.get_func_name(ea) or idc.get_name(ea) or ("sub_%X" % ea)


def asm_lines(start, end):
    import idc
    import idautils

    return ["%#x: %s" % (h, idc.generate_disasm_line(h, 0) or "")
            for h in idautils.Heads(start, end)]


# --------------------------------------------------------------------------
# 子命令 —— 每个都 **返回 dict**，由 main() 统一 emit（保证 Session 已正确关闭）
# --------------------------------------------------------------------------
def cmd_analyze(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    if db_exists(db) and not args.force:
        with Session(b, db, False) as s:
            import ida_funcs

            return {"ok": True, "action": "skipped",
                    "reason": "数据库已存在（用 --force 重建）",
                    "binary": b, "db": db,
                    "functions": ida_funcs.get_func_qty()}
    with Session(b, db, True):
        import ida_funcs

        return {"ok": True, "action": "analyzed", "binary": b, "db": db,
                "functions": ida_funcs.get_func_qty(),
                "file_type": file_type_name(), **arch_info()}


def cmd_info(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import ida_entry
        import ida_funcs
        import ida_nalt
        import ida_segment
        import idautils

        eps = []
        for i in range(ida_entry.get_entry_qty()):
            if len(eps) >= 20:
                break
            ord_ = ida_entry.get_entry_ordinal(i)
            eps.append({"ea": hex(ida_entry.get_entry(ord_)),
                        "name": ida_entry.get_entry_name(ord_), "ordinal": ord_})

        return {"binary": b, "db": db,
                "root_filename": _safe(ida_nalt.get_root_filename),
                "file_type": file_type_name(),
                "imagebase": hex(ida_nalt.get_imagebase()),
                "entrypoints": eps,
                "segments": ida_segment.get_segm_qty(),
                "functions": ida_funcs.get_func_qty(),
                "strings": sum(1 for _ in idautils.Strings()),
                **arch_info()}


def cmd_funcs(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import ida_funcs
        import idc
        import idautils

        offset = int(args.offset or 0)
        limit = clamp(args.limit, 100)
        flt = (args.filter or "").lower()
        items, total = [], 0
        for ea in idautils.Functions():
            nm = idc.get_func_name(ea) or ""
            if flt and flt not in nm.lower():
                continue
            total += 1
            if total <= offset or len(items) >= limit:
                continue
            f = ida_funcs.get_func(ea)
            items.append({"ea": hex(ea), "name": nm,
                          "size": f.size() if f else 0,
                          "end": hex(f.end_ea) if f else None})
        return {"total": total, "offset": offset, "limit": limit,
                "filter": args.filter, "items": items}


def cmd_decompile(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import ida_funcs
        import ida_hexrays

        ea, tr = resolve_target(args.target)
        if not ida_hexrays.init_hexrays_plugin():
            fail("Hex-Rays 反编译器不可用（授权或插件缺失）")
        f = ida_funcs.get_func(ea)
        if not f:
            fail("地址 %s 不在任何函数内（用 disasm 看原始指令，或 semz 压缩一段）"
                 % hex(ea))
        cf = ida_hexrays.decompile(f.start_ea)
        if cf is None:
            fail("反编译失败——混淆/VM 保护的代码常见此情况，改用 disasm 或 semz",
                 ea=hex(f.start_ea), name=name_of(f.start_ea))
        text = str(cf)
        return {"ea": hex(f.start_ea), "end": hex(f.end_ea),
                "name": name_of(f.start_ea), **tr,
                "lines": text.count("\n") + 1, "pseudocode": text}


def cmd_disasm(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import ida_funcs

        ea, tr = resolve_target(args.target)
        f = ida_funcs.get_func(ea)
        start, end = (f.start_ea, f.end_ea) if f else (ea, ea + args.span)
        offset = int(args.offset or 0)
        limit = clamp(args.limit, 200, 5000)
        lines = asm_lines(start, end)
        window = lines[offset:offset + limit]
        items = []
        for line in window:
            a, _, txt = line.partition(": ")
            items.append({"ea": a, "text": txt})
        return {"ea": hex(start), "end": hex(end), "name": name_of(start), **tr,
                "total": len(lines), "offset": offset,
                "limit": limit, "returned": len(items), "items": items}


def cmd_xrefs(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import ida_funcs
        import idautils

        ea, tr = resolve_target(args.target)
        limit = clamp(args.limit, 200, 2000)
        items = []
        if args.direction == "to":
            for x in idautils.XrefsTo(ea, 0):
                items.append({"ea": hex(x.frm), "func": name_of(x.frm),
                              "type": x.type, "iscode": bool(x.iscode)})
                if len(items) >= limit:
                    break
        else:
            for x in idautils.XrefsFrom(ea, 0):
                items.append({"ea": hex(x.to), "func": name_of(x.to),
                              "type": x.type, "iscode": bool(x.iscode)})
                if len(items) >= limit:
                    break
        return {"target": hex(ea), "name": name_of(ea), **tr,
                "direction": args.direction,
                "is_function": bool(ida_funcs.get_func(ea)),
                "returned": len(items), "items": items}


def cmd_strings(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import idautils

        offset = int(args.offset or 0)
        limit = clamp(args.limit, 100)
        minlen = int(args.minlen or 4)
        flt = (args.filter or "").lower()
        items, total = [], 0
        for s in idautils.Strings():
            try:
                txt = getattr(s, "str", None) or str(s)
            except Exception:
                continue
            if len(txt) < minlen:
                continue
            if flt and flt not in txt.lower():
                continue
            total += 1
            if total <= offset or len(items) >= limit:
                continue
            items.append({"ea": hex(s.ea), "len": len(txt), "text": txt})
        return {"total": total, "offset": offset, "limit": limit,
                "minlen": minlen, "filter": args.filter, "items": items}


def cmd_names(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import idautils

        offset = int(args.offset or 0)
        limit = clamp(args.limit, 100)
        flt = (args.filter or "").lower()
        items, total = [], 0
        for ea, nm in idautils.Names():
            if flt and flt not in nm.lower():
                continue
            total += 1
            if total <= offset or len(items) >= limit:
                continue
            items.append({"ea": hex(ea), "name": nm})
        return {"total": total, "offset": offset, "limit": limit,
                "filter": args.filter, "items": items}


def cmd_segments(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    with Session(b, db, False):
        import ida_segment

        items = []
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            if not s:
                continue
            items.append({
                "name": ida_segment.get_segm_name(s),
                "start": hex(s.start_ea), "end": hex(s.end_ea),
                "class": ida_segment.get_segm_class(s),
                "perm": "".join(c for c in
                                ("r" if s.perm & 4 else "-",
                                 "w" if s.perm & 2 else "-",
                                 "x" if s.perm & 1 else "-")),
                "bitness": s.bitness, "size": s.end_ea - s.start_ea})
        return {"count": len(items), "items": items}


def cmd_semz(args):
    body, meta = None, {}

    if args.text_file or args.stdin:
        raw = (sys.stdin.read() if args.stdin
               else open(os.path.expanduser(args.text_file), "r", errors="replace").read())
        body = raw
        meta = {"source": "stdin" if args.stdin else args.text_file}
    else:
        b = need_binary(args)
        db = db_path_for(b, args.db)
        with Session(b, db, False):
            import ida_funcs

            ea, tr = resolve_target(args.target)
            f = ida_funcs.get_func(ea)
            start, end = (f.start_ea, f.end_ea) if f else (ea, ea + args.span)
            body = "\n".join(asm_lines(start, end))
            meta = {"ea": hex(start), "end": hex(end), "name": name_of(start),
                    "db": db, **tr}

    if not body or not body.strip():
        fail("没有可压缩的汇编文本", **meta)

    compress_text = load_semz("compress_text")

    try:
        r = compress_text(body, level=args.level,
                          arch=None if args.arch == "auto" else args.arch)
    except Exception as e:
        fail("压缩失败: %s" % e)

    out = r.get("text") or r.get("compressed") or ""
    result = dict(meta)
    result.update({
        "level": args.level, "arch": args.arch,
        "stats": r.get("stats"), "truncated": r.get("truncated"),
        "hint": r.get("hint"),
        "chars_in": len(body), "chars_out": len(out),
        "compressed": out,
    })
    if args.with_map:
        result["label_map"] = r.get("map")
    return result


def cmd_exec(args):
    b = need_binary(args)
    db = db_path_for(b, args.db)
    import tempfile

    with Session(b, db, args.save):
        ns = {"__name__": "__idaq_exec__", "json": json}
        for mod in ("idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
                    "ida_segment", "ida_nalt", "ida_entry", "ida_hexrays",
                    "ida_auto", "ida_name", "ida_xref", "ida_typeinf",
                    "ida_search", "ida_frame", "ida_struct", "ida_enum"):
            try:
                ns[mod] = __import__(mod)
            except Exception:
                pass

        tmp = tempfile.TemporaryFile()
        saved = os.dup(1)
        old_stdout = sys.stdout
        os.dup2(tmp.fileno(), 1)
        sys.stdout = os.fdopen(os.dup(tmp.fileno()), "w", buffering=1)
        err = None
        try:
            exec(compile(args.code, "<idaq exec>", "exec"), ns)
        except Exception:
            import traceback

            err = traceback.format_exc()
        finally:
            try:
                sys.stdout.flush()
            except Exception:
                pass
            sys.stdout = old_stdout
            os.dup2(saved, 1)
            os.close(saved)
        tmp.seek(0)
        captured = tmp.read().decode("utf-8", "replace")
        tmp.close()

        res = {"stdout": captured, "saved": bool(args.save)}
        if "result" in ns and ns["result"] is not None:
            res["result"] = ns["result"]
        if err:
            res["error"] = err
        return res


# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="idaq", description="JSON-first IDA Pro 9.4 CLI (+SEMZ)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-b", "--binary", help="目标二进制（或用 IDAQ_BIN）")
    p.add_argument("--db", help="显式指定 .i64 路径（默认 <binary>.i64）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("analyze", help="建/更新 .i64（首次必需）")
    s.add_argument("--force", action="store_true", help="即使已存在也重建")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("info", help="文件/架构/入口/统计")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("funcs", help="函数列表（分页）")
    s.add_argument("--filter")
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(func=cmd_funcs)

    s = sub.add_parser("decompile", help="反编译为伪代码")
    s.add_argument("target")
    s.set_defaults(func=cmd_decompile)

    s = sub.add_parser("disasm", help="反汇编（分页）")
    s.add_argument("target")
    s.add_argument("--span", type=int, default=0x100)
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(func=cmd_disasm)

    s = sub.add_parser("xrefs", help="交叉引用")
    s.add_argument("target")
    s.add_argument("--direction", choices=["to", "from"], default="to")
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(func=cmd_xrefs)

    s = sub.add_parser("strings", help="字符串（分页）")
    s.add_argument("--minlen", type=int, default=4)
    s.add_argument("--filter")
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(func=cmd_strings)

    s = sub.add_parser("names", help="符号名搜索")
    s.add_argument("--filter")
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(func=cmd_names)

    s = sub.add_parser("segments", help="段列表")
    s.set_defaults(func=cmd_segments)

    s = sub.add_parser("semz", help="SEMZ 反汇编压缩")
    s.add_argument("target", nargs="?")
    s.add_argument("--level", choices=["safe", "full", "max", "ultra"], default="safe")
    s.add_argument("--arch", choices=["auto", "x86", "x64", "arm64"], default="auto")
    s.add_argument("--span", type=int, default=0x200)
    s.add_argument("--text-file")
    s.add_argument("--stdin", action="store_true")
    s.add_argument("--with-map", action="store_true")
    s.set_defaults(func=cmd_semz)

    s = sub.add_parser("exec", help="逃生舱：任意 IDAPython")
    s.add_argument("code")
    s.add_argument("--save", action="store_true", help="把改动写回数据库")
    s.set_defaults(func=cmd_exec)

    return p


def main():
    args = build_parser().parse_args()
    try:
        result = args.func(args)
    except SystemExit:
        raise
    except Exception:
        import traceback

        fail("未捕获异常:\n" + traceback.format_exc(), 1)
    emit(result if result is not None else {"ok": True})


if __name__ == "__main__":
    main()
