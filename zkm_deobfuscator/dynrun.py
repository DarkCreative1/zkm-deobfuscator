from __future__ import annotations
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_HERE = Path(__file__).parent / "dyndump"
_CACHE: Path | None = None

def helpers_dir() -> Path | None:
    global _CACHE
    srcs = [_HERE / "DynDump.java", _HERE / "VerifyAll.java"]
    cls = Path(tempfile.gettempdir()) / "zkm_deobf_helpers" / "DynDump.class"
    if _CACHE and cls.exists():
        try:
            if all(cls.stat().st_mtime >= s.stat().st_mtime for s in srcs):
                return _CACHE
        except OSError:
            pass
    javac = shutil.which("javac")
    if not javac:
        return None
    d = Path(tempfile.gettempdir()) / "zkm_deobf_helpers"
    d.mkdir(exist_ok=True)
    try:
        r = subprocess.run([javac, "-d", str(d), str(_HERE / "DynDump.java"),
                            str(_HERE / "VerifyAll.java")],
                           capture_output=True, text=True, timeout=120)
    except Exception:
        return None
    if r.returncode != 0 or not (d / "DynDump.class").exists():
        return None
    _CACHE = d
    return d

def _java() -> str | None:
    return shutil.which("java")

def dump_tables(jar_path: str, class_name: str, fields: list[str],
                timeout: int = 90) -> tuple[dict[str, list[str | None]], dict[str, str]]:

    h = helpers_dir()
    j = _java()
    if not h or not j or not fields:
        return {}, {}
    args = [j, "-cp", os.pathsep.join([str(h), jar_path]), "DynDump", "x"]
    for f in fields:
        args.append(f"T:{class_name}:{f}")
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return {}, {}
    out: dict[str, list[str | None]] = {}
    singles: dict[str, str] = {}
    for line in (r.stdout or "").splitlines():
        if line.startswith("TX "):
            try:
                _, _i, rest = line.split(" ", 2)
                ln, vals = rest.split(":", 1)
                chars = [int(x) for x in vals.split(",") if x != ""]
                singles[fields[int(_i) - 1]] = "".join(chr(c) for c in chars)
            except Exception:
                continue
            continue
        if not line.startswith("TOK "):
            continue
        try:
            _, _i, rest = line.split(" ", 2)
            parts = rest.split(" ", 1)
            n = int(parts[0])
            arr: list[str | None] = []
            if len(parts) > 1:

                for tok in parts[1].split("|"):
                    if not tok.strip():
                        continue
                    tok = tok.strip()
                    if tok == "NULL":
                        arr.append(None)
                        continue
                    ln, vals = tok.split(":", 1)
                    chars = [int(x) for x in vals.split(",") if x != ""]
                    arr.append("".join(chr(c) for c in chars))
            out[fields[int(_i) - 1]] = arr
        except Exception:
            continue
    return out, singles

def dump_ints(jar_path: str, class_name: str,
              sites: list[tuple[str, int, int]], timeout: int = 90) -> dict[int, object]:

    h = helpers_dir()
    j = _java()
    if not h or not j:
        return {}
    args = [j, "-cp", os.pathsep.join([str(h), jar_path]), "DynDump", class_name]
    for i, (kind, arg, key) in enumerate(sites):
        args.append(f"{kind}:{arg}:{key}")
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return {}
    out: dict[int, object] = {}
    for line in (r.stdout or "").splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "OK":
            try:
                out[int(p[1]) - 1] = int(p[2])
            except ValueError:
                pass
    return out

def verify_jar(jar_path: str, timeout: int = 120) -> tuple[bool, str]:
    h = helpers_dir()
    j = _java()
    if not h or not j:
        return False, "javac/java absent"
    try:
        r = subprocess.run([j, "-cp", str(h), "VerifyAll", jar_path],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return False, str(e)[:300]
    ok = r.returncode == 0
    return ok, ((r.stdout or "") + (r.stderr or ""))[-1500:]
