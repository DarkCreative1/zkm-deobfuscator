from __future__ import annotations
from dataclasses import dataclass, field
import struct
import re

from .classfile import ClassFile, disassemble
from . import crypto as C

@dataclass
class StringFinding:
    technique: str
    method: str
    detail: str
    decrypted: list[str] = field(default_factory=list)

_CP_DER = "DES/CBC/PKCS5Padding"
_OP = {
    "getstatic": 178, "putstatic": 179, "aaload": 50, "ldc": 18,
    "ldc_w": 19, "ldc2_w": 20, "invokestatic": 184, "invokevirtual": 182,
    "invokedynamic": 186, "tableswitch": 170, "jsr": 168, "ret": 169,
    "goto": 167, "sipush": 17, "bipush": 16,
}

def _cp_strings(cf: ClassFile) -> list[str]:
    out = []
    for _, s in cf.get_strings():
        out.append(s)

    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e.tag == 1 and isinstance(e.value, str) and len(e.value) > 8:
            out.append(e.value)
    return out

def _cp_has(cf: ClassFile, needle: str) -> bool:
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e.tag == 1 and needle in str(e.value):
            return True
    return False

def _method_ref_names(cf: ClassFile) -> list[tuple[str, str, str]]:
    return [(c, n, d) for _, c, n, d in cf.get_method_refs()]

def detect_techniques(cf: ClassFile) -> list[StringFinding]:
    out: list[StringFinding] = []
    has_des = _cp_has(cf, "DES/CBC/PKCS5Padding")
    has_indy = len(cf.bootstrap_methods) > 0 and _cp_has(cf, "MutableCallSite")
    refs = _method_ref_names(cf)
    has_tochar = any(d.startswith("(Ljava/lang/String;)") for _, _, d in refs)

    def _is_own(cname: str) -> bool:
        return (cname or "").replace(".", "/") == (cf.this_class or "")
    own_ii = [(c, n) for c, n, d in refs
              if re.fullmatch(r"\(II+\)Ljava/lang/String;", d or "") and _is_own(c)]
    own_ij = [(c, n) for c, n, d in refs
              if re.fullmatch(r"\(IJ\)Ljava/lang/String;", d or "") and _is_own(c)]

    for m in cf.methods:
        ins = disassemble(m.code)
        ops = [o for _, o, _ in ins]

        if _OP["jsr"] in ops or _OP["ret"] in ops:
            out.append(StringFinding("LABEL_JUMP", f"{m.name}{m.desc}",
                                     "jsr/ret subroutine — emitDecryptSubroutine izi"))

        for off, op, opr in ins:
            if op == 170 and len(opr) >= 12:
                try:
                    p = 0
                    while (off + 1 + p) % 4 != 0:
                        p += 1
                    lo = struct.unpack_from(">i", opr, p + 4)[0]
                    hi = struct.unpack_from(">i", opr, p + 8)[0]
                    span = hi - lo + 1
                    if span == 7 or (lo == 0 and hi == 5):
                        out.append(StringFinding("XOR_OUTER_LOOP", f"{m.name}{m.desc}",
                                                 f"tableswitch 7-case @ {off} — xorKeys dongusu"))
                    elif span >= 200:
                        out.append(StringFinding("LOOKUP_METHOD_AND_INDEX", f"{m.name}{m.desc}",
                                                 f"tableswitch ~256-case @ {off} — byteShuffleTable"))
                except Exception:
                    pass

        if own_ii and m.name not in ("<clinit>",):

            for _, o, _b in ins:
                if o == 184:
                    out.append(StringFinding("LOOKUP_CALLSITE", f"{m.name}{m.desc}",
                                             "own class'indaki (II)String helper'a invokestatic"))
                    break

    if own_ii:
        out.append(StringFinding("LOOKUP_METHOD_AND_INDEX", "<class>",
                                 f"(II)/(III)String helper ({own_ii[0][1]}) — rolling-XOR inner"))
    if own_ij or has_des:
        out.append(StringFinding("LOOKUP_METHOD_AND_INDEX_DES", "<class>",
                                 "(IJ)String + DES/CBC/PKCS5Padding — inner DES"))
    if has_indy:
        out.append(StringFinding("INDY_ENTRY_AND_INDEX", "<class>",
                                 "invokedynamic + MutableCallSite bootstrap — DES inner, indy wrapper"))

    for m in cf.methods:
        ins = disassemble(m.code)
        for k in range(len(ins) - 2):
            if ins[k][1] == 178 and ins[k + 2][1] == 50:

                ops2 = [o for _, o, _ in ins[k:k + 3]]
                if 50 in ops2:
                    out.append(StringFinding("FIELD_ARRAY_AND_INDEX", f"{m.name}{m.desc}",
                                             f"getstatic+aaload @ {ins[k][0]}"))
                    break
    if has_tochar and any("([C)Ljava/lang/String;" in (d or "") for _, _, d in refs):
        out.append(StringFinding("SEPARATE_METHODS", "<class>",
                                 "(String;)[C + ([C)String; helper cifti — legacy teknik"))
    return out

def extract_xor_keys_from_method(code: bytes) -> list[int] | None:

    ins = disassemble(code)
    for i, (off, op, opr) in enumerate(ins):
        if op == 170 and len(opr) >= 12:
            keys: list[int] = []

            for _, o2, b2 in ins[i + 1:i + 24]:
                v = _const_push(o2, b2)
                if v is not None and 1 <= v <= 255:
                    keys.append(v)
                    if len(keys) == 7:
                        return keys
    return None

def _const_push(op: int, opr: bytes) -> int | None:
    if 2 <= op <= 8:
        return {2: -1, 3: 0, 4: 1, 5: 2, 6: 3, 7: 4, 8: 5}[op]
    if op == 16 and len(opr) >= 1:
        v = opr[0]
        return v - 256 if v > 127 else v
    if op == 17 and len(opr) >= 2:
        return struct.unpack(">h", opr[:2])[0]
    return None

def _ldc_strings(cf: ClassFile) -> list[str]:

    seen: set[str] = set()
    out: list[str] = []
    for _, s in cf.get_strings():
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

def try_decrypt_chunks(cf: ClassFile, max_n: int = 8) -> dict:

    res: dict = {"xor_keys": None, "chunks": []}
    xor_keys = None
    for m in cf.methods:
        k = extract_xor_keys_from_method(m.code)
        if k:
            xor_keys = k
            break
    res["xor_keys"] = xor_keys
    if not xor_keys:
        return res
    for s in _ldc_strings(cf):
        if len(s) < 2:
            continue
        try:
            hit = best_split_decrypt(s, xor_keys, max_n)
            if hit:
                n, parts, score = hit
                res["chunks"].append({"raw_len": len(s), "n": n, "parts": parts,
                                      "score": round(score, 3)})
        except Exception:
            continue
    return res

def best_split_decrypt(enc_chunk: str, xor_keys: list[int],
                       max_n: int = 8) -> tuple[int, list[str], float] | None:

    best: tuple[float, int, list[str]] | None = None

    for n in range(1, max_n + 1):
        if n > 1 and len(enc_chunk) < 4:
            break
        for split in C.all_splits(enc_chunk, n):
            if len(split) != n:
                continue
            dec = [C.xor_with_keys(p, xor_keys) for p in split]
            score = sum(_score_text(p) for p in dec) / n

            if n == 1 and (score < 0.99 or len(enc_chunk) < 4):
                continue
            key = (round(score, 4), n)
            if best is None or key > (round(best[0], 4), best[1]):
                best = (score, n, dec)
    if best and best[0] > 0.7:
        return (best[1], best[2], best[0])
    return None

def _score_text(s: str) -> float:
    if not s:
        return 0.5
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    return ok / len(s)

def _printable(s: str) -> bool:
    if not s:
        return True
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    return ok / max(len(s), 1) > 0.7

def extract_fieldarray_sites(cf: ClassFile) -> list[tuple[str, str, int, int, str, int]]:

    out: list[tuple[str, str, int, int, str, int]] = []
    for m in cf.methods:
        try:
            ins = disassemble(m.code)
        except Exception:
            continue
        tloc = _table_locals(cf, ins)
        for k in range(len(ins) - 2):
            o0, p0, r0 = ins[k]
            o1, p1, r1 = ins[k + 1]
            o2, p2, r2 = ins[k + 2]
            if p2 != 50:
                continue
            idx = _push_int(cf, p1, r1)
            if idx is None or idx < 0:
                continue
            start, field = None, None

            f = _field_is_strtable(cf, p0, r0)
            if f is not None:
                start, field = o0, f
            else:

                ln = _aload_n(p0, r0)
                if ln is not None and ln in tloc:

                    for kk in range(k):
                        ff = _field_is_strtable(cf, ins[kk][1], ins[kk][2])
                        if ff is not None:
                            field = ff
                            break
                    start = o0
            if start is None or field is None:
                continue
            out.append((m.name, m.desc, start, o2 + 1, field, idx))
    return out

def _table_locals(cf: ClassFile, ins: list) -> set[int]:

    def is_store(k):
        o, p, r = ins[k]
        if p == 58 and len(r) == 1:
            return r[0]
        if p in (75, 76, 77, 78):
            return {75: 0, 76: 1, 77: 2, 78: 3}[p]
        return None
    def is_table_getstatic(k):
        o, p, r = ins[k]
        if p != 178 or len(r) != 2:
            return False
        fidx = (r[0] << 8) | r[1]
        e = cf.cp[fidx]
        if not e or e.tag != 9:
            return False
        cls, nt = e.value
        fn, fd = cf.cp[nt].value
        return cf.utf8(fd) == "[Ljava/lang/String;"
    stores: dict[int, list[int]] = {}
    for k in range(len(ins)):
        n = is_store(k)
        if n is not None:
            stores.setdefault(n, []).append(k)
    out = set()
    for n, ks in stores.items():
        if all(k > 0 and is_table_getstatic(k - 1) for k in ks):
            out.add(n)
    return out

def _aload_n(op: int, opr: bytes) -> int | None:
    if op == 25 and len(opr) == 1:
        return opr[0]
    if op in (42, 43, 44, 45):
        return {42: 0, 43: 1, 44: 2, 45: 3}[op]
    return None

def _push_int(cf: ClassFile, op: int, opr: bytes) -> int | None:
    v = _const_push(op, opr)
    if v is not None:
        return v
    if op in (18, 19) and opr:
        ci = opr[0] if op == 18 else struct.unpack(">H", opr[:2])[0]
        ce = cf.cp[ci]
        if ce and ce.tag == 3:
            vv = ce.value
            return vv - 2**32 if vv >= 2**31 else vv
    return None

def _field_is_strtable(cf: ClassFile, op: int, opr: bytes) -> str | None:
    if op != 178 or len(opr) != 2:
        return None
    fidx = (opr[0] << 8) | opr[1]
    e = cf.cp[fidx]
    if not e or e.tag != 9:
        return None
    cls, nt = e.value
    fn, fd = cf.cp[nt].value
    if cf.utf8(fd) != "[Ljava/lang/String;":
        return None
    return cf.utf8(fn)

def extract_stringfield_sites(cf: ClassFile) -> list[tuple[str, str, int, int, str]]:

    finals = {f.name for f in cf.fields
              if f.desc == "Ljava/lang/String;" and (f.access & 0x10)}
    if not finals:
        return []
    out: list[tuple[str, str, int, int, str]] = []
    for m in cf.methods:
        try:
            ins = disassemble(m.code)
        except Exception:
            continue
        for (off, op, opr) in ins:
            if op != 178 or len(opr) != 2:
                continue
            fidx = (opr[0] << 8) | opr[1]
            e = cf.cp[fidx]
            if not e or e.tag != 9:
                continue
            cls, nt = e.value
            fn, fd = cf.cp[nt].value
            if cf.utf8(fd) != "Ljava/lang/String;":
                continue
            if cf.class_name(cls).replace(".", "/") != (cf.this_class or ""):
                continue
            if cf.utf8(fn) not in finals:
                continue
            out.append((m.name, m.desc, off, off + 3, cf.utf8(fn)))
    return out
