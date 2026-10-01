from __future__ import annotations
from dataclasses import dataclass
import re

from .classfile import ClassFile, disassemble

_UNBOX = {"intValue": "I", "longValue": "J", "floatValue": "F", "doubleValue": "D",
          "booleanValue": "Z", "charValue": "C", "byteValue": "B", "shortValue": "S"}

@dataclass
class ParamFinding:
    kind: str
    where: str
    detail: str

def detect_param_obfuscation(cf: ClassFile) -> list[ParamFinding]:
    out: list[ParamFinding] = []
    for m in cf.methods:
        if m.desc.startswith("([Ljava/lang/Object;)"):

            ins = disassemble(m.code)
            ops = [o for _, o, _ in ins]
            if 50 in ops and 192 in ops:

                unboxes = [n for _, _, n, _ in
                           [(0, "", n, d) for _, _, n, d in cf.get_method_refs()] if n in _UNBOX]

                idxs = []
                for k in range(len(ins)):
                    if ins[k][1] == 50 and k >= 1:
                        v = _push_const(ins[k - 1][1], ins[k - 1][2])
                        if v is not None:
                            idxs.append(v)
                out.append(ParamFinding(
                    "PARAM_OBFUSCATED", f"{cf.path}::{m.name}{m.desc}",
                    f"descriptor ([Object;)Ret + aaload/checkcast{(f' + unbox{unboxes}' if unboxes else '')}"
                    f"{(f' + unpack-idx sirasi={idxs}' if idxs else '')} — "
                    f"orijinal arity aaload idx sirasindan cikarilabilir."))

    for m in cf.methods:
        if m.desc.endswith("[Ljava/lang/Object;") and "[Ljava/lang/Object;" in m.desc:
            ops = [o for _, o, _ in disassemble(m.code)]
            if 89 in ops and 83 in ops and 176 in ops and len(ops) <= 30:
                out.append(ParamFinding("PACK_HELPER", f"{cf.path}::{m.name}{m.desc}",
                                        "pack helper — caller tarafinda inline edilip eleman sirasi cikarilmali."))
    return out

def _push_const(op: int, opr: bytes) -> int | None:
    if 2 <= op <= 8:
        return {2: -1, 3: 0, 4: 1, 5: 2, 6: 3, 7: 4, 8: 5}[op]
    if op == 16 and opr:
        v = opr[0]
        return v - 256 if v > 127 else v
    if op == 17 and len(opr) >= 2:
        import struct
        return struct.unpack(">h", opr[:2])[0]
    return None

_OBF_NAME = re.compile(r"^[a-zA-Z]{1,3}$|^[IlO0]{2,}$|^m\d+$|^func\d+$")

def suggest_names(cf: ClassFile) -> list[tuple[str, str, str]]:

    out: list[tuple[str, str, str]] = []
    ci = 0
    mi = 0
    for f in cf.fields:
        if _OBF_NAME.fullmatch(f.name or "") and f.name not in ("<init>", "<clinit>"):
            out.append(("field", f.name, f"f_{ci:03d}_{f.desc.replace('/', '_')[:12]}"))
            ci += 1
    for m in cf.methods:
        if m.name in ("<init>", "<clinit>"):
            continue
        if _OBF_NAME.fullmatch(m.name or ""):
            out.append(("method", f"{m.name}{m.desc}", f"m_{mi:03d}"))
            mi += 1

    simple = (cf.this_class or "").split("/")[-1]
    if _OBF_NAME.fullmatch(simple or ""):
        out.append(("class", cf.this_class, f"{(cf.this_class or '').rsplit('/', 1)[0]}/C_{simple}_renamed"))
    return out
