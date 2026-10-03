from __future__ import annotations
import struct
from dataclasses import dataclass

from .classfile import ClassFile, disassemble
from . import crypto as C

@dataclass
class ConstFinding:
    kind: str
    method: str
    detail: str

def detect(cf: ClassFile) -> list[ConstFinding]:
    out: list[ConstFinding] = []
    mrefs = [(c, n, d) for _, c, n, d in cf.get_method_refs()]
    has_ij_i = any(d == "(IJ)I" for _, _, d in mrefs)
    has_ij_j = any(d == "(IJ)J" for _, _, d in mrefs)
    has_nopad = any("DES/CBC/NoPadding" in str(cf.cp[i].value)
                    for i in range(1, len(cf.cp)) if cf.cp[i] and cf.cp[i].tag == 1)
    has_threadid = any("getId" in str(cf.cp[i].value) or "threadId" in str(cf.cp[i].value)
                       for i in range(1, len(cf.cp)) if cf.cp[i] and cf.cp[i].tag == 1)
    if has_ij_i:
        out.append(ConstFinding("INT_LOOKUP", "<class>",
                                "(IJ)I lookup mevcut" + (" + DES/CBC/NoPadding" if has_nopad else " (XOR)")))
    if has_ij_j:
        out.append(ConstFinding("LONG_LOOKUP", "<class>",
                                "(IJ)J lookup mevcut" + (" + DES/CBC/NoPadding" if has_nopad else " (XOR)")))
    if has_nopad:
        out.append(ConstFinding("DES_NOPAD", "<class>", "DES/CBC/NoPadding sabiti — int/long inner DES"))
    if has_threadid and (has_ij_i or has_ij_j):
        out.append(ConstFinding("CIPHER_CACHE", "<class>",
                                "Thread.getId/threadId cipher cache — DES lookup işareti"))
    cp1 = [str(cf.cp[i].value) for i in range(1, len(cf.cp)) if cf.cp[i] and cf.cp[i].tag == 1]
    has_mh = any(("MutableCallSite" in s or "findStatic" in s or "findVirtual" in s) for s in cp1)
    if cf.bootstrap_methods and (has_ij_i or has_ij_j) and has_mh:
        out.append(ConstFinding("INDY_CONST", "<class>", "invokedynamic const lookup (indy wrapper)"))

    for m in cf.methods:
        ins = disassemble(m.code)
        for k in range(len(ins) - 2):
            if ins[k][1] == 20 and ins[k + 1][1] in (16, 17) and ins[k + 2][1] == 167:
                out.append(ConstFinding("ENC_SLOT", f"{m.name}{m.desc}",
                                        f"ldc2_w+push+goto dispatch @ {ins[k][0]}"))
                break
    return out

def recover_int(enc_long: int, per_value_key: int, outer_key: int,
                outer_is_des: bool, inner_is_des: bool) -> int:

    tmp = C.des_long_crypt(enc_long, outer_key, True) if outer_is_des else (enc_long ^ outer_key)
    rnd = C.des_long_crypt(tmp, per_value_key, True) if inner_is_des else (tmp ^ per_value_key)
    rnd &= 0xFFFFFFFFFFFFFFFF
    # Java int semantics: pack signed so struct.pack(">i") never fails.
    return rnd - 2**32 if rnd >= 2**31 else rnd

def recover_long(enc_long: int, per_value_key: int, outer_key: int,
                 outer_is_des: bool, inner_is_des: bool) -> int:
    tmp = C.des_long_crypt(enc_long, outer_key, True) if outer_is_des else (enc_long ^ outer_key)
    return C.des_long_crypt(tmp, per_value_key, True) if inner_is_des else (tmp ^ per_value_key)
