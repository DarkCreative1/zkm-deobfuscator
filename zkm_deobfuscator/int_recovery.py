from __future__ import annotations
import struct

from .classfile import ClassFile, disassemble

M32 = (1 << 32) - 1

def _i32(v: int) -> int:
    v &= M32
    return v - 2**32 if v >= 2**31 else v

def extract_int_lookup_params_cf(cf: ClassFile, code: bytes) -> tuple[int, int] | None:

    ins = disassemble(code)
    for k in range(len(ins) - 5):
        ops = [o for _, o, _ in ins[k:k + 6]]
        if ops[0] == 20 and ops[1] == 127 and ops[2] == 136 and ops[3] == 130 \
                and ops[5] == 130 and ins[k + 4][1] in (16, 17):
            opr = ins[k][2]
            cidx = struct.unpack(">H", opr[:2])[0]
            e = cf.cp[cidx]
            mask = e.value if (e and e.tag == 5) else None
            _, kop, kopr = ins[k + 4]
            if kop == 16:
                v = kopr[0]
                kval = v - 256 if v > 127 else v
            else:
                kval = struct.unpack(">h", kopr[:2])[0]
            if mask is not None:
                return (mask, kval)
    return None

def extract_int_sites(cf: ClassFile, desc: str = "(IJ)I") -> list[tuple[str, int, int]]:

    return [(w, a, b) for (w, _, _, a, b, _, _) in extract_int_site_ranges(cf, desc)]

def extract_int_site_ranges(cf: ClassFile, desc: str = "(IJ)I"
                            ) -> list[tuple[str, str, str, int, int, int, int]]:

    tgt = None
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e.tag == 10:
            cls, nt = e.value
            n, d = cf.cp[nt].value
            if cf.utf8(d) == desc:
                tgt = i
                break
    if tgt is None:
        return []
    out: list[tuple[str, str, str, int, int, int, int]] = []
    for m in cf.methods:
        ins = disassemble(m.code)
        for k in range(len(ins)):
            off, op, opr = ins[k]
            if op == 184 and len(opr) == 2 and ((opr[0] << 8) | opr[1]) == tgt and k >= 2:
                key = _const_long(ins[k - 1][1], ins[k - 1][2], cf)
                arg = _const_int(ins[k - 2][1], ins[k - 2][2], cf)
                if key is not None and arg is not None:
                    end = off + 1 + len(opr)
                    out.append((f"{m.name}{m.desc}@{off}", m.name, m.desc,
                                arg, key, ins[k - 2][0], end))
    return out

def _const_int(op: int, opr: bytes, cf: ClassFile) -> int | None:
    if 2 <= op <= 8:
        return {2: -1, 3: 0, 4: 1, 5: 2, 6: 3, 7: 4, 8: 5}[op]
    if op == 16 and opr:
        v = opr[0]
        return v - 256 if v > 127 else v
    if op == 17 and len(opr) >= 2:
        return struct.unpack(">h", opr[:2])[0]
    if op in (18, 19) and opr:
        idx = opr[0] if op == 18 else struct.unpack(">H", opr[:2])[0]
        e = cf.cp[idx]
        if e and e.tag == 3:
            v = e.value
            return v - 2**32 if v >= 2**31 else v
    return None

def _const_long(op: int, opr: bytes, cf: ClassFile) -> int | None:
    if op == 20 and len(opr) >= 2:
        idx = struct.unpack(">H", opr[:2])[0]
        e = cf.cp[idx]
        if e and e.tag == 5:
            v = e.value
            return v - 2**64 if v >= 2**63 else v
    return None

def recover_int_xor(arg: int, key: int, mask: int, index_xor: int,
                    enc_longs: list[int]) -> int:

    idx = (arg ^ (key & mask) ^ index_xor) & M32
    return _i32(enc_longs[idx] ^ key)
