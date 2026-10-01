from __future__ import annotations
import struct

from .classfile import disassemble
from . import rewrite as RW

_BRANCH2 = set(range(153, 169)) | {198, 199}
_BRANCH4 = {200, 201}

def jump_targets(code: bytes) -> set[int]:

    out: set[int] = set()
    for off, op, opr in disassemble(code):
        if op in _BRANCH2 and len(opr) == 2:
            out.add(off + struct.unpack(">h", opr)[0])
        elif op in _BRANCH4 and len(opr) == 4:
            out.add(off + struct.unpack(">i", opr)[0])
        elif op in (170, 171):
            p = 0
            while (off + 1 + p) % 4 != 0:
                p += 1
            if op == 170:
                default = struct.unpack_from(">i", opr, p)[0]
                lo = struct.unpack_from(">i", opr, p + 4)[0]
                hi = struct.unpack_from(">i", opr, p + 8)[0]
                out.add(off + default)
                for i in range(max(hi - lo + 1, 0)):
                    out.add(off + struct.unpack_from(">i", opr, p + 12 + 4 * i)[0])
            else:
                default = struct.unpack_from(">i", opr, p)[0]
                np = struct.unpack_from(">i", opr, p + 4)[0]
                out.add(off + default)
                for i in range(max(np, 0)):
                    out.add(off + struct.unpack_from(">i", opr, p + 16 + 8 * i)[0])
    return out

def _cp_append_string(cp_vals: list, enc: dict) -> dict:

    out = {}
    for i in range(1, len(cp_vals)):
        e = cp_vals[i]
        if e and e[0] == 8:
            u = cp_vals[e[1]]
            if u and u[0] == 1:
                out[u[1].encode("utf-8", "surrogatepass")] = i
    return out

def _encode_mutf8(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        o = ord(ch)
        if o == 0:
            out += b"\xc0\x80"
        elif o < 0x80:
            out.append(o)
        elif o < 0x800:
            out.append(0xC0 | (o >> 6))
            out.append(0x80 | (o & 0x3F))
        else:

            if 0x10000 <= o <= 0x10FFFF:
                v = o - 0x10000
                hi, lo = 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF)
                for u in (hi, lo):
                    out.append(0xE0 | (u >> 12))
                    out.append(0x80 | ((u >> 6) & 0x3F))
                    out.append(0x80 | (u & 0x3F))
            else:
                out.append(0xE0 | (o >> 12))
                out.append(0x80 | ((o >> 6) & 0x3F))
                out.append(0x80 | (o & 0x3F))
    return bytes(out)

def patch_constants(raw: bytes, str_patches: list[tuple[str, str, int, int, str]],
                    int_patches: list[tuple[str, str, int, int, int]]) -> tuple[bytes, dict]:

    from .classfile import mutf8_decode
    pos = 8
    cp_vals, pos = RW._parse_cp(raw, pos)

    str_index: dict[bytes, int] = {}
    int_index: dict[int, int] = {}
    for i in range(1, len(cp_vals)):
        e = cp_vals[i]
        if not e:
            continue
        if e[0] == 8:
            u = cp_vals[e[1]]
            if u and u[0] == 1:
                ub = u[1] if isinstance(u[1], bytes) else u[1].encode("utf-8", "surrogatepass")
                str_index[ub] = i
        elif e[0] == 3:
            int_index[e[1]] = i

    cp_count = len(cp_vals)

    p = 8
    _, cp_end = RW._parse_cp(raw, p)
    cp_end_pos = cp_end

    new_entries = bytearray()
    nxt = cp_count

    def get_string_idx(text: str) -> int:
        nonlocal nxt, new_entries
        key = text.encode("utf-8", "surrogatepass")
        if key in str_index:
            return str_index[key]
        ub = _encode_mutf8(text)
        new_entries.append(1)
        new_entries += struct.pack(">H", len(ub)) + ub
        uidx = nxt
        nxt += 1
        new_entries.append(8)
        new_entries += struct.pack(">H", uidx)
        sidx = nxt
        nxt += 1
        str_index[key] = sidx
        return sidx

    def get_int_idx(v: int) -> int:
        nonlocal nxt, new_entries
        if v in int_index:
            return int_index[v]
        new_entries.append(3)
        new_entries += struct.pack(">i", v)
        iidx = nxt
        nxt += 1
        int_index[v] = iidx
        return iidx

    code_map: dict[tuple[str, str], tuple[bytes, dict]] = {}
    for m in RW._iter_methods(raw):
        code_map[(m["name"], m["desc"])] = (raw[m["code_off"]:m["code_off"] + m["code_len"]], m)

    out = bytearray(raw)
    skipped: list[str] = []
    applied = 0

    def apply_patches(patches, is_str: bool):
        nonlocal applied
        for name, desc, start, end, val in patches:
            key = (name, desc)
            if key not in code_map:
                skipped.append(f"{name}{desc}@[{start},{end}): method absent")
                continue
            code, m = code_map[key]
            span = end - start
            idx = get_string_idx(val) if is_str else get_int_idx(val)
            need = 3 if idx > 255 else 2
            if span < need:
                skipped.append(f"{name}{desc}@[{start},{end}): aralik kisa")
                continue

            tgts = jump_targets(code)
            inside = sorted(t for t in tgts if start < t < end)
            ldc_at = start
            if any(t == start for t in tgts):
                pass
            if inside:
                if len(set(inside)) == 1:

                    ldc_at = inside[0]
                else:
                    skipped.append(f"{name}{desc}@[{start},{end}): coklu ic dal")
                    continue

            bad = False
            for k in range(m["etab_n"]):
                o = m["etab_off"] + 8 * k
                s0, e0, h0 = struct.unpack_from(">HHH", raw, o)
                if any(start <= x < end for x in (s0, e0, h0)):
                    bad = True
                    break
            if bad:
                skipped.append(f"{name}{desc}@[{start},{end}): exception siniri")
                continue

            base = m["code_off"]
            lp = 3 if idx > 255 else 2
            if ldc_at + lp > end:
                skipped.append(f"{name}{desc}@[{start},{end}): ldc sigmiyor")
                continue
            for i in range(start, ldc_at):
                out[base + i] = 0
            if idx > 255:
                out[base + ldc_at:base + ldc_at + 3] = bytes([19]) + struct.pack(">H", idx)
            else:
                out[base + ldc_at:base + ldc_at + 2] = bytes([18, idx])
            for i in range(ldc_at + lp, end):
                out[base + i] = 0
            applied += 1

    apply_patches(str_patches, True)
    apply_patches(int_patches, False)

    if new_entries:

        header = bytes(out[:8])
        old_count = struct.unpack_from(">H", bytes(out), 8)[0]
        cp_bytes_old = bytes(out[10:cp_end_pos])
        rest = bytes(out[cp_end_pos:])
        result = (header[:8] + struct.pack(">H", nxt) + cp_bytes_old
                  + bytes(new_entries) + rest)
        return result, {"applied": applied, "skipped": skipped,
                        "added_cp": nxt - old_count}
    return bytes(out), {"applied": applied, "skipped": skipped, "added_cp": 0}
