from __future__ import annotations
import struct

def _u2(b: bytes, p: int) -> int:
    return struct.unpack_from(">H", b, p)[0]

def _u4(b: bytes, p: int) -> int:
    return struct.unpack_from(">I", b, p)[0]

def _cp_utf8(cp_vals: list, idx: int) -> str:
    v = cp_vals[idx]
    return v[1] if v and v[0] == 1 else ""

def _parse_cp(data: bytes, pos: int):
    n = _u2(data, pos)
    pos += 2
    vals: list = [None] * n
    i = 1
    while i < n:
        tag = data[pos]
        pos += 1
        if tag == 1:
            ln = _u2(data, pos)
            raw = data[pos + 2:pos + 2 + ln]
            try:
                vals[i] = (1, raw.decode("utf-8"))
            except UnicodeDecodeError:
                vals[i] = (1, __import__("zkm_deobfuscator.classfile",
                                         fromlist=["mutf8_decode"]).mutf8_decode(raw))
            pos += 2 + ln
        elif tag in (3, 4):
            vals[i] = (tag, _u4(data, pos))
            pos += 4
        elif tag in (5, 6):
            vals[i] = (tag, (data[pos:pos + 8]))
            pos += 8
            i += 1
        elif tag == 7:
            vals[i] = (7, _u2(data, pos))
            pos += 2
        elif tag == 8:
            vals[i] = (8, _u2(data, pos))
            pos += 2
        elif tag in (9, 10, 11, 12, 17, 18):
            vals[i] = (tag, (_u2(data, pos), _u2(data, pos + 2)))
            pos += 4
        elif tag == 15:
            vals[i] = (15, (data[pos], _u2(data, pos + 1)))
            pos += 3
        elif tag == 16:
            vals[i] = (16, _u2(data, pos))
            pos += 2
        elif tag in (19, 20):
            vals[i] = (tag, _u2(data, pos))
            pos += 2
        else:
            raise ValueError(f"cp tag {tag}")
        i += 1
    return vals, pos

def _skip_attrs(data: bytes, pos: int, count: int) -> int:
    for _ in range(count):
        ln = _u4(data, pos + 2)
        pos += 6 + ln
    return pos

def _iter_methods(data: bytes):

    pos = 8
    cp_vals, pos = _parse_cp(data, pos)
    pos += 2 + 2 + 2
    nif = _u2(data, pos)
    pos += 2 + 2 * nif
    nf = _u2(data, pos)
    pos += 2
    for _ in range(nf):
        pos += 6
        pos = _skip_attrs(data, pos + 2, _u2(data, pos))
    nm = _u2(data, pos)
    pos += 2
    for _ in range(nm):
        access = _u2(data, pos)
        name = _cp_utf8(cp_vals, _u2(data, pos + 2))
        desc = _cp_utf8(cp_vals, _u2(data, pos + 4))
        na = _u2(data, pos + 6)
        pos += 8
        for _ in range(na):
            an = _cp_utf8(cp_vals, _u2(data, pos))
            alen = _u4(data, pos + 2)
            abase = pos + 6
            if an == "Code":
                maxs = _u2(data, abase)
                maxl = _u2(data, abase + 2)
                clen = _u4(data, abase + 4)
                coff = abase + 8
                etab_n = _u2(data, coff + clen)
                etab_off = coff + clen + 2
                yield {"name": name, "desc": desc, "access": access,
                       "attr_len_pos": pos + 2, "attr_len": alen,
                       "code_off": coff, "code_len": clen,
                       "etab_off": etab_off, "etab_n": etab_n,
                       "max_stack": maxs, "max_locals": maxl}
            pos += 6 + alen

def list_exception_entries(data: bytes, method_name: str,
                           method_desc: str) -> list[tuple[int, int, int, int]]:
    for m in _iter_methods(data):
        if m["name"] == method_name and m["desc"] == method_desc:
            out = []
            for k in range(m["etab_n"]):
                o = m["etab_off"] + 8 * k
                out.append((_u2(data, o), _u2(data, o + 2),
                            _u2(data, o + 4), _u2(data, o + 6)))
            return out
    raise KeyError(f"method {method_name}{method_desc} not found")

def find_strict_fake_handlers(data: bytes) -> dict[tuple[str, str], list[int]]:

    from .classfile import parse_class, disassemble
    try:
        cf = parse_class(data, "<mem>")
    except Exception:
        return {}
    out: dict[tuple[str, str], list[int]] = {}
    for m in cf.methods:
        if not m.exception_table or not m.code:
            continue
        try:
            ins = disassemble(m.code)
        except Exception:
            continue
        offs = [o for o, _, _ in ins]
        ops = [o for _, o, _ in ins]
        for k, (s, e, h, t) in enumerate(m.exception_table):
            try:
                ki = offs.index(h)
            except ValueError:
                continue
            if ops[ki] == 191:
                nxt = offs[ki + 1] if ki + 1 < len(offs) else len(m.code)
                if nxt == h + 1:
                    out.setdefault((m.name, m.desc), []).append(k)
    return out

def strip_fake_handlers(data: bytes) -> tuple[bytes, dict]:

    fakes = find_strict_fake_handlers(data)
    cur = data
    counts: dict = {}
    for (name, desc), idxs in fakes.items():
        before = list_exception_entries(cur, name, desc)
        cur = remove_exception_entries(cur, name, desc, idxs)
        after = list_exception_entries(cur, name, desc)
        assert len(after) == len(before) - len(idxs)
        counts[f"{name}{desc}"] = len(idxs)
    return cur, counts

def remove_exception_entries(data: bytes, method_name: str, method_desc: str,
                             drop: list[int]) -> bytes:

    targets = [m for m in _iter_methods(data)
               if m["name"] == method_name and m["desc"] == method_desc]
    if not targets:
        raise KeyError(f"method {method_name}{method_desc} not found")
    if len(targets) > 1:
        raise ValueError("ambiguous method (bridge?)")
    m = targets[0]
    keep = [k for k in range(m["etab_n"]) if k not in set(drop)]
    if len(keep) == m["etab_n"]:
        return data

    new_tab = b"".join(
        data[m["etab_off"] + 8 * k:m["etab_off"] + 8 * k + 8] for k in keep)
    head = data[:m["etab_off"] - 2]
    tail = data[m["etab_off"] + 8 * m["etab_n"]:]
    new_count = struct.pack(">H", len(keep))

    new_attr_len = m["attr_len"] - 8 * (m["etab_n"] - len(keep))
    patched = head + new_count + new_tab + tail
    patched = (patched[:m["attr_len_pos"]]
               + struct.pack(">I", new_attr_len)
               + patched[m["attr_len_pos"] + 4:])
    return patched
