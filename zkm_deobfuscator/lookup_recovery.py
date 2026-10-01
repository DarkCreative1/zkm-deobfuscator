from __future__ import annotations
import struct

from .classfile import ClassFile, disassemble
from . import crypto as C
from .string_decryptor import extract_xor_keys_from_method, _const_push

def clinit_chunks_in_order(cf: ClassFile) -> list[str]:

    m = cf.find_method("<clinit>")
    if not m:
        return []
    out: list[str] = []
    for _, op, opr in disassemble(m.code):
        s = None
        if op == 18 and len(opr) >= 1:
            e = cf.cp[opr[0]]
            if e and e.tag == 8:
                s = cf.utf8(e.value)
        elif op == 19 and len(opr) >= 2:
            idx = struct.unpack(">H", opr[:2])[0]
            e = cf.cp[idx]
            if e and e.tag == 8:
                s = cf.utf8(e.value)
        if s is not None and len(s) >= 2:
            out.append(s)
    return out

def clinit_table_sizes(cf: ClassFile) -> list[int]:

    m = cf.find_method("<clinit>")
    if not m:
        return []

    ins = disassemble(m.code)
    out: list[int] = []
    for k in range(len(ins) - 1):
        off, op, opr = ins[k]
        if op == 189 and len(opr) == 2:
            cidx = (opr[0] << 8) | opr[1]
            e = cf.cp[cidx]
            if e and e.tag == 7 and cf.utf8(e.value) == "java/lang/String":
                v = _const_push(*ins[k - 1][1:])
                if v is not None and v > 0:
                    out.append(v)
    return out

def extract_lookup_params(cf: ClassFile, code: bytes) -> dict | None:

    ins = disassemble(code)
    by_off = {off: (op, opr) for off, op, opr in ins}
    index_xor = None
    shuffle: list[int] | None = None
    for k in range(len(ins) - 4):
        ops = [o for _, o, _ in ins[k:k + 5]]

        if ops[0] in (21, 26, 27, 28, 29) and ops[2] == 130 and ops[4] == 126:
            _, kop, kopr = ins[k + 1]
            if kop == 16:
                v = kopr[0]
                index_xor = v - 256 if v > 127 else v
            elif kop == 17:
                index_xor = struct.unpack(">h", kopr[:2])[0]
            break
    for off, op, opr in ins:
        if op != 170 or len(opr) < 12:
            continue
        p = 0
        while (off + 1 + p) % 4 != 0:
            p += 1
        lo = struct.unpack_from(">i", opr, p + 4)[0]
        hi = struct.unpack_from(">i", opr, p + 8)[0]
        if hi - lo + 1 < 200:
            continue
        default = struct.unpack_from(">i", opr, p)[0]
        tbl = [struct.unpack_from(">i", opr, p + 12 + 4 * i)[0]
               for i in range(hi - lo + 1)]
        vals = []
        ok = True
        for t in tbl + [default]:
            tgt = off + t
            if tgt not in by_off:
                ok = False
                break
            o2, b2 = by_off[tgt]
            v = _const_push(o2, b2)
            if v is None:
                ok = False
                break
            vals.append(v & 0xFF)
        if ok and len(vals) >= 256:
            shuffle = vals[:256]
            break
    if index_xor is None or shuffle is None:
        return None
    return {"index_xor": index_xor & 0xFFFF, "shuffle": shuffle}

def extract_lookup_sites(cf: ClassFile, desc: str = "(II)Ljava/lang/String;") -> list[tuple[str, int, int]]:

    return [(w, a, b) for (w, _, _, a, b, _, _) in extract_lookup_site_ranges(cf, desc)]

def extract_lookup_site_ranges(cf: ClassFile,
                               desc: str = "(II)Ljava/lang/String;"
                               ) -> list[tuple[str, str, str, int, int, int, int]]:

    tgt = None
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e.tag == 10:
            cls, nt = e.value
            cname = cf.class_name(cls)
            n, d = cf.cp[nt].value
            if cf.utf8(d) == desc and cname.replace(".", "/") == (cf.this_class or ""):
                tgt = i
    if tgt is None:
        return []
    out = []
    for m in cf.methods:
        ins = disassemble(m.code)
        for k in range(len(ins)):
            off, op, opr = ins[k]
            if op == 184 and len(opr) == 2 and ((opr[0] << 8) | opr[1]) == tgt and k >= 2:
                a = _const_push(*ins[k - 2][1:])
                b = _const_push(*ins[k - 1][1:])
                if a is None:
                    a = _ldc_int(cf, *ins[k - 2][1:])
                if b is None:
                    b = _ldc_int(cf, *ins[k - 1][1:])
                if a is not None and b is not None:
                    end = off + 1 + len(opr)
                    out.append((f"{m.name}{m.desc}@{off}", m.name, m.desc,
                                a, b, ins[k - 2][0], end))
    return out

def _ldc_int(cf: ClassFile, op: int, opr: bytes) -> int | None:
    if op in (18, 19) and opr:
        idx = opr[0] if op == 18 else struct.unpack(">H", opr[:2])[0]
        e = cf.cp[idx]
        if e and e.tag == 3:
            v = e.value
            return v - 2**32 if v >= 2**31 else v
    return None

def inner_decrypt(enc_piece: str, key: int, shuffle: list[int]) -> str:
    ku = key & 0xFFFF
    k0, k1 = ku & 255, (ku >> 8) & 255
    off = shuffle[ord(enc_piece[0]) & 255]
    bb = [(k0 - off) % 256, (k1 - off) % 256]
    out = []
    for i, ch in enumerate(enc_piece):
        g = i % 2
        e = ord(ch)
        pl = (e ^ bb[g]) & 0xFFFF
        out.append(chr(pl))
        bb[g] = (((bb[g] >> 3) | (bb[g] << 5)) ^ pl) & 255
    return "".join(out)

def _print_score(s: str) -> float:
    if not s:
        return 0.5
    return sum(1 for c in s if c.isprintable() or c in "\n\t\r") / len(s)

def _ascii_score(s: str) -> float:

    if not s:
        return 0.0
    a = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\t") / len(s)
    return a

def valid_intervals(ch: str, max_piece: int = 40) -> list[tuple[int, int]]:

    out = []
    L = len(ch)

    for e in range(1, min(L, max_piece) + 1):
        out.append((0, e))

    for s in range(1, L):
        want = ord(ch[s - 1])
        if 1 <= want <= max_piece and s + want <= L:
            out.append((s, s + want))
    return out

def recover_direct(cf: ClassFile, max_piece: int = 40,
                   min_score: float = 0.9, top_k: int = 6) -> dict:

    res: dict = {"plaintexts": {}, "log": []}
    m = cf.find_method("<clinit>")
    if not m:
        return res
    xor_keys = extract_xor_keys_from_method(m.code)
    if not xor_keys:
        res["log"].append("xorKeys absent")
        return res
    chunks = [s for s in clinit_chunks_in_order(cf) if len(s) >= 4]
    lookups = [mm for mm in cf.methods
               if mm.desc in ("(II)Ljava/lang/String;", "(III)Ljava/lang/String;")]
    if not lookups:
        res["log"].append("lookup absent")
        return res
    params = extract_lookup_params(cf, lookups[0].code)
    if not params:
        res["log"].append("lookup params absent")
        return res
    shuffle = params["shuffle"]
    sites = extract_lookup_sites(cf, lookups[0].desc)
    res["log"].append(f"chunks={len(chunks)} sites={len(sites)}")

    per_site: dict[str, list] = {}
    for where, encIdx, key in sites:
        cands = []
        for ci, ch in enumerate(chunks):
            for s, e in valid_intervals(ch, max_piece):
                piece = ch[s:e]
                try:
                    outer = C.xor_with_keys(piece, xor_keys)
                    pl = inner_decrypt(outer, key, shuffle)
                except Exception:
                    continue
                asc = _ascii_score(pl)
                if asc < min_score:
                    continue
                sc = _print_score(pl)
                cands.append(((round(asc, 4), round(sc, 4), len(pl)), ci, s, e, pl))
        cands.sort(key=lambda c: c[0], reverse=True)

        seen = set()
        uniq = []
        for c in cands:
            k = (c[1], c[2], c[3])
            if k not in seen:
                seen.add(k)
                uniq.append(c)
        per_site[where] = uniq[:top_k]
        if not uniq:
            res["log"].append(f"{where} ADAY absent")

    taken: list[tuple[int, int, int]] = []
    order = sorted(per_site, key=lambda w: per_site[w][0][0] if per_site[w] else (0,),
                   reverse=True)
    for where in order:
        placed = False
        for bkey, ci, s, e, pl in per_site[where]:
            if any(ci == t[0] and not (e <= t[1] or s >= t[2]) for t in taken):
                continue
            taken.append((ci, s, e))
            res["plaintexts"][where] = pl
            res["log"].append(f"{where} <- chunk{ci}[{s}:{e}] ascii={bkey[0]:.2f}")
            placed = True
            break
        if not placed:
            res["log"].append(f"{where} COZULEMEDI")
    return res

def recover_class_strings(cf: ClassFile) -> dict:

    res: dict = {"plaintexts": {}, "log": []}
    m = cf.find_method("<clinit>")
    if not m:
        return res
    xor_keys = extract_xor_keys_from_method(m.code)
    if not xor_keys:
        res["log"].append("xorKeys not found")
        return res
    chunks = clinit_chunks_in_order(cf)
    sizes = clinit_table_sizes(cf)
    lookups = [mm for mm in cf.methods
               if mm.desc in ("(II)Ljava/lang/String;", "(III)Ljava/lang/String;")]
    if not lookups:
        res["log"].append("lookup helper absent")
        return res
    lk = lookups[0]
    params = extract_lookup_params(cf, lk.code)
    if not params:
        res["log"].append("lookup parametreleri cikarilamadi")
        return res
    sites = extract_lookup_sites(cf, lk.desc)
    if not sites:
        res["log"].append("call-site absent")
        return res
    ix, shuffle = params["index_xor"], params["shuffle"]

    total = sizes[0] if sizes else len(sites)

    cand: list[list[list[str]]] = []
    for c in chunks:
        per_n = []
        for n in range(1, min(len(c), 12) + 1):
            for sp in C.all_splits(c, n, cap=60):
                if len(sp) == n:
                    per_n.append([C.xor_with_keys(p, xor_keys) for p in sp])
                    break
        cand.append(per_n)

    import itertools
    best = None

    options = [c[:12] for c in cand]
    count = 1
    for o in options:
        count *= max(len(o), 1)
    res["log"].append(f"chunks={len(chunks)} sizes={sizes} sites={len(sites)} combos={count}")
    if count > 20000:
        res["log"].append("arama uzayi very buyuk, kisitlandirildi")
        options = [o[:4] for o in options]
    for combo in itertools.product(*options):
        flat = [p for split in combo for p in split]
        if len(flat) != total:
            continue
        score = asc = 0.0
        plains: dict[str, str] = {}
        ok_all = True
        for where, encIdx, key in sites:
            pos = (encIdx ^ ix) & 0xFFFF
            if pos >= len(flat):
                ok_all = False
                break
            try:
                pl = inner_decrypt(flat[pos], key, shuffle)
            except Exception:
                ok_all = False
                break
            plains[where] = pl
            score += _print_score(pl)
            asc += _ascii_score(pl)
        if not ok_all:
            continue
        score /= max(len(sites), 1)
        asc /= max(len(sites), 1)
        bkey = (round(asc, 4), round(score, 4))
        if best is None or bkey > (round(best[0], 4), round(best[3], 4)):
            best = (score, plains, [len(s) for s in combo], asc)
    if best and best[3] > 0.6:
        res["plaintexts"] = best[1]
        res["log"].append(f"SECILDI layout={[int(x) for x in best[2]]} ascii={best[3]:.3f}")
    else:
        res["log"].append("uygun layout not found")
    return res
