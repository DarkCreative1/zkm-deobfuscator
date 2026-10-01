from __future__ import annotations
import struct
from dataclasses import dataclass, field

@dataclass
class CpEntry:
    tag: int
    value: object = None

@dataclass
class MethodInfo:
    access: int
    name: str
    desc: str
    code: bytes = b""
    max_stack: int = 0
    max_locals: int = 0
    exception_table: list = field(default_factory=list)
    raw_attrs: list = field(default_factory=list)

@dataclass
class FieldInfo:
    access: int
    name: str
    desc: str

@dataclass
class ClassFile:
    path: str
    minor: int
    major: int
    cp: list
    access: int
    this_class: str
    super_class: str
    interfaces: list[str]
    fields: list[FieldInfo]
    methods: list[MethodInfo]
    source_file: str | None = None
    bootstrap_methods: list = field(default_factory=list)

    def utf8(self, idx: int) -> str:
        e = self.cp[idx]
        if e is None:
            return ""
        if e.tag == 1:
            return e.value
        return str(e.value)

    def class_name(self, idx: int) -> str:
        e = self.cp[idx]
        if e and e.tag == 7:
            return self.utf8(e.value)
        return ""

    def get_strings(self) -> list[tuple[int, str]]:
        out = []
        for i in range(1, len(self.cp)):
            e = self.cp[i]
            if e and e.tag == 8:
                out.append((i, self.utf8(e.value)))
        return out

    def get_method_refs(self) -> list[tuple[int, str, str, str]]:
        out = []
        for i in range(1, len(self.cp)):
            e = self.cp[i]
            if e and e.tag in (10, 11):
                cls, nt = e.value
                cname = self.class_name(cls)
                nt_e = self.cp[nt]
                if nt_e:
                    n, d = nt_e.value
                    out.append((i, cname, self.utf8(n), self.utf8(d)))
        return out

    def get_field_refs(self) -> list[tuple[int, str, str, str]]:
        out = []
        for i in range(1, len(self.cp)):
            e = self.cp[i]
            if e and e.tag == 9:
                cls, nt = e.value
                cname = self.class_name(cls)
                nt_e = self.cp[nt]
                if nt_e:
                    n, d = nt_e.value
                    out.append((i, cname, self.utf8(n), self.utf8(d)))
        return out

    def find_method(self, name: str) -> MethodInfo | None:
        for m in self.methods:
            if m.name == name:
                return m
        return None

class _R:
    def __init__(self, b: bytes):
        self.b = b
        self.p = 0

    def u1(self) -> int:
        v = self.b[self.p]
        self.p += 1
        return v

    def u2(self) -> int:
        v = struct.unpack_from(">H", self.b, self.p)[0]
        self.p += 2
        return v

    def u4(self) -> int:
        v = struct.unpack_from(">I", self.b, self.p)[0]
        self.p += 4
        return v

    def raw(self, n: int) -> bytes:
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

def mutf8_decode(raw: bytes) -> str:

    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        a = raw[i]
        if a < 0x80:
            out.append(chr(a))
            i += 1
        elif (a & 0xE0) == 0xC0 and i + 1 < n and (raw[i + 1] & 0xC0) == 0x80:
            out.append(chr(((a & 0x1F) << 6) | (raw[i + 1] & 0x3F)))
            i += 2
        elif (a & 0xF0) == 0xE0 and i + 2 < n and (raw[i + 1] & 0xC0) == 0x80 \
                and (raw[i + 2] & 0xC0) == 0x80:
            c = ((a & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F)
            out.append(chr(c))
            i += 3
        else:

            out.append(chr(a))
            i += 1
    return "".join(out)

def parse_class(data: bytes, path: str = "<memory>") -> ClassFile:
    r = _R(data)
    assert r.raw(4) == b"\xca\xfe\xba\xbe", "not a class file"
    minor, major = r.u2(), r.u2()
    cp_count = r.u2()
    cp: list = [None] * cp_count
    i = 1
    while i < cp_count:
        tag = r.u1()
        if tag == 1:
            ln = r.u2()
            raw = r.raw(ln)
            try:
                val = raw.decode("utf-8")

                if mutf8_decode(raw) != val:
                    val = mutf8_decode(raw)
            except UnicodeDecodeError:
                val = mutf8_decode(raw)
            cp[i] = CpEntry(1, val)
        elif tag in (3, 4):
            cp[i] = CpEntry(tag, r.u4())
        elif tag in (5, 6):
            hi, lo = r.u4(), r.u4()
            cp[i] = CpEntry(tag, (hi << 32) | lo)
            i += 1
            if i < cp_count:
                cp[i] = None
        elif tag == 7:
            cp[i] = CpEntry(7, r.u2())
        elif tag == 8:
            cp[i] = CpEntry(8, r.u2())
        elif tag in (9, 10, 11, 12, 17, 18):
            a, b = r.u2(), r.u2()
            cp[i] = CpEntry(tag, (a, b))
        elif tag == 15:
            k, idx = r.u1(), r.u2()
            cp[i] = CpEntry(15, (k, idx))
        elif tag == 16:
            cp[i] = CpEntry(16, r.u2())
        elif tag in (19, 20):
            cp[i] = CpEntry(tag, r.u2())
        else:
            raise ValueError(f"unknown cp tag {tag} @ {i}")
        i += 1

    access = r.u2()
    this_c, super_c = r.u2(), r.u2()

    def _cname(idx: int) -> str:
        if idx == 0 or cp[idx] is None:
            return ""
        e = cp[idx]
        assert e.tag == 7
        u = cp[e.value]
        return u.value if u else ""

    nif = r.u2()
    ifs = [_cname(r.u2()) for _ in range(nif)]
    nf = r.u2()
    fields: list[FieldInfo] = []
    for _ in range(nf):
        fa, fn, fd = r.u2(), r.u2(), r.u2()
        na = r.u2()
        for _ in range(na):
            r.u2()
            ln = r.u4()
            r.raw(ln)
        fields.append(FieldInfo(fa, cp[fn].value if cp[fn] else "", cp[fd].value if cp[fd] else ""))
    nm = r.u2()
    methods: list[MethodInfo] = []
    for _ in range(nm):
        ma, mn, md = r.u2(), r.u2(), r.u2()
        mname = cp[mn].value if cp[mn] else ""
        mdesc = cp[md].value if cp[md] else ""
        na = r.u2()
        code = b""
        ms, ml = 0, 0
        etab: list = []
        raw_attrs: list = []
        for _ in range(na):
            an, alen = r.u2(), r.u4()
            aname = cp[an].value if cp[an] else ""
            ab = r.raw(alen)
            raw_attrs.append((aname, ab))
            if aname == "Code" and len(ab) >= 12:
                rr = _R(ab)
                ms, ml = rr.u2(), rr.u2()
                cl = rr.u4()
                code = rr.raw(cl)
                eln = rr.u2()
                for _ in range(eln):
                    etab.append((rr.u2(), rr.u2(), rr.u2(), rr.u2()))

                an2 = rr.u2()
                for _ in range(an2):
                    rr.u2()
                    l2 = rr.u4()
                    rr.raw(l2)
        methods.append(MethodInfo(ma, mname, mdesc, code, ms, ml, etab, raw_attrs))

    na = r.u2()
    src = None
    bsm: list = []
    for _ in range(na):
        an, alen = r.u2(), r.u4()
        aname = cp[an].value if cp[an] else ""
        ab = r.raw(alen)
        if aname == "SourceFile" and len(ab) >= 2:
            idx = struct.unpack_from(">H", ab, 0)[0]
            src = cp[idx].value if cp[idx] else None
        elif aname == "BootstrapMethods" and len(ab) >= 2:
            rr = _R(ab)
            n = rr.u2()
            for _ in range(n):
                mh, na2 = rr.u2(), rr.u2()
                args = [rr.u2() for _ in range(na2)]
                bsm.append((mh, args))
    return ClassFile(path, minor, major, cp, access, _cname(this_c), _cname(super_c),
                     ifs, fields, methods, src, bsm)

_OP_LEN: dict[int, int] = {}
for _op in list(range(0, 16)) + list(range(26, 54)) + list(range(59, 96)) \
        + list(range(96, 132)) + list(range(133, 153)) + [172, 173, 174, 175, 176, 177,
        190, 191, 194, 195, 202]:
    _OP_LEN[_op] = 0
for _op in (16, 18, 21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169, 188):
    _OP_LEN[_op] = 1
for _op in (17, 19, 20, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
            164, 165, 166, 167, 168, 178, 179, 180, 181, 182, 183, 184,
            187, 189, 192, 193, 198, 199):
    _OP_LEN[_op] = 2
_OP_LEN[132] = 2
_OP_LEN[197] = 3
_OP_LEN[185] = 4
_OP_LEN[186] = 4
_OP_LEN[200] = 4
_OP_LEN[201] = 4
_OP_LEN[170] = -1
_OP_LEN[171] = -1
_OP_LEN[196] = -1

def disassemble(code: bytes) -> list[tuple[int, int, bytes]]:

    out: list[tuple[int, int, bytes]] = []
    p = 0
    n = len(code)
    while p < n:
        off = p
        op = code[p]
        p += 1
        if op not in _OP_LEN:
            raise ValueError(f"unknown opcode {op} @ {off}")
        ln = _OP_LEN[op]
        if ln >= 0:
            if p + ln > n:
                raise ValueError(f"truncated instruction {op} @ {off}")
            out.append((off, op, code[p:p + ln]))
            p += ln
        elif op in (170, 171):
            while p % 4 != 0:
                p += 1
            if p + 8 > n:
                raise ValueError(f"truncated switch @ {off}")
            if op == 170:
                lo = struct.unpack_from(">i", code, p + 4)[0]
                hi = struct.unpack_from(">i", code, p + 8)[0]
                cnt = hi - lo + 1
                end = p + 12 + max(cnt, 0) * 4
            else:
                np = struct.unpack_from(">i", code, p + 4)[0]
                end = p + 8 + max(np, 0) * 8
            if end > n:
                raise ValueError(f"truncated switch cases @ {off}")
            out.append((off, op, code[off + 1:end]))
            p = end
        else:
            if p >= n:
                raise ValueError(f"truncated wide @ {off}")
            op2 = code[p]
            if op2 == 132:
                if p + 5 > n:
                    raise ValueError(f"truncated wide-iinc @ {off}")
                out.append((off, op, code[p:p + 5]))
                p += 5
            elif op2 in (21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169):
                if p + 3 > n:
                    raise ValueError(f"truncated wide @ {off}")
                out.append((off, op, code[p:p + 3]))
                p += 3
            else:
                raise ValueError(f"bad wide sub-opcode {op2} @ {off}")
    return out

def verify_disassembly(code: bytes) -> bool:

    try:
        ins = disassemble(code)
    except ValueError:
        return False
    pos = 0
    for off, _, opr in ins:
        if off != pos:
            return False
        pos = off + 1 + len(opr)
    return pos == len(code)

def count_opcode(code: bytes, op: int) -> int:
    return sum(1 for _, o, _ in disassemble(code) if o == op)

def has_string(code: bytes, s: str) -> bool:
    return s.encode("latin1", "ignore") in code
