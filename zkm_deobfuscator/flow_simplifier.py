from __future__ import annotations
from dataclasses import dataclass

from .classfile import ClassFile, disassemble

_IFS = {153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 198, 199}
_ATHROW = 191

@dataclass
class FlowFinding:
    kind: str
    where: str
    detail: str
    severity: str = "info"

def _static_writes(cf: ClassFile) -> dict[str, list[str]]:

    writes: dict[str, list[str]] = {}
    for m in cf.methods:
        for _, op, opr in disassemble(m.code):
            if op == 179 and len(opr) == 2:
                idx = (opr[0] << 8) | opr[1]
                writes.setdefault(str(idx), []).append(m.name)
    return writes

def detect_opaque_fields(cf: ClassFile) -> list[FlowFinding]:
    out: list[FlowFinding] = []
    writes = _static_writes(cf)

    reads: dict[str, list[str]] = {}
    for m in cf.methods:
        for _, op, opr in disassemble(m.code):
            if op == 178 and len(opr) == 2:
                idx = (opr[0] << 8) | opr[1]
                reads.setdefault(str(idx), []).append(m.name)
    for idx, w in writes.items():
        if set(w) == {"<clinit>"} and idx in reads and len(reads[idx]) >= 1:

            for m in cf.methods:
                ins = disassemble(m.code)
                for k in range(len(ins) - 1):
                    if ins[k][1] == 178 and len(ins[k][2]) == 2 and \
                            ((ins[k][2][0] << 8) | ins[k][2][1]) == int(idx) and ins[k + 1][1] in _IFS:
                        out.append(FlowFinding(
                            "OPAQUE_PREDICATE_FIELD", f"{cf.path}::{m.name}",
                            f"static field cp#{idx} only <clinit>'te is written, "
                            f"burada getstatic+ifXX — buyuk olasilikla opaque predicate. "
                            f"<clinit> sabit katlama with always-true/false'a indirgenebilir.",
                            "high"))
                        break
                else:
                    continue
                break

    for m in cf.methods:
        ops = [o for _, o, _ in disassemble(m.code)]
        if len(ops) <= 12 and 184 in ops and 154 in ops and any(o in (3, 4) for o in ops) and 172 in ops:
            out.append(FlowFinding("NEGATED_GETTER", f"{cf.path}::{m.name}{m.desc}",
                                   "getter+ifne+iconst_0/1+ireturn — negatedGetter sarmalayici olabilir.",
                                   "medium"))
    return out

def detect_fake_handlers(cf: ClassFile) -> list[FlowFinding]:
    out: list[FlowFinding] = []
    for m in cf.methods:
        if not m.exception_table or not m.code:
            continue
        ins = disassemble(m.code)
        offs = [o for o, _, _ in ins]
        for (s, e, h, _t) in m.exception_table:

            try:
                k = offs.index(h)
            except ValueError:
                continue
            body = [o for _, o, _ in ins[k:k + 4]]
            if body and body[0] == _ATHROW:
                out.append(FlowFinding("FAKE_HANDLER", f"{cf.path}::{m.name}{m.desc}",
                                       f"handler@{h} dosrudan athrow — addRethrowingHandler sahtesi, "
                                       f"koruma aralisi [{s},{e}). removable.", "high"))
            elif len(body) <= 3 and _ATHROW in body:
                out.append(FlowFinding("FAKE_HANDLER?", f"{cf.path}::{m.name}{m.desc}",
                                       f"handler@{h} {len(body)} instr icinde athrow — muhtemel sahte.",
                                       "medium"))

        for fr in cf.methods:
            if fr.code and len(fr.code) <= 8:
                ops = [o for _, o, _ in disassemble(fr.code)]
                if ops[:3] == [25, 25, 176] or ops == [42, 176] or (ops and ops[-1] == 176 and len(ops) <= 3):
                    out.append(FlowFinding("IDENTITY_STUB", f"{cf.path}::{fr.name}{fr.desc}",
                                           "static (T)T{aload;areturn} — ExceptionObfuscator identity stub. "
                                           "Call-site invokestatic nop'a indirgenebilir.", "medium"))
                    break
    return out

def detect_trampolines(cf: ClassFile) -> list[FlowFinding]:
    out: list[FlowFinding] = []
    for m in cf.methods:
        ins = disassemble(m.code)
        n_goto = sum(1 for _, o, _ in ins if o == 167)
        n_tbl = sum(1 for _, o, _ in ins if o == 170)
        if n_goto >= 8 and len(ins) > 0 and n_goto / max(len(ins), 1) > 0.15:
            out.append(FlowFinding("GOTO_TRAMPOLINE", f"{cf.path}::{m.name}{m.desc}",
                                   f"{n_goto} goto / {len(ins)} instr — planFlowObfuscationJumps trampolini "
                                   f"olabilir. CFG rebuild + olu blok temizlisi onerilir.", "medium"))
        if n_tbl >= 2 and m.name not in ("<clinit>",):
            out.append(FlowFinding("DISPATCHER", f"{cf.path}::{m.name}{m.desc}",
                                   f"{n_tbl} tableswitch — GOTO dispatcher veya string shuffle olabilir.",
                                   "low"))
    return out

def detect_all(cf: ClassFile) -> list[FlowFinding]:
    return detect_opaque_fields(cf) + detect_fake_handlers(cf) + detect_trampolines(cf)
