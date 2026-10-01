from __future__ import annotations
from dataclasses import dataclass

from .classfile import ClassFile

@dataclass
class RefFinding:
    kind: str
    where: str
    detail: str

_LOOKUP_SIGNS = ("(J)Ljava/lang/Class;", "(JJ)Ljava/lang/reflect/Field;",
                 "(J)Ljava/lang/reflect/Field;", "(JJ)Ljava/lang/reflect/Method;",
                 "(J)Ljava/lang/reflect/Method;")

def detect(cf: ClassFile) -> list[RefFinding]:
    out: list[RefFinding] = []
    cp1 = [str(cf.cp[i].value) for i in range(1, len(cf.cp)) if cf.cp[i] and cf.cp[i].tag == 1]

    def has(n: str) -> bool:
        return any(n in s for s in cp1)

    mrefs = [(c, n, d) for _, c, n, d in cf.get_method_refs()]
    sigs = [d for _, _, d in mrefs]
    if any(s in _LOOKUP_SIGNS for s in sigs):
        out.append(RefFinding("REF_RESOLVER", "<class>",
                              "class/field/method resolver helper mevcut — table+reflection indirection"))
    if has("getDeclaredFields") or has("getDeclaredMethods"):
        out.append(RefFinding("REFLECTION_LOOKUP", "<class>",
                              "getDeclaredFields/Methods — linear member lookup (buildField/MethodLookupCode)"))
    if has("parseLong") and has("forName"):
        out.append(RefFinding("INDEX_DECODER", "<class>",
                              "Long.parseLong+Class.forName — indexDecoder + classResolver izi"))
    if has("findStatic") or has("findVirtual") or has("MutableCallSite"):
        out.append(RefFinding("METHODHANDLE_INDY", "<class>",
                              "Lookup.find*/MutableCallSite — MethodHandle/indirection katmani"))
    if has("asCollector") or has("insertArguments") or has("explicitCastArguments"):
        out.append(RefFinding("BOOTSTRAP", "<class>", "MethodHandles bootstrap — invokedynamic resolver"))

    has_long_field = any(f.desc == "J" for f in cf.fields)

    if any("[Ljava/lang/Object;" in (d or "") and (d or "").endswith("[Ljava/lang/Object;")
           for _, _, d in mrefs):
        out.append(RefFinding("PACK_HELPER", "<class>",
                              "([Object;I)[Object; pack helper — MethodParameterObfuscator izi"))

    if any(d in ("(IJ)I", "(IJ)J") for _, _, d in mrefs) and has_long_field:
        out.append(RefFinding("KEYED_LOOKUP", "<class>",
                              "lookup + static J field — MethodKeyInjector with anahtarli casri olabilir; "
                              "keyLocal (lload) sabit katlaninca key sabite indirgenir"))
    return out

def decode_index(packed_key: int) -> int:

    return (packed_key >> 46) & 0xFFFFFFFF
