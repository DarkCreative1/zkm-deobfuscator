import sys, io, subprocess, shutil
sys.path.insert(0, ".")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import zipfile

JAVA = shutil.which("java")
assert JAVA, "java bulunamadi; JDK kurulu olmali"
from zkm_deobfuscator.classfile import parse_class, disassemble
from zkm_deobfuscator import rewrite as RW
from zkm_deobfuscator import flow_simplifier as FL

SRC_JAR = "corpus/fixtures/demo3E-obf.jar"

targets = {}
z = zipfile.ZipFile(SRC_JAR)
raws = {n: z.read(n) for n in z.namelist() if n.endswith(".class")}
for n, raw in raws.items():
    cf = parse_class(raw, n)
    for m in cf.methods:
        if not m.exception_table or not m.code:
            continue
        ins = disassemble(m.code)
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
                    targets.setdefault((n, m.name, m.desc), []).append(k)
print("kaldirilacak:", {k: v for k, v in targets.items()})

patched = dict(raws)
for (n, name, desc), idxs in targets.items():
    before = RW.list_exception_entries(patched[n], name, desc)
    patched[n] = RW.remove_exception_entries(patched[n], name, desc, idxs)
    after = RW.list_exception_entries(patched[n], name, desc)
    print(n, name, desc, "once:", len(before), "-> sonra:", len(after))
    assert len(after) == len(before) - len(idxs)

with zipfile.ZipFile("build/test-tmp/demo3E-patched.jar", "w", zipfile.ZIP_DEFLATED) as out:
    for n, raw in patched.items():
        parse_class(raw, n)
        out.writestr(n, raw)
print("patched jar written, parse OK")

total_removed = sum(len(v) for v in targets.values())
assert total_removed == 8, total_removed
z2 = zipfile.ZipFile("build/test-tmp/demo3E-patched.jar")
cf2 = parse_class(z2.read("a/a/b.class"), "x")
kept = [(m.name, m.desc, m.exception_table) for m in cf2.methods if m.exception_table]
assert len(kept) == 1 and kept[0][0] == "b", kept
print("kalan gercek handler:", kept)

r = subprocess.run([JAVA, "-cp", "build/test-tmp/demo3E-patched.jar", "a.a.a"],
                   capture_output=True, text=True)
print("output:", r.stdout.strip().replace("\n", " | "))
assert "hello-ZKM-E2E-secret-sauce" in r.stdout and "calc=1035" in r.stdout, r.stderr[-500:]
print("PATCHER test GECTI")
