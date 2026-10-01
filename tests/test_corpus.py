import sys, glob, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zkm_deobfuscator.classfile import parse_class, verify_disassembly

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
roots = [
    os.path.join(ROOT, "build", "classes", "java", "main"),
    os.path.join(ROOT, "build", "classes", "java", "test"),
    os.path.join(ROOT, "corpus"),
]
files = []
for r in roots:
    if not os.path.isdir(r):
        continue
    for dp, _, fns in os.walk(r):
        for fn in fns:
            if fn.endswith(".class"):
                files.append(os.path.join(dp, fn))

import zipfile
jar_classes = []
for j in [os.path.join(ROOT, "corpus", "fixtures", "demo2.jar"),
          os.path.join(ROOT, "corpus", "fixtures", "demo2-obf.jar")]:
    os.makedirs(os.path.join(ROOT, "build", "test-tmp"), exist_ok=True)
    try:
        z = zipfile.ZipFile(j)
        for n in z.namelist():
            if n.endswith(".class"):
                jar_classes.append((os.path.basename(j) + "!" + n, z.read(n)))
    except Exception as e:
        print("jar skip:", j, e)

n_ok = n_fail = 0
bad_parse = []
for f in files:
    try:
        cf = parse_class(open(f, "rb").read(), f)
        n_ok += 1
    except Exception as e:
        n_fail += 1
        bad_parse.append((f, str(e)[:100]))
for name, data in jar_classes:
    try:
        parse_class(data, name)
        n_ok += 1
    except Exception as e:
        n_fail += 1
        bad_parse.append((name, str(e)[:100]))
print(f"parse: ok={n_ok} fail={n_fail}")
for f, e in bad_parse[:10]:
    print("  FAIL:", f, e)

n_m = n_bad = 0
bad_m = []
def check(cf, tag):
    global n_m, n_bad
    for m in cf.methods:
        if not m.code:
            continue
        n_m += 1
        if not verify_disassembly(m.code):
            n_bad += 1
            if len(bad_m) < 15:
                bad_m.append(f"{tag}::{m.name}{m.desc} len={len(m.code)}")

for f in files:
    try:
        check(parse_class(open(f, "rb").read(), f), f)
    except Exception:
        pass
for name, data in jar_classes:
    try:
        check(parse_class(data, name), name)
    except Exception:
        pass
print(f"disasm: methods={n_m} bad={n_bad}")
for b in bad_m:
    print("  BAD:", b)
print("CORPUS test BITTI")
