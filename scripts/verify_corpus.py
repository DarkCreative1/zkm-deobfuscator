#!/usr/bin/env python3
"""Runs the deobfuscator over every corpus jar and verifies 1:1 restoration.

For each corpus/jars/<demo>-<tag>/{obf,original}.jar:
  1. deobfuscates obf.jar -> deobf.jar
  2. runs original and deobf, compares stdout byte-for-byte
  3. compares class / field / method signatures

Exit code is non-zero if any corpus fails.
"""
import os
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")
def _tool(name, fallback):
    java = os.environ.get("JAVA_HOME")
    if not java:
        return fallback
    exe = name + ".exe" if os.name == "nt" else ""
    for sub in (os.path.join("bin", name + exe), os.path.join("bin", "java")):
        p = os.path.join(java, *sub.split(os.sep))
        if os.path.isfile(p):
            return p
    return fallback


JAVA_BIN = _tool("java", "java")
JAR = _tool("jar", "jar")

CP = os.pathsep.join([
    os.path.join(ROOT, "build", "classes", "java", "main"),
    os.path.join(ROOT, "lib", "asm-9.8.jar"),
    os.path.join(ROOT, "lib", "asm-tree-9.8.jar"),
    os.path.join(ROOT, "lib", "asm-commons-9.8.jar"),
])

HEADER = ("corpus", "main", "verify", "run", "1:1", "skipped", "status")


def jar_classes(path):
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist() if n.endswith(".class")}


def run_java(jar, main, timeout=90):
    try:
        r = subprocess.run([JAVA_BIN, "-cp", jar, main],
                           capture_output=True, timeout=timeout)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return -1, b""


def find_main(jar):
    with zipfile.ZipFile(jar) as z:
        for n in sorted(z.namelist()):
            if not n.endswith(".class"):
                continue
            name = n[:-6].replace("/", ".")
            rc, _ = run_java(jar, name, timeout=20)
            if rc == 0:
                return name
    return None


def signature(data, name):
    sys.path.insert(0, ROOT)
    from zkm_deobfuscator.classfile import parse_class
    cf = parse_class(data, name)
    sig = set()
    for f in getattr(cf, "fields", []):
        sig.add("F %s:%s" % (f.name, f.desc))
    for m in getattr(cf, "methods", []):
        sig.add("M %s%s" % (m.name, m.desc))
    return frozenset(sig)


def check_set(obf, orig, deobf):
    cmd = [JAVA_BIN, "-cp", CP, "com.zkmdeobf.Main", obf, "-o", deobf]
    clog = os.path.join(CORPUS, "changelogs", os.path.basename(os.path.dirname(orig)) + ".txt")
    if os.path.exists(clog):
        cmd += ["--map", clog]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    verified = "verify: OK" in r.stdout
    skipped = ("str_skipped" in r.stdout) or ("int_unresolved" in r.stdout)

    mo = find_main(orig)
    md = find_main(deobf)
    run_ok = False
    if mo and md:
        rc_o, so = run_java(orig, mo)
        rc_d, sd = run_java(deobf, md)
        run_ok = (rc_o == 0 and rc_d == 0 and so == sd and len(so) > 0)

    co, cd = jar_classes(orig), jar_classes(deobf)
    sig_ok = set(co) == set(cd)
    if sig_ok:
        for k in co:
            if signature(co[k], k) != signature(cd[k], k):
                sig_ok = False
                break

    status = "OK" if (verified and run_ok and sig_ok and not skipped) else "FAIL"
    return mo or "?", verified, run_ok, sig_ok, skipped, status


def main():
    base = os.path.join(CORPUS, "jars")
    if not os.path.isdir(base):
        print("corpus/jars not found")
        return 1
    sets = sorted(d for d in os.listdir(base)
                  if os.path.isdir(os.path.join(base, d)))
    if not sets:
        print("corpus/jars is empty")
        return 1

    rows = []
    for s in sets:
        d = os.path.join(base, s)
        obf = os.path.join(d, "obf.jar")
        orig = os.path.join(d, "original.jar")
        deobf = os.path.join(d, "deobf.jar")
        if not (os.path.exists(obf) and os.path.exists(orig)):
            rows.append((s, "-", False, False, False, False, "MISSING"))
            continue
        rows.append((s,) + check_set(obf, orig, deobf))

    widths = [max(len(str(r[i])) for r in rows + [HEADER]) for i in range(len(HEADER))]
    print("  ".join(h.ljust(w) for h, w in zip(HEADER, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))

    bad = [r for r in rows if r[-1] != "OK"]
    print()
    print("PASSED: %d / %d" % (len(rows) - len(bad), len(rows)))
    for r in bad:
        print("  FAIL %s" % r[0])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
