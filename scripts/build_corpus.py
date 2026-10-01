#!/usr/bin/env python3
"""Rebuilds the whole corpus with a given ZKM installation.

Usage:
    python scripts/build_corpus.py --zkm <zkm.jar> --tag zkm13
    python scripts/build_corpus.py --zkm <zkm.jar> --tag zkm27 --extra encryptIntegerConstants=aggressive

Produces corpus/jars/<demo>-<tag>/{original,obf,deobf}.jar
and corpus/changelogs/<demo>-<tag>.txt
"""
import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")

def _tool(name, fallback):
    java = os.environ.get("JAVA_HOME")
    if not java:
        return fallback
    exe = name + ".exe" if os.name == "nt" else ""
    p = os.path.join(java, "bin", name + exe)
    return p if os.path.isfile(p) else fallback


JAVAC = _tool("javac", "javac")
JAR = _tool("jar", "jar")
JAVA_BIN = _tool("java", "java")

DEMOS = ["demo1", "demo2", "demo3"]

DEFAULT_OPTS = [
    "obfuscateFlow=aggressive",
    "encryptStringLiterals=enhanced",
    "exceptionObfuscation=heavy",
    "obfuscateReferences=normal",
]

ZKM27_EXTRA = [
    "encryptIntegerConstants=aggressive",
    "encryptLongConstants=normal",
    "obfuscateParameters=normal",
    "obfuscateReferenceStructures=inSpecialClass",
]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        sys.stderr.write((r.stdout or "") + (r.stderr or ""))
    return r.returncode == 0


def compile_demo(name):
    src = os.path.join(CORPUS, "src", name)
    out = os.path.join(ROOT, "build", "corpus-build", name)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    files = []
    for dp, _, fns in os.walk(src):
        files += [os.path.join(dp, f) for f in fns if f.endswith(".java")]
    if not files:
        return None
    if not run([JAVAC, "-nowarn", "-d", out] + files):
        return None
    jar = os.path.join(ROOT, "build", "corpus-build", name + ".jar")
    if not run([JAR, "cf", jar, "-C", out, "."]):
        return None
    return jar


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zkm", required=True, help="path to ZKM.jar")
    ap.add_argument("--tag", required=True, help="version tag, e.g. zkm27")
    ap.add_argument("--extra", action="append", default=[],
                    help="additional ZKM obfuscate options")
    args = ap.parse_args()

    opts = list(DEFAULT_OPTS) + list(args.extra)
    for demo in DEMOS:
        orig = compile_demo(demo)
        if not orig:
            print("%s: compile failed, skipped" % demo)
            continue
        outdir = os.path.join(CORPUS, "jars", "%s-%s" % (demo, args.tag))
        os.makedirs(outdir, exist_ok=True)
        original = os.path.join(outdir, "original.jar")
        obf = os.path.join(outdir, "obf.jar")
        clog = os.path.join(CORPUS, "changelogs", "%s-%s.txt" % (demo, args.tag))
        os.makedirs(os.path.dirname(clog), exist_ok=True)
        for p in (obf, clog):
            if os.path.exists(p):
                os.remove(p)
        shutil.copyfile(orig, original)

        body = "\n          ".join(opts)
        script = (
            'open "%s";\n'
            'obfuscate changeLogFileOut="%s"\n          %s;\n'
            'saveAll archiveCompression=all "%s";\n' % (original, clog, body, obf))
        zkm_script = os.path.join(ROOT, "build", "corpus-build", "%s.zkm" % demo)
        os.makedirs(os.path.dirname(zkm_script), exist_ok=True)
        with open(zkm_script, "w") as f:
            f.write(script)

        ok = run([JAVA_BIN, "-jar", args.zkm, zkm_script])
        if ok and os.path.exists(obf):
            n = sum(1 for n in subprocess.run([JAR, "tf", obf],
                                              capture_output=True, text=True).stdout.splitlines()
                    if n.endswith(".class"))
            print("%-7s OK  obf=%d bayt  class=%d" % (demo, os.path.getsize(obf), n))
        else:
            print("%-7s FAIL (zkm output uretmedi)" % demo)


if __name__ == "__main__":
    main()
