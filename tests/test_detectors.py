import sys, struct
sys.path.insert(0, ".")
from zkm_deobfuscator.classfile import parse_class
from zkm_deobfuscator import string_decryptor as SD, flow_simplifier as FL
from zkm_deobfuscator import const_decryptor as CD, reference_resolver as RR

SRC = r"""
public class SynthZkm {
  static int opaque;
  static String[] table;
  static { opaque = 1; table = new String[]{"enc"}; }
  static String lookup(int i, int k) { return table[(i ^ 0x1234) & 0xFFFF]; }
  public static int demo(int x) {
    int r = 0;
    switch (x % 7) { case 0: r=11; break; case 1: r=22; break; case 2: r=33; break;
      case 3: r=44; break; case 4: r=55; break; case 5: r=66; break; default: r=77; }
    if (opaque != 0) { r += 1; } else { r += 2; }
    try { r += x; } catch (RuntimeException e) { throw e; }
    return r + lookup(0, 0).length();
  }
}
"""

def build():
    import subprocess, pathlib, tempfile, os
    d = tempfile.mkdtemp()
    p = os.path.join(d, "SynthZkm.java")
    open(p, "w").write(SRC)
    subprocess.check_call(["javac", "-d", d, p])
    return open(os.path.join(d, "SynthZkm.class"), "rb").read()

raw = build()
cf = parse_class(raw, "SynthZkm.class")
s = SD.detect_techniques(cf)
f = FL.detect_all(cf)
c = CD.detect(cf)
print("string:", [(x.technique, x.method) for x in s])
print("flow:", [(x.kind, x.where) for x in f])
print("const:", [(x.kind, x.method) for x in c])
assert any(x.technique == "XOR_OUTER_LOOP" for x in s), "7-case tableswitch yakalanmali"
assert any(x.kind in ("OPAQUE_PREDICATE_FIELD", "FAKE_HANDLER?") or "OPAQUE" in x.kind or "HANDLER" in x.kind for x in f), f"flow izi beklenir: {f}"
print("SENTETIK TEST GECTI")
