import sys, io, subprocess, zipfile, shutil
sys.path.insert(0, ".")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from zkm_deobfuscator.pipeline import deobfuscate_jar
from zkm_deobfuscator.classfile import parse_class

EXPECTED_OUT = ("hello-ZKM-E2E-secret-sauce|magic=305419896|big=1234605616436508552|"
                "grade=B-good|ex=ok-100")
EXPECTED_DEMO2 = "hello-ZKM-E2E-secret-sauce|B-good"

JAVA = shutil.which("java")
JAVAP = shutil.which("javap")
assert JAVA, "java bulunamadi; JDK kurulu olmali"

def run_jar(jar, main):
    r = subprocess.run([JAVA, "-cp", jar, main], capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-500:]
    return r.stdout.strip().replace("\r", "")

def javap_strings(jar, cls):
    assert JAVAP, "javap bulunamadi; JDK kurulu olmali"
    r = subprocess.run([JAVAP, "-c", "-p", "-cp", jar, cls], capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0
    return r.stdout

def test_demo2():
    print("== demo2 (string XOR + int) ==")
    d = deobfuscate_jar("corpus/fixtures/demo2-obf.jar", "build/test-tmp/_t2.jar")
    s = d["stats"]
    print(s)
    assert s["str_patched"] == 9, s
    assert s["int_patched"] == 5, s
    assert not s["str_skipped"] and not s["int_unresolved"], s
    assert d["verify"]["ok"], d["verify"]
    assert run_jar("build/test-tmp/_t2.jar", "a.a.a").startswith(EXPECTED_DEMO2)
    dump = javap_strings("build/test-tmp/_t2.jar", "a.a.b") + javap_strings("build/test-tmp/_t2.jar", "a.a.a")
    for want in ["ZKM-E2E", "empty-tag", "hello-", "-secret-sauce", "A-excellent",
                 "B-good", "C-average", "D-poor", "F-fail",
                 "int 90", "int 80", "int 70", "int 60"]:
        assert want in dump, f"not found: {want}"
    print("demo2 OK")

def test_demo3b():
    print("== demo3B (LOOKUP rolling) ==")
    d = deobfuscate_jar("corpus/fixtures/demo3B-obf.jar", "build/test-tmp/_t3b.jar")
    s = d["stats"]
    print(s)
    assert s["str_patched"] == 21, s
    assert d["verify"]["ok"], d["verify"]
    assert run_jar("build/test-tmp/_t3b.jar", "a.a.a").startswith(EXPECTED_OUT)
    dump = javap_strings("build/test-tmp/_t3b.jar", "a.a.b")
    for want in ["magic=", "empty-tag", "negative-input", "caught-", "-mid-"]:
        assert want in dump, f"not found: {want}"
    print("demo3B OK")

def test_demo3e():
    print("== demo3E (fake handler) ==")
    d = deobfuscate_jar("corpus/fixtures/demo3E-obf.jar", "build/test-tmp/_t3e.jar")
    s = d["stats"]
    print(s)
    assert s["handlers_removed"] == 8, s
    assert d["verify"]["ok"], d["verify"]
    assert run_jar("build/test-tmp/_t3e.jar", "a.a.a").startswith(EXPECTED_OUT)

    cf = parse_class(zipfile.ZipFile("build/test-tmp/_t3e.jar").read("a/a/b.class"), "x")
    assert sum(len(m.exception_table) for m in cf.methods) == 1
    print("demo3E OK")

if __name__ == "__main__":
    test_demo2()
    test_demo3b()
    test_demo3e()
    print("E2E JAR TESTLERI GECTI")
