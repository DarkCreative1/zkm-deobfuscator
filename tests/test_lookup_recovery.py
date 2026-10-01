import sys, io
sys.path.insert(0, ".")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import zipfile
from zkm_deobfuscator.classfile import parse_class
from zkm_deobfuscator import lookup_recovery as LR

EXPECT_MAIN = {
    "ZKM-E2E", "calc=", "foo", "bar", "cat=",
}
EXPECT_WORKER = {
    "magic=", "big=", "grade=", "ex=", "-mid-", "empty-tag", "hello-",
    "-secret-sauce", "A-excellent", "B-good", "C-average", "D-poor",
    "F-fail", "negative-input", "ok-", "caught-",
}

EXPECT_SITES = {
    "main([Ljava/lang/String;)V@9": "ZKM-E2E",
    "a(Ljava/lang/String;)Ljava/lang/String;@29": "magic=",
    "b(I)Ljava/lang/String;@14": "negative-input",
    "b(I)Ljava/lang/String;@35": "ok-",
    "a(I)Ljava/lang/String;@12": "A-excellent",
}

def run() -> None:
    z = zipfile.ZipFile("corpus/fixtures/demo3B-obf.jar")
    cf_m = parse_class(z.read("a/a/a.class"), "a/a/a.class")
    cf_w = parse_class(z.read("a/a/b.class"), "a/a/b.class")

    rm = LR.recover_class_strings(cf_m)
    got_m = set(rm["plaintexts"].values())
    print("MAIN:", sorted(got_m))
    assert got_m == EXPECT_MAIN, f"MAIN fark: {got_m ^ EXPECT_MAIN}"

    rw = LR.recover_direct(cf_w)
    got_w = set(rw["plaintexts"].values())
    print("WORKER:", sorted(got_w))
    assert got_w == EXPECT_WORKER, f"WORKER fark: {got_w ^ EXPECT_WORKER}"

    allp = dict(rm["plaintexts"])
    allp.update(rw["plaintexts"])
    for site, want in EXPECT_SITES.items():
        assert allp.get(site) == want, f"{site}: {allp.get(site)!r} != {want!r}"
    print("LOOKUP KURTARMA test GECTI (5/5 + 16/16)")

if __name__ == "__main__":
    run()
