from __future__ import annotations
import argparse
from .pipeline import run, print_summary

def main() -> None:
    ap = argparse.ArgumentParser(description="ZKM deobfuscator — tara + deobfuscate JAR uret")
    ap.add_argument("input", help=".jar veya .class dosyasi")
    ap.add_argument("-o", "--output", default=None, help="deobfuscated output jar")
    ap.add_argument("--report", default="report.json")
    ap.add_argument("--scan-only", action="store_true", help="only tara, jar yazma")
    a = ap.parse_args()
    rep = run(a.input, a.output, a.report, a.scan_only)
    print_summary(rep)
    d = rep.get("deobfuscate")
    if d:
        print("deobfuscate:", {k: (v if not isinstance(v, list) else f"{len(v)} adet")
                               for k, v in d.items() if k != "verify_log"})
    print(f"rapor: {a.report}")
    if a.output and not a.scan_only:
        print(f"output: {a.output}")

if __name__ == "__main__":
    main()
