from __future__ import annotations
import io
import json
import struct
import zipfile
from pathlib import Path

from .classfile import parse_class, ClassFile
from . import string_decryptor as SD
from . import const_decryptor as CD
from . import flow_simplifier as FL
from . import reference_resolver as RR
from . import param_restorer as PR
from . import lookup_recovery as LR
from . import int_recovery as IR
from . import rewrite as RW

def scan_jar(jar_path: str) -> dict:
    z = zipfile.ZipFile(jar_path)
    report: dict = {"input": jar_path, "classes": [], "summary": {}}
    counts: dict[str, int] = {}
    for name in z.namelist():
        if not name.endswith(".class"):
            continue
        try:
            cf = parse_class(z.read(name), name)
        except Exception as e:
            report["classes"].append({"name": name, "error": str(e)})
            continue
        entry: dict = {"name": name, "class": cf.this_class, "findings": []}

        def add(kind: str, where: str, detail: str, sev: str = "info"):
            entry["findings"].append({"kind": kind, "where": where, "detail": detail,
                                      "severity": sev})
            counts[kind] = counts.get(kind, 0) + 1

        for f in SD.detect_techniques(cf):
            add(f.technique, f.method, f.detail, "high" if "LOOKUP" in f.technique else "medium")
        dec = SD.try_decrypt_chunks(cf)
        if dec.get("xor_keys"):
            add("XOR_KEYS_RECOVERED", "<class>", f"xorKeys={dec['xor_keys']}", "high")

        lookup_plains: dict = {}
        try:
            lk = [mm for mm in cf.methods
                  if mm.desc in ("(II)Ljava/lang/String;", "(III)Ljava/lang/String;")]
            own = False
            for i in range(1, len(cf.cp)):
                e = cf.cp[i]
                if e and e.tag == 10:
                    cls, nt = e.value
                    n, d = cf.cp[nt].value
                    if cf.utf8(d) in ("(II)Ljava/lang/String;", "(III)Ljava/lang/String;") \
                            and cf.class_name(cls).replace(".", "/") == (cf.this_class or ""):
                        own = True
                        break
            if own and lk:
                r = LR.recover_class_strings(cf)
                if not r["plaintexts"]:
                    r = LR.recover_direct(cf)
                lookup_plains = r["plaintexts"]
                for where, pl in sorted(lookup_plains.items()):
                    add("LOOKUP_PLAINTEXT", where, f"[{pl}]", "high")
                if not lookup_plains:
                    add("LOOKUP_UNRESOLVED", "<class>", "; ".join(r["log"][-2:]), "medium")
        except Exception as ex:
            add("LOOKUP_ERROR", "<class>", str(ex)[:200], "low")
        if not lookup_plains:

            for ch in dec["chunks"][:5]:
                add("DECRYPTED_CHUNK", "<class>",
                    f"n={ch['n']} parts={ch['parts'][:4]}", "high")
        for f in CD.detect(cf):
            add(f.kind, f.method, f.detail, "high" if "LOOKUP" in f.kind else "medium")

        try:
            for m in cf.methods:
                if m.desc == "(IJ)I":
                    par = IR.extract_int_lookup_params_cf(cf, m.code)
                    if par:
                        add("INT_LOOKUP_PARAMS", f"{m.name}{m.desc}",
                            f"MASK={par[0]} INDEX_XOR={par[1]}", "high")
                        break
            sites = IR.extract_int_sites(cf)
            for where, a, k in sites[:24]:
                add("INT_LOOKUP_SITE", where, f"idx_arg={a} key={k}", "medium")
        except Exception:
            pass
        for f in FL.detect_all(cf):
            add(f.kind, f.where, f.detail, f.severity)
        for f in RR.detect(cf):
            add(f.kind, f.where, f.detail, "medium")
        for f in PR.detect_param_obfuscation(cf):
            add(f.kind, f.where, f.detail, "high")
        for kind, cur, sug in PR.suggest_names(cf):
            add("RENAME_SUGGESTION", f"{kind}:{cur}", f"oneri: {sug}", "low")
        report["classes"].append(entry)
    report["summary"] = {"class_count": len(report["classes"]), "finding_counts": counts}
    return report

def write_report(report: dict, path: str) -> None:
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

def deobfuscate_jar(input_path: str, output_path: str) -> dict:

    from . import deobfuscate as DE
    from . import dynrun
    zin = zipfile.ZipFile(input_path)
    names = zin.namelist()
    raws = {n: zin.read(n) for n in names}
    zin.close()

    stats = {"str_patched": 0, "str_skipped": [], "int_patched": 0,
             "int_unresolved": [], "handlers_removed": 0, "classes": 0}
    out_classes: dict[str, bytes] = {}

    for n in names:
        if not n.endswith(".class"):
            continue
        raw = raws[n]
        try:
            cf = parse_class(raw, n)
        except Exception:
            out_classes[n] = raw
            continue
        stats["classes"] += 1
        str_patches: list[tuple[str, str, int, int, str]] = []

        try:
            plains: dict[str, str] = {}
            r = LR.recover_class_strings(cf)
            if r["plaintexts"]:
                plains = r["plaintexts"]
            else:
                r2 = LR.recover_direct(cf)
                plains = r2["plaintexts"]
            if plains:

                for lk_desc in ("(II)Ljava/lang/String;", "(III)Ljava/lang/String;"):
                    for (w, mn, md, _a, _b, s, e) in LR.extract_lookup_site_ranges(cf, lk_desc):
                        if w in plains:
                            str_patches.append((mn, md, s, e, plains[w]))
        except Exception:
            pass

        cur = raw
        if str_patches:
            try:
                cur, rep = DE.patch_constants(cur, str_patches, [])
                stats["str_patched"] += rep["applied"]
                stats["str_skipped"].extend(rep["skipped"])
            except Exception as ex:
                stats["str_skipped"].append(f"{n}: {str(ex)[:120]}")

        try:
            fa_sites = SD.extract_fieldarray_sites(cf)
        except Exception:
            fa_sites = []
        try:
            str_fields = sorted({f.name for f in cf.fields
                                 if f.desc == "Ljava/lang/String;" and (f.access & 0x10)})
            sf_sites = SD.extract_stringfield_sites(cf)
        except Exception:
            str_fields, sf_sites = [], []
        tables, singles = {}, {}
        if fa_sites or sf_sites:
            fields = sorted({f for (_, _, _, _, f, _) in fa_sites})
            try:
                tables, singles = dynrun.dump_tables(
                    input_path, (cf.this_class or "").replace("/", "."),
                    fields + [f for f in str_fields if f not in fields])
            except Exception:
                tables, singles = {}, {}
            fa_patches = []
            for (mn, md, s, e, f, idx) in fa_sites:
                arr = tables.get(f, [])
                if idx < len(arr) and arr[idx] is not None:
                    fa_patches.append((mn, md, s, e, arr[idx]))
                else:
                    stats["str_skipped"].append(f"{n}::{mn}{md}@[{s},{e}): table absent")

            for (mn, md, s, e, f) in sf_sites:
                if f in singles and singles[f] is not None:
                    fa_patches.append((mn, md, s, e, singles[f]))
                else:
                    stats["str_skipped"].append(f"{n}::{mn}{md}@[{s},{e}): field absent")
            if fa_patches:
                try:
                    cur, rep = DE.patch_constants(cur, fa_patches, [])
                    stats["str_patched"] += rep["applied"]
                    stats["str_skipped"].extend(rep["skipped"])
                except Exception as ex:
                    stats["str_skipped"].append(f"{n}: {str(ex)[:120]}")

        int_ranges = []
        try:
            int_ranges = IR.extract_int_site_ranges(cf, "(IJ)I")
        except Exception:
            pass
        if int_ranges:
            dyn_vals: dict[int, object] = {}
            try:
                sites = [("I", a, k) for (_, _, _, a, k, _, _) in int_ranges]
                dyn_vals = dynrun.dump_ints(input_path,
                                            (cf.this_class or "").replace("/", "."),
                                            sites)
            except Exception:
                pass
            int_patches = []
            for i, (w, mn, md, a, k, s, e) in enumerate(int_ranges):
                if i in dyn_vals:
                    int_patches.append((mn, md, s, e, int(dyn_vals[i])))
                else:
                    stats["int_unresolved"].append(f"{n}::{w}")
            if int_patches:
                try:
                    cur, rep = DE.patch_constants(cur, [], int_patches)
                    stats["int_patched"] += rep["applied"]
                    stats["str_skipped"].extend(rep["skipped"])
                except Exception as ex:
                    stats["str_skipped"].append(f"{n}: {str(ex)[:120]}")

        try:
            cur, cnt = RW.strip_fake_handlers(cur)
            stats["handlers_removed"] += sum(cnt.values())
        except Exception:
            pass
        out_classes[n] = cur

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for n in names:
            zout.writestr(n, out_classes.get(n, raws[n]))
    vok, vlog = dynrun.verify_jar(output_path)
    return {"stats": stats, "verify": {"ok": vok, "log": vlog},
            "output": output_path}

def run(input_path: str, output: str | None = None, report_path: str = "report.json",
        scan_only: bool = False) -> dict:
    p = Path(input_path)
    if p.suffix == ".jar" or zipfile.is_zipfile(str(p)):
        report = scan_jar(str(p))
    else:
        cf = parse_class(p.read_bytes(), p.name)

        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".jar", delete=False) as t:
            tmp = t.name
        with zipfile.ZipFile(tmp, "w") as z:
            z.write(str(p), p.name)
        report = scan_jar(tmp)
        os.unlink(tmp)
    write_report(report, report_path)
    if output and not scan_only:

        try:
            deob = deobfuscate_jar(str(p), output)
            report["deobfuscate"] = deob["stats"]
            report["deobfuscate"]["verify_ok"] = deob["verify"]["ok"]
            report["deobfuscate"]["verify_log"] = deob["verify"]["log"][-600:]
        except Exception as ex:
            report["deobfuscate"] = {"error": str(ex)[:300]}
        write_report(report, report_path)
    return report

def print_summary(report: dict) -> None:
    print(f"class: {report['summary'].get('class_count')}")
    for k, v in sorted(report["summary"].get("finding_counts", {}).items(),
                       key=lambda x: -x[1])[:30]:
        print(f"  {k:28s} x{v}")
    n_err = sum(1 for c in report["classes"] if "error" in c)
    if n_err:
        print(f"  [uyari] {n_err} class okunamadi")
