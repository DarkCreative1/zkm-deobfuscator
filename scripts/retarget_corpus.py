import os
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = 61

CLASS_EXT = ".class"


def class_version(data):
    if len(data) < 8 or data[0:4] != b"\xca\xfe\xba\xbe":
        return None
    return struct.unpack(">H", data[6:8])[0]


def rewrite(data, target):
    major = class_version(data)
    if major is None or major <= target:
        return data, major
    patched = bytearray(data)
    patched[6:8] = struct.pack(">H", target)
    return bytes(patched), major


def process_jar(path, target):
    with zipfile.ZipFile(path, "r") as zin:
        names = zin.namelist()
        entries = [(i, zin.read(i.filename)) for i in zin.infolist()]

    changed = 0
    seen = set()
    out = []
    for info, data in entries:
        name = info.filename
        if name.endswith(CLASS_EXT):
            new_data, major = rewrite(data, target)
            seen.add(major)
            if new_data is not data and new_data != data:
                changed += 1
            data = new_data
        out.append((info, data))

    if changed == 0:
        return 0, sorted(v for v in seen if v is not None)

    tmp = path + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for info, data in out:
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = info.external_attr
            zout.writestr(zi, data)
    os.replace(tmp, path)
    return changed, sorted(v for v in seen if v is not None)


def iter_jars(roots):
    for r in roots:
        full = os.path.join(ROOT, r) if not os.path.isabs(r) else r
        if os.path.isfile(full):
            yield full
            continue
        for dirpath, _dirnames, filenames in os.walk(full):
            for f in sorted(filenames):
                if f.endswith(".jar"):
                    yield os.path.join(dirpath, f)


def main(argv):
    target = DEFAULT_TARGET
    args = []
    for a in argv:
        if a.startswith("--target="):
            target = int(a.split("=", 1)[1])
        else:
            args.append(a)

    roots = args or ["corpus/jars", "corpus/fixtures"]

    total_files = 0
    total_classes = 0
    for jar in iter_jars(roots):
        if not zipfile.is_zipfile(jar):
            continue
        changed, before = process_jar(jar, target)
        if changed:
            total_files += 1
            total_classes += changed
            print("%-44s %3d class  %s -> %d"
                  % (os.path.relpath(jar, ROOT).replace("\\", "/"),
                     changed, before, target))
    print("retargeted %d class in %d jar (target major %d)"
          % (total_classes, total_files, target))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
