import sys
sys.path.insert(0, ".")
import struct
import zipfile
from zkm_deobfuscator.classfile import parse_class
from zkm_deobfuscator import int_recovery as IR

z = zipfile.ZipFile("corpus/fixtures/demo2-obf.jar")
cf = parse_class(z.read("a/a/b.class"), "a/a/b.class")

lookup = next(m for m in cf.methods if m.desc == "(IJ)I")
params = IR.extract_int_lookup_params_cf(cf, lookup.code)
print("params (MASK, IDX_XOR):", params)
assert params == (32767, 0x4256), params

sites = IR.extract_int_sites(cf)
print("sites:", sites)
assert len(sites) == 5

ENC = [-1535701415273817048, -4053523173738095047, -5187989390702372588,
       -3379558863154558104, -3453772378396368469]
mask, ix = params
results = sorted(IR.recover_int_xor(a, k, mask, ix, ENC) for _, a, k in sites)
print("recovered:", results)
assert results == [60, 70, 80, 87, 90], results
print("STATIK INT KURTARMA test GECTI")
