import sys
sys.path.insert(0, ".")
from zkm_deobfuscator import crypto as C

def test_xor():
    keys = [11, 22, 33, 44, 55, 66, 77]
    s = "Hello ZKM World! merhaba 123"
    assert C.xor_with_keys(C.xor_with_keys(s, keys), keys) == s
    print("xor ok")

def test_rolling_both():
    for bl in (True, False):
        keys = [0x12, 0xAB]
        s = "RollingXor-Test-42"
        enc = C.rolling_xor_encrypt(s, keys, bl)
        dec = C.rolling_xor_decrypt_orig_variant(enc, keys) if bl else C.rolling_xor_decrypt(enc, keys)
        assert dec == s, (bl, repr(dec))
    print("rolling ok")

def test_des_string():
    key = 0x0123456789ABCDEF
    for s in ["hello", "ZKM-string-şifreleme", "a" * 30, ""]:
        if not s:
            continue
        enc = C.des_string_encrypt(s, key)
        dec = C.des_string_decrypt(enc, key)
        assert dec == s, (s, repr(dec))
    print("des-string ok")

def test_des_long():
    k = 0x1122334455667788
    for v in [0, 1, 42, 0xDEADBEEFCAFEBABE, 0xFFFFFFFFFFFFFFFF]:
        enc = C.des_long_crypt(v, k, False)
        assert C.des_long_crypt(enc, k, True) == (v & 0xFFFFFFFFFFFFFFFF)
    print("des-long ok")

def test_split_backtrack():

    e0, e1, e2 = "ABCDE", "XY", "WXYZ"
    chunk = e0 + chr(len(e1)) + e1 + chr(len(e2)) + e2
    parts = C.decrypt_chunk_table(chunk, 3)
    assert parts == [e0, e1, e2], parts
    print("split ok")

def test_modified_utf8():
    s = "AB\x00CDé"
    assert C.java_modified_utf8_decode(C.java_modified_utf8_encode(s)) == s
    print("mutf8 ok")

if __name__ == "__main__":
    test_xor()
    test_rolling_both()
    test_des_string()
    test_des_long()
    test_split_backtrack()
    test_modified_utf8()
    print("TUM KRIPTO TESTLERI GECTI")
