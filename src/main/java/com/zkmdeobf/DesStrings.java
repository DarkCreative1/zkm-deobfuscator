package com.zkmdeobf;

public final class DesStrings {
    private DesStrings() {}

    public static String desInnerDecrypt(String encPiece, long key) {
        return Crypto.desStringDecrypt(encPiece, key);
    }

    public static String desInnerEncrypt(String plain, long key) {
        return Crypto.desStringEncrypt(plain, key);
    }

    public static long recoverLongStatic(int arg, long key, long mask, int xor, long[] enc) {
        if (enc == null) throw new IllegalArgumentException("enc==null");
        long l = (arg ^ (key & mask) ^ xor);
        if (l < 0 || l >= enc.length) throw new IllegalArgumentException("idx out of range: " + l);
        return enc[(int) l] ^ key;
    }

    public static int recoverIntStatic(int arg, long key, long mask, int xor, long[] enc) {
        if (enc == null) throw new IllegalArgumentException("enc==null");
        long l = (arg ^ (key & mask) ^ xor);
        if (l < 0 || l >= enc.length) throw new IllegalArgumentException("idx out of range: " + l);
        return (int) (enc[(int) l] ^ key);
    }
}
