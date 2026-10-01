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
        int idx = (int) (arg ^ (key & mask) ^ xor);
        return enc[idx] ^ key;
    }

    public static int recoverIntStatic(int arg, long key, long mask, int xor, long[] enc) {
        int idx = (int) (arg ^ (key & mask) ^ xor);
        return (int) (enc[idx] ^ key);
    }
}
