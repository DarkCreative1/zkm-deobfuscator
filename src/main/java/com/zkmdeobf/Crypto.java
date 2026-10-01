package com.zkmdeobf;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class Crypto {
    private Crypto() {}

    public static String xorWithKeys(String s, int[] keys) {
        char[] c = s.toCharArray();
        for (int i = 0; i < c.length; i++) c[i] = (char) (c[i] ^ keys[i % keys.length]);
        return new String(c);
    }

    public static int[] deriveXorKeys(int[] xorKeys, int chunkKey) {
        int[] o = new int[xorKeys.length];
        for (int i = 0; i < o.length; i++) o[i] = xorKeys[i] ^ chunkKey;
        return o;
    }

    public static String rollingXorEncrypt(String s, int[] keys, boolean useOrig) {
        int[] bb = keys.clone();
        char[] bd = s.toCharArray();
        for (int i = 0; i < bd.length; i++) {
            int bg = i % bb.length;
            char bh = bd[i];
            bd[i] = (char) (bd[i] ^ bb[bg]);
            int bi = (bb[bg] >>> 3) | (bb[bg] << 5);
            bi ^= useOrig ? bh : bd[i];
            bb[bg] = bi & 255;
        }
        return new String(bd);
    }

    public static String rollingXorDecrypt(String s, int[] keys) {
        int[] bb = keys.clone();
        char[] bd = s.toCharArray();
        for (int i = 0; i < bd.length; i++) {
            int bg = i % bb.length;
            char e = bd[i];
            bd[i] = (char) (e ^ bb[bg]);
            int bi = (bb[bg] >>> 3) | (bb[bg] << 5);
            bi ^= e;
            bb[bg] = bi & 255;
        }
        return new String(bd);
    }

    public static String rollingXorDecryptOrig(String s, int[] keys) {
        int[] bb = keys.clone();
        char[] bd = s.toCharArray();
        for (int i = 0; i < bd.length; i++) {
            int bg = i % bb.length;
            char e = bd[i];
            char plain = (char) (e ^ bb[bg]);
            bd[i] = plain;
            int bi = (bb[bg] >>> 3) | (bb[bg] << 5);
            bi ^= plain;
            bb[bg] = bi & 255;
        }
        return new String(bd);
    }

    public static byte[] longToBytes(long v) {
        return new byte[]{(byte) (v >>> 56), (byte) (v >>> 48), (byte) (v >>> 40),
                (byte) (v >>> 32), (byte) (v >>> 24), (byte) (v >>> 16),
                (byte) (v >>> 8), (byte) v};
    }

    public static long bytesToLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[i] & 0xFF);
        return v;
    }

    private static byte[] desCbc(byte[] data, byte[] key8, boolean decrypt, boolean pad) throws Exception {

        Cipher ch = Cipher.getInstance("DES/CBC/" + (pad ? "PKCS5Padding" : "NoPadding"));
        SecretKeyFactory f = SecretKeyFactory.getInstance("DES");
        ch.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE,
                f.generateSecret(new DESKeySpec(key8)), new IvParameterSpec(new byte[8]));
        byte[] out = ch.doFinal(data);
        if (decrypt && pad && out.length > 0) {
            int p = out[out.length - 1] & 0xFF;
            if (p >= 1 && p <= 8) {
                boolean ok = true;
                for (int i = out.length - p; i < out.length; i++) if ((out[i] & 0xFF) != p) ok = false;
                if (ok) { byte[] t = new byte[out.length - p]; System.arraycopy(out, 0, t, 0, t.length); out = t; }
            }
        }
        return out;
    }

    public static String desStringEncrypt(String plain, long key) {
        try {
            byte[] raw = mutf8Encode(plain);
            return new String(desCbc(raw, longToBytes(key), false, true), StandardCharsets.ISO_8859_1);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    public static String desStringDecrypt(String enc, long key) {
        try {
            byte[] raw = enc.getBytes(StandardCharsets.ISO_8859_1);
            return mutf8Decode(desCbc(raw, longToBytes(key), true, true));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    public static long desLongCrypt(long value, long key, boolean decrypt) {
        try {
            return bytesToLong(desCbc(longToBytes(value), longToBytes(key), decrypt, false));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    public static byte[] mutf8Encode(String s) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c == 0) { o.write(0xC0); o.write(0x80); }
            else if (c < 0x80) o.write(c);
            else if (c < 0x800) { o.write(0xC0 | (c >> 6)); o.write(0x80 | (c & 0x3F)); }
            else { o.write(0xE0 | (c >> 12)); o.write(0x80 | ((c >> 6) & 0x3F)); o.write(0x80 | (c & 0x3F)); }
        }
        return o.toByteArray();
    }

    public static String mutf8Decode(byte[] b) {
        StringBuilder o = new StringBuilder();
        int i = 0;
        while (i < b.length) {
            int a = b[i] & 0xFF;
            if (a < 0x80) { if (a == 0) break; o.append((char) a); i++; }
            else if ((a & 0xE0) == 0xC0) { o.append((char) (((a & 0x1F) << 6) | (b[i + 1] & 0x3F))); i += 2; }
            else { o.append((char) (((a & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F))); i += 3; }
        }
        return o.toString();
    }

    public static List<List<String>> allSplits(String chunk, int n, int cap) {
        List<List<String>> out = new ArrayList<>();
        if (n <= 1) { List<String> one = new ArrayList<>(); one.add(chunk); out.add(one); return out; }
        rec(chunk, chunk.length(), n - 1, new ArrayList<>(), out, cap);
        return out;
    }

    private static void rec(String chunk, int pos, int idx, List<String> acc,
                            List<List<String>> out, int cap) {
        if (out.size() >= cap) return;
        if (idx == 0) {
            List<String> sol = new ArrayList<>(acc);
            sol.add(chunk.substring(0, pos));
            java.util.Collections.reverse(sol);
            out.add(sol);
            return;
        }
        for (int L = 0; L < pos; L++) {
            if (chunk.charAt(pos - L - 1) == L) {
                acc.add(chunk.substring(pos - L, pos));
                rec(chunk, pos - L - 1, idx - 1, acc, out, cap);
                acc.remove(acc.size() - 1);
            }
        }
    }

    public static double scorePrint(String s) {
        if (s.isEmpty()) return 0.5;
        int ok = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isISOControl(c) || c == '\n' || c == '\t' || c == '\r') ok++;
        }
        return (double) ok / s.length();
    }

    public static double scoreAscii(String s) {
        if (s.isEmpty()) return 0.0;
        int ok = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 32 && c < 127) || c == '\n' || c == '\t') ok++;
        }
        return (double) ok / s.length();
    }
}
