package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class LookupRecovery {
    private LookupRecovery() {}

    public record LookupParams(int indexXor, int[] shuffle) {}

    public static LookupParams params(MethodNode lookup) {
        if (lookup == null) return null;
        List<AbstractInsnNode> ins = ClassIO.list(lookup);
        List<AbstractInsnNode> real = new ArrayList<>();
        for (AbstractInsnNode n : ins) {
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            if (n.getOpcode() == Opcodes.NOP) continue;
            real.add(n);
        }
        Integer indexXor = null;
        for (int k = 0; k + 4 < real.size(); k++) {
            int o0 = real.get(k).getOpcode();
            AbstractInsnNode n1 = real.get(k + 1);
            if (o0 == Opcodes.ILOAD
                    && real.get(k + 2).getOpcode() == Opcodes.IXOR
                    && real.get(k + 4).getOpcode() == Opcodes.IAND) {
                indexXor = ClassIO.constInt(n1);
                if (indexXor != null) break;
            }
        }
        int[] shuffle = null;
        for (AbstractInsnNode n : ins) {
            if (n.getOpcode() != Opcodes.TABLESWITCH) continue;
            TableSwitchInsnNode t = (TableSwitchInsnNode) n;
            long span = (long) t.max - (long) t.min + 1;
            if (span < 200 || span > 4096) continue;
            List<LabelNode> order = new ArrayList<>(t.labels);
            order.add(t.dflt);
            List<Integer> vals = new ArrayList<>();
            boolean ok = true;
            for (LabelNode lab : order) {
                AbstractInsnNode cur = lab.getNext();
                while (cur != null && (cur instanceof LabelNode || cur instanceof LineNumberNode || cur instanceof FrameNode))
                    cur = cur.getNext();
                Integer v = cur == null ? null : ClassIO.constInt(cur);
                if (v == null || v < 0 || v > 255) { ok = false; break; }
                vals.add(v & 0xFF);
            }
            if (ok && vals.size() >= 256) {
                // Must be a permutation of 0..255; otherwise it is not a shuffle table.
                boolean[] seen = new boolean[256];
                boolean perm = true;
                for (int i = 0; i < 256; i++) {
                    int v = vals.get(i);
                    if (seen[v]) { perm = false; break; }
                    seen[v] = true;
                }
                if (!perm) continue;
                shuffle = new int[256];
                for (int i = 0; i < 256; i++) shuffle[i] = vals.get(i);
                break;
            }
        }
        if (indexXor == null || shuffle == null) return null;
        return new LookupParams(indexXor & 0xFFFF, shuffle);
    }

    public static String innerDecrypt(String enc, int key, int[] shuffle) {
        if (enc == null || enc.isEmpty() || shuffle == null || shuffle.length < 256) return "";
        int ku = key & 0xFFFF;
        int k0 = ku & 255, k1 = (ku >> 8) & 255;
        int off = shuffle[enc.charAt(0) & 255];
        int[] bb = {(k0 - off) & 255, (k1 - off) & 255};
        char[] bd = enc.toCharArray();
        StringBuilder o = new StringBuilder(bd.length);
        for (int i = 0; i < bd.length; i++) {
            int g = i % 2;
            int e = bd[i];
            char pl = (char) (e ^ bb[g]);
            o.append(pl);
            bb[g] = (((bb[g] >>> 3) | (bb[g] << 5)) ^ pl) & 255;
        }
        return o.toString();
    }

    public static List<int[]> validIntervals(String ch, int maxPiece) {
        List<int[]> o = new ArrayList<>();
        int L = ch.length();
        for (int e = 1; e <= Math.min(L, maxPiece); e++) o.add(new int[]{0, e});
        for (int s = 1; s < L; s++) {
            int want = ch.charAt(s - 1);
            if (want >= 1 && want <= maxPiece && s + want <= L) o.add(new int[]{s, s + want});
        }
        return o;
    }

    public record Found(StringDecryptor.LookupSite site, String plain, String detail) {
        public String where() { return site.mName() + site.mDesc(); }
    }

    public static List<Found> recoverLayout(ClassNode cn) {
        List<Found> o = new ArrayList<>();
        MethodNode clinit = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (clinit == null) return o;
        int[] keys = StringDecryptor.extractXorKeys(clinit);
        if (keys == null) return o;
        List<String> chunks = StringDecryptor.clinitChunks(cn, clinit);
        List<Integer> sizes = StringDecryptor.tableSizes(clinit);
        MethodNode lk = null;
        for (MethodNode m : cn.methods)
            if (m.desc.equals("(II)Ljava/lang/String;") || m.desc.equals("(III)Ljava/lang/String;")) { lk = m; break; }
        if (lk == null) return o;
        LookupParams p = params(lk);
        if (p == null) return o;
        List<StringDecryptor.LookupSite> sites = new ArrayList<>();
        for (MethodNode m : cn.methods) sites.addAll(StringDecryptor.lookupSites(cn, m, lk.desc));
        if (sites.isEmpty()) return o;
        int total = sizes.isEmpty() ? sites.size() : sizes.get(0);

        List<List<List<String>>> cand = new ArrayList<>();
        for (String c : chunks) {
            List<List<String>> perN = new ArrayList<>();
            for (int n = 1; n <= Math.min(c.length(), 12); n++) {
                for (List<String> sp : Crypto.allSplits(c, n, 60)) {
                    if (sp.size() == n) {
                        List<String> dec = new ArrayList<>();
                        for (String q : sp) dec.add(Crypto.xorWithKeys(q, keys));
                        perN.add(dec);
                        break;
                    }
                }
            }
            cand.add(perN);
        }
        if (tooBig(cand, 12)) return o;
        double[] best = {-1};
        List<Found> bestF = new ArrayList<>();
        List<Integer> bestL = new ArrayList<>();
        int[] combo = new int[cand.size()];
        searchLayout(cand, 0, combo, total, sites, p, keys, best, bestF, bestL);
        if (bestF.isEmpty()) return bestF;

        double asc = 0;
        for (Found f : bestF) asc += Crypto.scoreAscii(f.plain());
        asc /= bestF.size();
        if (asc < 0.85) return new ArrayList<>();
        return bestF;
    }

    private static void searchLayout(List<List<List<String>>> cand, int d, int[] combo, int total,
                                     List<StringDecryptor.LookupSite> sites, LookupParams p,
                                     int[] keys, double[] best, List<Found> bestF, List<Integer> bestL) {
        if (d == cand.size()) {
            List<String> flat = new ArrayList<>();
            for (int i = 0; i < cand.size(); i++) flat.addAll(cand.get(i).get(combo[i]));
            if (flat.size() != total) return;
            double asc = 0, sc = 0;
            List<Found> cur = new ArrayList<>();
            for (StringDecryptor.LookupSite s : sites) {
                int pos = (s.encIdx() ^ p.indexXor()) & 0xFFFF;
                if (pos >= flat.size()) return;
                String pl;
                try { pl = innerDecrypt(flat.get(pos), s.key(), p.shuffle()); }
                catch (Exception e) { return; }
                cur.add(new Found(s, pl, ""));
                asc += Crypto.scoreAscii(pl);
                sc += Crypto.scorePrint(pl);
            }
            asc /= sites.size();
            sc /= sites.size();
            double key = asc + sc * 1e-4;
            if (key > best[0]) {
                best[0] = key;
                bestF.clear();
                bestF.addAll(cur);
                bestL.clear();
                for (int i = 0; i < cand.size(); i++) bestL.add(cand.get(i).get(combo[i]).size());
            }
            return;
        }
        for (int i = 0; i < cand.get(d).size() && i < 12; i++) {
            combo[d] = i;
            searchLayout(cand, d + 1, combo, total, sites, p, keys, best, bestF, bestL);
        }
    }

    public static List<Found> recoverDirect(ClassNode cn) {
        List<Found> o = new ArrayList<>();
        MethodNode clinit = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (clinit == null) return o;
        int[] keys = StringDecryptor.extractXorKeys(clinit);
        if (keys == null) return o;
        List<String> chunksAll = StringDecryptor.clinitChunks(cn, clinit);
        List<String> chunks = new ArrayList<>();
        for (String c : chunksAll) if (c.length() >= 4) chunks.add(c);
        MethodNode lk = null;
        for (MethodNode m : cn.methods)
            if (m.desc.equals("(II)Ljava/lang/String;") || m.desc.equals("(III)Ljava/lang/String;")) { lk = m; break; }
        if (lk == null) return o;
        LookupParams p = params(lk);
        if (p == null) return o;
        List<StringDecryptor.LookupSite> sites = new ArrayList<>();
        for (MethodNode m : cn.methods) sites.addAll(StringDecryptor.lookupSites(cn, m, lk.desc));

        Map<StringDecryptor.LookupSite, List<Cand>> perSite = new LinkedHashMap<>();
        for (StringDecryptor.LookupSite s : sites) {
            List<Cand> cands = new ArrayList<>();
            for (int ci = 0; ci < chunks.size(); ci++) {
                String ch = chunks.get(ci);
                // Cap per-chunk work: interval enumeration is O(L^2) and each
                // candidate runs a decrypt+score. Huge chunks would stall the
                // whole class on a single call site.
                if (ch.length() > 512) continue;
                for (int[] iv : validIntervals(ch, ch.length())) {
                    String piece = ch.substring(iv[0], iv[1]);
                    String pl;
                    try {
                        pl = innerDecrypt(Crypto.xorWithKeys(piece, keys), s.key(), p.shuffle());
                    } catch (Exception e) { continue; }
                    double asc = Crypto.scoreAscii(pl);
                    if (asc < 0.9) continue;
                    double sc = Crypto.scorePrint(pl);
                    cands.add(new Cand(asc, sc, pl.length(), ci, iv[0], iv[1], pl));
                }
            }
            cands.sort((a, b) -> {
                int c = Double.compare(b.asc, a.asc);
                if (c != 0) return c;
                c = Double.compare(b.sc, a.sc);
                if (c != 0) return c;
                return Integer.compare(b.len, a.len);
            });
            List<Cand> uniq = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (Cand c : cands) {
                String k = c.ci + ":" + c.s + ":" + c.e;
                if (seen.add(k)) uniq.add(c);
                if (uniq.size() >= 6) break;
            }
            String where = s.mName() + s.mDesc() + "#?";
            perSite.put(s, uniq);
        }

        List<StringDecryptor.LookupSite> order = new ArrayList<>(perSite.keySet());
        order.sort((a, b) -> {
            List<Cand> la = perSite.get(a), lb = perSite.get(b);
            double sa = la.isEmpty() ? -1 : la.get(0).asc, sb = lb.isEmpty() ? -1 : lb.get(0).asc;
            return Double.compare(sb, sa);
        });
        List<int[]> taken = new ArrayList<>();
        for (StringDecryptor.LookupSite w : order) {
            for (Cand c : perSite.get(w)) {
                boolean clash = false;
                for (int[] t : taken) {
                    // Same chunk+same span shared by two call sites is legal reuse.
                    if (t[0] == c.ci && t[1] == c.s && t[2] == c.e) continue;
                    if (t[0] == c.ci && !(c.e <= t[1] || c.s >= t[2])) { clash = true; break; }
                }
                if (!clash) {
                    taken.add(new int[]{c.ci, c.s, c.e});
                    o.add(new Found(w, c.pl, "chunk" + c.ci + "[" + c.s + ":" + c.e + "]"));
                    break;
                }
            }
        }
        return o;
    }

    private record Cand(double asc, double sc, int len, int ci, int s, int e, String pl) {}

    static boolean tooBig(List<List<List<String>>> cand, int perChunkCap) {
        long prod = 1;
        for (List<List<String>> perN : cand) {
            long sz = Math.max(Math.min(perN.size(), perChunkCap), 1);
            if (prod > 250000 / sz) return true;
            prod *= sz;
            if (prod > 250000) return true;
        }
        return false;
    }
}
