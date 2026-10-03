package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class StringDecryptor {
    private StringDecryptor() {}

    public static int[] extractXorKeys(MethodNode clinit) {
        List<AbstractInsnNode> ins = ClassIO.list(clinit);
        for (int k = 0; k < ins.size(); k++) {
            AbstractInsnNode n = ins.get(k);
            if (n.getOpcode() != Opcodes.TABLESWITCH) continue;
            TableSwitchInsnNode t = (TableSwitchInsnNode) n;
            int span = t.max - t.min + 1;
            if (span != 7 && !(t.min == 0 && t.max == 5)) continue;
            List<Integer> keys = new ArrayList<>();
            List<LabelNode> order = new ArrayList<>(t.labels);
            order.add(t.dflt);
            for (LabelNode lab : order) {
                AbstractInsnNode cur = nextReal(clinit, lab);
                Integer v = cur == null ? null : ClassIO.constInt(cur);
                if (v == null || v < 0 || v > 255) break;
                keys.add(v);
                if (keys.size() == 7) {
                    int[] o = new int[7];
                    for (int i = 0; i < 7; i++) o[i] = keys.get(i);
                    return o;
                }
            }
        }
        return null;
    }

    private static AbstractInsnNode nextReal(MethodNode m, AbstractInsnNode from) {
        AbstractInsnNode n = from.getNext();
        while (n != null && (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode)) n = n.getNext();
        return n;
    }

    public static List<String> clinitChunks(ClassNode cn, MethodNode clinit) {
        List<String> o = new ArrayList<>();
        for (AbstractInsnNode n = clinit.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() == Opcodes.LDC && n instanceof LdcInsnNode) {
                Object c = ((LdcInsnNode) n).cst;
                if (c instanceof String && ((String) c).length() >= 2) o.add((String) c);
            }
        }
        return o;
    }

    public static List<Integer> tableSizes(MethodNode clinit) {
        List<Integer> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(clinit);
        for (int k = 1; k < ins.size(); k++) {
            AbstractInsnNode n = ins.get(k);
            if (n.getOpcode() == Opcodes.ANEWARRAY && n instanceof TypeInsnNode
                    && ((TypeInsnNode) n).desc.equals("java/lang/String")) {
                Integer v = ClassIO.constInt(prevReal(ins, k));
                if (v != null && v > 0) o.add(v);
            }
        }
        return o;
    }

    private static AbstractInsnNode prevReal(List<AbstractInsnNode> ins, int k) {
        for (int j = k - 1; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (!(n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode)) return n;
        }
        return null;
    }

    public record SplitResult(int n, List<String> parts, double score) {}

    public static List<String> recoverFieldTable(ClassNode cn) {
        MethodNode clinit = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (clinit == null) return null;
        int[] keys = extractXorKeys(clinit);
        if (keys == null) return null;
        List<String> chunks = clinitChunks(cn, clinit);
        List<Integer> sizes = tableSizes(clinit);
        if (chunks.isEmpty() || sizes.isEmpty()) return null;
        List<String> flat = new ArrayList<>();
        for (String c : chunks) {
            SplitResult b = bestSplitDecrypt(c, keys, 8);
            if (b == null) continue;
            flat.addAll(b.parts());
        }
        if (flat.isEmpty() || !sizes.contains(flat.size())) return null;
        return flat;
    }

    private static List<String> searchTableBest(List<List<List<String>>> cand, int total) {
        List<String> bestFlat = null;
        double bestScore = -1;
        int[] combo = new int[cand.size()];
        int[] lim = new int[cand.size()];
        for (int i = 0; i < cand.size(); i++) lim[i] = Math.min(cand.get(i).size(), 16);
        long combos = 1;
        for (int l : lim) combos *= Math.max(l, 1);
        if (combos > 5000) return null;
        int[] idx = new int[cand.size()];
        while (true) {
            List<String> flat = new ArrayList<>();
            for (int i = 0; i < cand.size(); i++) flat.addAll(cand.get(i).get(idx[i]));
            if (flat.size() == total) {
                double s = 0;
                for (String p : flat) s += Crypto.scorePrint(p);
                s /= flat.size();
                if (s > bestScore) { bestScore = s; bestFlat = flat; }
            }
            int p = 0;
            while (p < cand.size()) {
                idx[p]++;
                if (idx[p] < lim[p]) break;
                idx[p] = 0;
                p++;
            }
            if (p == cand.size()) break;
        }
        if (bestFlat != null && bestScore > 0.85) return bestFlat;
        return null;
    }

    public static SplitResult bestSplitDecrypt(String encChunk, int[] keys, int maxN) {
        SplitResult best = null;
        for (int n = 1; n <= maxN; n++) {
            if (n > 1 && encChunk.length() < 4) break;
            for (List<String> sp : Crypto.allSplits(encChunk, n, 300)) {
                if (sp.size() != n) continue;
                List<String> dec = new ArrayList<>();
                double s = 0;
                for (String p : sp) { String d = Crypto.xorWithKeys(p, keys); dec.add(d); s += Crypto.scorePrint(d); }
                s /= n;
                if (n == 1 && (s < 0.99 || encChunk.length() < 4)) continue;
                if (best == null || s > best.score + 1e-9
                        || (Math.abs(s - best.score) < 1e-9 && n > best.n)) {
                    best = new SplitResult(n, dec, s);
                }
            }
        }
        if (best != null && best.score > 0.7) return best;
        return null;
    }

    public record FieldSite(String mName, String mDesc, AbstractInsnNode from,
                            AbstractInsnNode to, String field, int idx) {}

    public static List<FieldSite> fieldArraySites(ClassNode cn, MethodNode m) {
        List<FieldSite> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(m);
        Set<Integer> tloc = tableLocals(cn, ins);
        for (int k = 0; k + 2 < ins.size(); k++) {
            AbstractInsnNode a = ins.get(k), b = ins.get(k + 1), c = ins.get(k + 2);
            if (c.getOpcode() != Opcodes.AALOAD) continue;
            Integer idx = ClassIO.constInt(b);
            if (idx == null) idx = ldcInt(cn, b);
            if (idx == null || idx < 0) continue;
            String field = null;
            AbstractInsnNode from = null;
            if (a.getOpcode() == Opcodes.GETSTATIC && a instanceof FieldInsnNode) {
                FieldInsnNode f = (FieldInsnNode) a;
                if (f.desc.equals("[Ljava/lang/String;")) { field = f.name; from = a; }
            } else {
                Integer ln = aloadN(a);
                if (ln != null && tloc.contains(ln)) {
                    field = tableFieldFor(cn, ins, ln);
                    from = a;
                }
            }
            if (field != null) o.add(new FieldSite(m.name, m.desc, from, c, field, idx));
        }
        return o;
    }

    private static Set<Integer> tableLocals(ClassNode cn, List<AbstractInsnNode> ins) {
        Map<Integer, List<Integer>> stores = new HashMap<>();
        for (int k = 0; k < ins.size(); k++) {
            Integer n = astoreN(ins.get(k));
            if (n != null) stores.computeIfAbsent(n, x -> new ArrayList<>()).add(k);
        }
        Set<Integer> o = new HashSet<>();
        for (Map.Entry<Integer, List<Integer>> e : stores.entrySet()) {
            boolean ok = true;
            for (int k : e.getValue()) {
                if (k == 0 || !isTableGetstatic(cn, ins.get(k - 1))) { ok = false; break; }
            }
            if (ok) o.add(e.getKey());
        }
        return o;
    }

    private static boolean isTableGetstatic(ClassNode cn, AbstractInsnNode n) {
        return n.getOpcode() == Opcodes.GETSTATIC && n instanceof FieldInsnNode
                && ((FieldInsnNode) n).desc.equals("[Ljava/lang/String;");
    }

    private static String tableFieldFor(ClassNode cn, List<AbstractInsnNode> ins, int local) {
        for (int k = 0; k < ins.size(); k++) {
            Integer n = astoreN(ins.get(k));
            if (n != null && n == local && k > 0 && isTableGetstatic(cn, ins.get(k - 1))) {
                return ((FieldInsnNode) ins.get(k - 1)).name;
            }
        }
        return null;
    }

    private static Integer astoreN(AbstractInsnNode n) {
        if (n.getOpcode() == Opcodes.ASTORE && n instanceof VarInsnNode) return ((VarInsnNode) n).var;
        return null;
    }

    private static Integer aloadN(AbstractInsnNode n) {
        if (n.getOpcode() == Opcodes.ALOAD && n instanceof VarInsnNode) return ((VarInsnNode) n).var;
        return null;
    }

    private static Integer ldcInt(ClassNode cn, AbstractInsnNode n) {
        if (n.getOpcode() == Opcodes.LDC && n instanceof LdcInsnNode) {
            Object c = ((LdcInsnNode) n).cst;
            if (c instanceof Integer) return (Integer) c;
        }
        return null;
    }

    public record LookupSite(String mName, String mDesc, int encIdx, int key,
                             AbstractInsnNode from, AbstractInsnNode invoke, int extra) {
        public LookupSite(String mName, String mDesc, int encIdx, int key,
                          AbstractInsnNode from, AbstractInsnNode invoke) {
            this(mName, mDesc, encIdx, key, from, invoke, 0);
        }
    }

    public static List<LookupSite> lookupSites(ClassNode cn, MethodNode m, String desc) {
        List<LookupSite> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(m);
        List<Integer> realIdx = new ArrayList<>();
        for (int i = 0; i < ins.size(); i++) {
            AbstractInsnNode n = ins.get(i);
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            if (n.getOpcode() == Opcodes.NOP) continue;
            realIdx.add(i);
        }
        int need = desc.equals("(III)Ljava/lang/String;") ? 3 : 2;
        for (int ri = need; ri < realIdx.size(); ri++) {
            AbstractInsnNode n = ins.get(realIdx.get(ri));
            if (n.getOpcode() != Opcodes.INVOKESTATIC || !(n instanceof MethodInsnNode)) continue;
            MethodInsnNode mi = (MethodInsnNode) n;
            if (!mi.desc.equals(desc) || !mi.owner.equals(cn.name)) continue;
            if (need == 3) {
                Integer a = ClassIO.constInt(ins.get(realIdx.get(ri - 3)));
                if (a == null) a = ldcInt(cn, ins.get(realIdx.get(ri - 3)));
                Integer b = ClassIO.constInt(ins.get(realIdx.get(ri - 2)));
                if (b == null) b = ldcInt(cn, ins.get(realIdx.get(ri - 2)));
                Integer c = ClassIO.constInt(ins.get(realIdx.get(ri - 1)));
                if (c == null) c = ldcInt(cn, ins.get(realIdx.get(ri - 1)));
                if (a != null && b != null && c != null)
                    o.add(new LookupSite(m.name, m.desc, a ^ c, b, ins.get(realIdx.get(ri - 3)), n, c));
                continue;
            }
            Integer a = ClassIO.constInt(ins.get(realIdx.get(ri - 2)));
            if (a == null) a = ldcInt(cn, ins.get(realIdx.get(ri - 2)));
            Integer b = ClassIO.constInt(ins.get(realIdx.get(ri - 1)));
            if (b == null) b = ldcInt(cn, ins.get(realIdx.get(ri - 1)));
            if (a != null && b != null)
                o.add(new LookupSite(m.name, m.desc, a, b, ins.get(realIdx.get(ri - 2)), n));
        }
        return o;
    }

    public record IJStringSite(String mName, String mDesc, int arg, long key,
                               AbstractInsnNode from, AbstractInsnNode invoke) {}

    public static List<IJStringSite> ijStringSites(ClassNode cn, MethodNode m) {
        List<IJStringSite> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(m);
        List<Integer> realIdx = new ArrayList<>();
        for (int i = 0; i < ins.size(); i++) {
            AbstractInsnNode n = ins.get(i);
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            if (n.getOpcode() == Opcodes.NOP) continue;
            realIdx.add(i);
        }
        for (int ri = 2; ri < realIdx.size(); ri++) {
            AbstractInsnNode n = ins.get(realIdx.get(ri));
            if (n.getOpcode() != Opcodes.INVOKESTATIC || !(n instanceof MethodInsnNode)) continue;
            MethodInsnNode mi = (MethodInsnNode) n;
            if (!mi.desc.equals("(IJ)Ljava/lang/String;") || !mi.owner.equals(cn.name)) continue;
            Integer a = ClassIO.constInt(ins.get(realIdx.get(ri - 2)));
            if (a == null) a = ldcInt(cn, ins.get(realIdx.get(ri - 2)));
            AbstractInsnNode pk = ins.get(realIdx.get(ri - 1));
            Long key = pk instanceof LdcInsnNode && ((LdcInsnNode) pk).cst instanceof Long
                    ? (Long) ((LdcInsnNode) pk).cst : null;
            if (a != null && key != null)
                o.add(new IJStringSite(m.name, m.desc, a, key, ins.get(realIdx.get(ri - 2)), n));
        }
        return o;
    }

    public record StrFieldSite(String mName, String mDesc, AbstractInsnNode getstatic, String field) {}

    public static List<StrFieldSite> stringFieldSites(ClassNode cn, MethodNode m) {
        Set<String> finals = new HashSet<>();
        for (FieldNode f : cn.fields)
            if (f.desc.equals("Ljava/lang/String;") && (f.access & Opcodes.ACC_FINAL) != 0) finals.add(f.name);
        List<StrFieldSite> o = new ArrayList<>();
        if (finals.isEmpty()) return o;
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() == Opcodes.GETSTATIC && n instanceof FieldInsnNode) {
                FieldInsnNode f = (FieldInsnNode) n;
                if (f.desc.equals("Ljava/lang/String;") && f.owner.equals(cn.name) && finals.contains(f.name))
                    o.add(new StrFieldSite(m.name, m.desc, n, f.name));
            }
        }
        return o;
    }
}
