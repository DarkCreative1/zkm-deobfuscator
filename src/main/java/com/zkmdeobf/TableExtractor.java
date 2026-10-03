package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class TableExtractor {
    private TableExtractor() {}

    private static final Set<String> CHARSETS = Set.of(
            "ISO-8859-1", "UTF-8", "UTF8", "US-ASCII", "ASCII",
            "UTF-16", "UTF-16BE", "UTF-16LE", "Cp1252", "windows-1252");

    public record Tables(List<String> strings, List<Long> longs,
                         List<String> stringChunks, List<String> longChunks) {}

    public static Tables extract(ClassNode cn) {
        MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (cl == null) return null;
        int[] keys = StringDecryptor.extractXorKeys(cl);
        if (keys == null) return null;
        List<String> chunks = new ArrayList<>();
        for (String c : StringDecryptor.clinitChunks(cn, cl)) {
            if (!CHARSETS.contains(c) && !c.isEmpty()) chunks.add(c);
        }
        if (chunks.isEmpty() || chunks.size() > 12) return null;
        List<Integer> strSizes = StringDecryptor.tableSizes(cl);
        List<Integer> longSizes = longTableSizes(cl);
        Set<Integer> strTotals = new LinkedHashSet<>(strSizes);
        Set<Integer> longTotals = new LinkedHashSet<>(longSizes);
        if (strTotals.isEmpty()) strTotals.add(0);
        if (longTotals.isEmpty()) longTotals.add(0);
        if (strTotals.size() == 1 && strTotals.contains(0)
                && longTotals.size() == 1 && longTotals.contains(0)) return null;

        List<StringDecryptor.SplitResult> splits = new ArrayList<>();
        for (String c : chunks) splits.add(StringDecryptor.bestSplitDecrypt(c, keys, 8));

        int k = chunks.size();
        Tables best = null;
        double bestScore = -1;
        for (int ns : strTotals) {
            for (int nl : longTotals) {
                if (ns == 0 && nl == 0) continue;
                for (int mask = 0; mask < (1 << k); mask++) {
                    List<String> flat = new ArrayList<>();
                    List<String> lch = new ArrayList<>();
                    double ssum = 0;
                    int scnt = 0;
                    boolean ok = true;
                    for (int i = 0; i < k; i++) {
                        if ((mask & (1 << i)) != 0) {
                            StringDecryptor.SplitResult b = splits.get(i);
                            if (b == null) { ok = false; break; }
                            flat.addAll(b.parts());
                            ssum += b.score() * b.n();
                            scnt += b.n();
                        } else {
                            lch.add(chunks.get(i));
                        }
                    }
                    if (!ok) continue;
                    if (ns > 0 && flat.size() != ns) continue;
                    if (ns == 0 && !flat.isEmpty()) continue;
                    List<Long> longs = new ArrayList<>();
                    if (nl > 0) {
                        if (hasCipherInit(cl)) continue;
                        byte[] all = concatBytes(lch);
                        if (all == null || all.length != 8 * nl) continue;
                        for (int i = 0; i < nl; i++) {
                            long v = 0;
                            for (int j = 0; j < 8; j++) v = (v << 8) | (all[i * 8 + j] & 0xFF);
                            longs.add(v);
                        }

                        if (looksMethodKeyed(cl)) continue;
                        Long ck = findLongXorKey(cl);
                        if (ck != null) {
                            for (int i = 0; i < longs.size(); i++) longs.set(i, longs.get(i) ^ ck);
                        }
                    } else if (!lch.isEmpty()) {
                        continue;
                    }
                    double score = scnt == 0 ? 1.0 : ssum / scnt;
                    if (score > bestScore) {
                        bestScore = score;
                        best = new Tables(new ArrayList<>(flat), longs,
                                strChunkList(chunks, mask), new ArrayList<>(lch));
                    }
                }
            }
        }
        if (best != null && bestScore > 0.85) return best;
        return null;
    }

    public static Tables extractViaEmulation(ClassNode cn, Map<String, ClassNode> classes,
                                            ClassLoader loader) {
        if (classes == null) return null;
        Map<String, Object> st = MiniInterpreter.emulateClinit(classes, loader, cn);
        if (st == null || st.isEmpty()) return null;
        List<List<String>> strCands = new ArrayList<>();
        List<List<Long>> longCands = new ArrayList<>();
        for (var f : cn.fields) {
            Object v = st.get(cn.name + "." + f.name);
            if (!(v instanceof MiniInterpreter.Arr a)) continue;
            if (f.desc.equals("[Ljava/lang/String;") && a.data instanceof Object[] o) {
                List<String> one = new ArrayList<>();
                boolean ok = true;
                int nulls = 0;
                for (Object e : o) {
                    if (e == null || e == MiniInterpreter.NULL) { one.add(null); nulls++; }
                    else if (e instanceof String s) one.add(s);
                    else { ok = false; break; }
                }

                if (ok && !one.isEmpty() && nulls < one.size()) strCands.add(one);
            } else if (f.desc.equals("[J") && a.data instanceof long[] l) {
                List<Long> one = new ArrayList<>();
                for (long x : l) one.add(x);
                if (!one.isEmpty()) longCands.add(one);
            }
        }
        MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
        List<String> strings = pickSized(strCands, cl == null ? List.of() : StringDecryptor.tableSizes(cl));
        List<Long> longs = pickSizedLong(longCands, cl == null ? List.of() : longTableSizes(cl));
        if ((strings == null || strings.isEmpty()) && (longs == null || longs.isEmpty())) return null;
        return new Tables(strings == null ? List.of() : strings,
                longs == null ? List.of() : longs, List.of(), List.of());
    }

    private static List<String> strChunkList(List<String> chunks, int mask) {
        List<String> o = new ArrayList<>();
        for (int i = 0; i < chunks.size(); i++)
            if ((mask & (1 << i)) != 0) o.add(chunks.get(i));
        return o;
    }

    private static List<String> pickSized(List<List<String>> cands, List<Integer> sizes) {
        if (cands.isEmpty()) return null;
        Set<Integer> totals = new LinkedHashSet<>(sizes);
        if (totals.isEmpty()) totals.add(0);
        List<String> best = null;
        int bestNulls = Integer.MAX_VALUE;
        for (int total : totals) {
            for (List<String> c : cands) {
                if (total > 0 && c.size() != total) continue;
                if (total == 0 && !c.isEmpty()) continue;
                int nulls = 0;
                for (String s : c) if (s == null) nulls++;
                if (nulls < bestNulls) { bestNulls = nulls; best = c; }
            }
            if (best != null && bestNulls == 0) return best;
        }
        return best;
    }

    private static List<Long> pickSizedLong(List<List<Long>> cands, List<Integer> sizes) {
        if (cands.isEmpty()) return null;
        Set<Integer> totals = new LinkedHashSet<>(sizes);
        if (totals.isEmpty()) totals.add(0);
        for (int total : totals) {
            for (List<Long> c : cands) {
                if (total > 0 && c.size() != total) continue;
                if (total == 0 && !c.isEmpty()) continue;
                return c;
            }
        }
        return null;
    }

    static boolean looksMethodKeyed(MethodNode cl) {
        List<AbstractInsnNode> ins = ClassIO.list(cl);
        for (int k = 0; k + 1 < ins.size(); k++) {
            AbstractInsnNode a = ins.get(k), b = ins.get(k + 1);
            if (a.getOpcode() != Opcodes.LLOAD || !(a instanceof VarInsnNode)) continue;
            if (b.getOpcode() != Opcodes.LXOR) continue;
            int local = ((VarInsnNode) a).var;
            int stores = 0;
            for (AbstractInsnNode s : ins) {
                if (s.getOpcode() == Opcodes.LSTORE && s instanceof VarInsnNode
                        && ((VarInsnNode) s).var == local) stores++;
            }
            if (stores != 1) return true;
            for (int j = k - 1; j >= 0; j--) {
                AbstractInsnNode s = ins.get(j);
                if (s.getOpcode() == Opcodes.GETSTATIC) return true;
                if (s.getOpcode() == Opcodes.LSTORE && s instanceof VarInsnNode
                        && ((VarInsnNode) s).var == local) break;
            }
        }
        return false;
    }

    static Long findLongXorKey(MethodNode cl) {
        List<AbstractInsnNode> ins = ClassIO.list(cl);
        for (int k = 0; k + 1 < ins.size(); k++) {
            AbstractInsnNode a = ins.get(k), b = ins.get(k + 1);
            if (a.getOpcode() != Opcodes.LLOAD || !(a instanceof VarInsnNode)) continue;
            if (b.getOpcode() != Opcodes.LXOR) continue;
            int local = ((VarInsnNode) a).var;

            int stores = 0;
            for (AbstractInsnNode s : ins) {
                if (s.getOpcode() == Opcodes.LSTORE && s instanceof VarInsnNode
                        && ((VarInsnNode) s).var == local) stores++;
            }
            if (stores != 1) continue;

            for (int j = k - 1; j >= 0; j--) {
                AbstractInsnNode s = ins.get(j);
                if (s.getOpcode() == Opcodes.LSTORE && s instanceof VarInsnNode
                        && ((VarInsnNode) s).var == local) {
                    AbstractInsnNode p = prevReal(ins, j);
                    if (p != null && p.getOpcode() == Opcodes.LDC && p instanceof LdcInsnNode
                            && ((LdcInsnNode) p).cst instanceof Long) {
                        return (Long) ((LdcInsnNode) p).cst;
                    }
                    break;
                }
                if (s.getOpcode() == Opcodes.GETSTATIC) break;
            }
        }
        return null;
    }

    private static boolean hasCipherInit(MethodNode cl) {
        for (AbstractInsnNode n = cl.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() == Opcodes.LDC && n instanceof LdcInsnNode l
                    && l.cst instanceof String s && s.contains("DES/")) return true;
        }
        return false;
    }

    private static byte[] concatBytes(List<String> chunks) {
        try {
            java.nio.charset.CharsetEncoder enc = StandardCharsets.ISO_8859_1.newEncoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            for (String c : chunks) {
                if (!enc.canEncode(c)) return null;
                byte[] b = c.getBytes(StandardCharsets.ISO_8859_1);
                o.write(b, 0, b.length);
            }
            return o.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public static List<Integer> longTableSizes(MethodNode clinit) {
        List<Integer> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(clinit);
        for (int k = 1; k < ins.size(); k++) {
            AbstractInsnNode n = ins.get(k);
            if (n.getOpcode() == Opcodes.NEWARRAY && n instanceof IntInsnNode x && x.operand == 11) {
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
}
