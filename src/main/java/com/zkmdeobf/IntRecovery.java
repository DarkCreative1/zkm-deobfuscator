package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class IntRecovery {
    private IntRecovery() {}

    public record LookupParams(long mask, int indexXor) {}
    public record Site(String mName, String mDesc, int arg, long key,
                       AbstractInsnNode from, AbstractInsnNode invoke, AbstractInsnNode keyPush) {
        public Site(String mName, String mDesc, int arg, long key,
                    AbstractInsnNode from, AbstractInsnNode invoke) {
            this(mName, mDesc, arg, key, from, invoke, null);
        }

        public boolean hasGap() {
            if (keyPush == null) return false;
            for (AbstractInsnNode x = from; x != null && x != invoke; x = x.getNext()) {
                if (x.getOpcode() < 0) continue;
                if (x == from || x == keyPush) continue;
                return true;
            }
            return false;
        }
    }

    public static LookupParams params(ClassNode cn, MethodNode lookup) {
        if (cn == null || lookup == null) return null;
        List<AbstractInsnNode> ins = ClassIO.list(lookup);
        List<AbstractInsnNode> real = new ArrayList<>();
        for (AbstractInsnNode n : ins) {
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            if (n.getOpcode() == Opcodes.NOP) continue;
            real.add(n);
        }
        List<LookupParams> found = new ArrayList<>();
        for (int k = 0; k + 5 < real.size(); k++) {
            int[] ops = new int[6];
            for (int i = 0; i < 6; i++) ops[i] = real.get(k + i).getOpcode();
            if (ops[0] == Opcodes.LDC && ops[1] == Opcodes.LAND && ops[2] == Opcodes.L2I
                    && ops[3] == Opcodes.IXOR && ops[5] == Opcodes.IXOR) {
                // ops[4] must be a key push (const or LDC int); otherwise mask/xor is garbage.
                AbstractInsnNode n0 = real.get(k), n4 = real.get(k + 4);
                if (!(n0 instanceof LdcInsnNode) || !(((LdcInsnNode) n0).cst instanceof Long)) continue;
                Integer kk = ClassIO.constInt(n4);
                if (kk == null) continue;
                found.add(new LookupParams((Long) ((LdcInsnNode) n0).cst, kk));
            }
        }
        if (found.isEmpty()) return null;
        return found.get(0);
    }

    public static List<Site> sites(ClassNode cn, MethodNode m, String desc) {
        List<Site> o = new ArrayList<>();
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
            if (!mi.desc.equals(desc)) continue;
            AbstractInsnNode nk1 = ins.get(realIdx.get(ri - 1)), nk2 = ins.get(realIdx.get(ri - 2));
            Long key = nk1 instanceof LdcInsnNode && ((LdcInsnNode) nk1).cst instanceof Long
                    ? (Long) ((LdcInsnNode) nk1).cst : null;
            Integer arg = key == null ? null : ClassIO.constInt(nk2);

            if (key != null && arg == null) {

                int found = -1;
                int d1 = 1;
                Set<LabelNode> tgts = ClassIO.jumpTargets(m);
                outer:
                for (int q = realIdx.get(ri - 1) - 1; q >= 0; q--) {
                    AbstractInsnNode x = ins.get(q);
                    if (x instanceof LabelNode ln) {
                        // Only a real jump/try target blocks the walk; debug labels don't.
                        if (tgts.contains(ln)) break;
                        continue;
                    }
                    if (x instanceof LineNumberNode || x instanceof FrameNode) continue;
                    if (x.getOpcode() == Opcodes.NOP) continue;
                    int xo = x.getOpcode();
                    if (xo == Opcodes.GOTO || xo == Opcodes.ATHROW || xo == Opcodes.JSR
                            || xo == Opcodes.RET
                            || (xo >= Opcodes.IRETURN && xo <= Opcodes.RETURN)) break;
                    if (x instanceof JumpInsnNode || x instanceof TableSwitchInsnNode
                            || x instanceof LookupSwitchInsnNode) break;
                    int[] ss = Rewriter.stackSizes(x);
                    if (ss == null) break;
                    int d0 = d1 + ss[0] - ss[1];
                    if (d0 == 0) {
                        if (ClassIO.constInt(x) != null) found = q;
                        break;
                    }
                    if (d0 < 0 || d0 > 6) break;
                    d1 = d0;
                }
                if (found >= 0) { nk2 = ins.get(found); arg = ClassIO.constInt(nk2); }
            }
            if (key != null && arg != null)
                o.add(new Site(m.name, m.desc, arg, key, nk2, n, nk1));
        }
        return o;
    }

    public static List<Site> allSites(ClassNode cn, MethodNode m) {
        List<Site> o = new ArrayList<>();
        o.addAll(sites(cn, m, "(IJ)I"));
        o.addAll(sites(cn, m, "(IJ)J"));
        return o;
    }

    public static int recoverInt(int arg, long key, long mask, int xor, long[] enc) {
        if (enc == null) throw new IllegalArgumentException("enc==null");
        long l = (arg ^ (key & mask) ^ xor);
        if (l < 0 || l >= enc.length) throw new IllegalArgumentException("idx-aralik:" + l);
        return (int) (enc[(int) l] ^ key);
    }

    public static long recoverLong(int arg, long key, long mask, int xor, long[] enc) {
        if (enc == null) throw new IllegalArgumentException("enc==null");
        long l = (arg ^ (key & mask) ^ xor);
        if (l < 0 || l >= enc.length) throw new IllegalArgumentException("idx-aralik:" + l);
        return enc[(int) l] ^ key;
    }

    public static long recoverLongDes(int arg, long key, long mask, int xor, long[] enc) {
        if (enc == null) throw new IllegalArgumentException("enc==null");
        long l = (arg ^ (key & mask) ^ xor);
        if (l < 0 || l >= enc.length) throw new IllegalArgumentException("idx-aralik:" + l);
        return Crypto.desLongCrypt(enc[(int) l], key, true);
    }

    public static boolean isDesLookup(ClassNode cn, MethodNode lookup) {
        for (AbstractInsnNode n = lookup.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof LdcInsnNode l && l.cst instanceof String s && s.contains("DES/")) return true;
            if (n instanceof MethodInsnNode mi
                    && (mi.owner.startsWith("javax/crypto/") || mi.owner.startsWith("javax/crypto/spec/")))
                return true;
        }
        return false;
    }
}
