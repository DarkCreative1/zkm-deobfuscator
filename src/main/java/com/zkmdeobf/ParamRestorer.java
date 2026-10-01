package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class ParamRestorer {
    private ParamRestorer() {}

    private static final Map<String, Type> UNBOX = Map.of(
        "intValue", Type.INT_TYPE, "longValue", Type.LONG_TYPE,
        "floatValue", Type.FLOAT_TYPE, "doubleValue", Type.DOUBLE_TYPE,
        "booleanValue", Type.BOOLEAN_TYPE, "charValue", Type.CHAR_TYPE,
        "byteValue", Type.BYTE_TYPE, "shortValue", Type.SHORT_TYPE);

    public record Unpack(int index, Type type, int local, List<AbstractInsnNode> nodes) {}
    public record Plan(MethodNode callee, List<Unpack> order, String newDesc,
                       List<AbstractInsnNode> closers) {
        public Plan(MethodNode callee, List<Unpack> order, String newDesc) {
            this(callee, order, newDesc, List.of());
        }
    }

    private record Unit(int index, Type type, int local, List<AbstractInsnNode> nodes, int end) {}

    private static boolean isDup(int op) {
        return op == Opcodes.DUP || op == Opcodes.DUP_X1 || op == Opcodes.DUP_X2
                || op == Opcodes.DUP2 || op == Opcodes.DUP2_X1 || op == Opcodes.DUP2_X2;
    }

    private static Unit parseUnit(List<AbstractInsnNode> ins, int k, boolean chain) {
        int p = k;
        if (chain) {
            if (!isDup(ins.get(p).getOpcode())) return null;
            p++;
        } else {
            if (!(ins.get(p) instanceof VarInsnNode v && v.var >= 0)) return null;
            if (ins.get(p).getOpcode() != Opcodes.ALOAD) return null;
            p++;
        }
        if (p + 2 >= ins.size()) return null;
        Integer idx = ClassIO.constInt(ins.get(p));
        if (idx == null || idx < 0) return null;
        if (ins.get(p + 1).getOpcode() != Opcodes.AALOAD) return null;
        if (ins.get(p + 2).getOpcode() != Opcodes.CHECKCAST
                || !(ins.get(p + 2) instanceof TypeInsnNode)) return null;
        Type t = Type.getObjectType(((TypeInsnNode) ins.get(p + 2)).desc);
        List<AbstractInsnNode> nodes = new ArrayList<>();
        for (int q = k; q <= p + 2; q++) nodes.add(ins.get(q));
        int e = p + 3;

        if (e < ins.size() && ins.get(e).getOpcode() == Opcodes.INVOKEVIRTUAL
                && ins.get(e) instanceof MethodInsnNode) {
            Type ub = UNBOX.get(((MethodInsnNode) ins.get(e)).name);
            if (ub != null) { nodes.add(ins.get(e)); t = ub; e++; }
        }

        int local = -1;
        if (e < ins.size() && isStore(ins.get(e))) {
            local = ((VarInsnNode) ins.get(e)).var;
            nodes.add(ins.get(e));
            e++;
        }
        return new Unit(idx, t, local, nodes, e);
    }

    public static Plan analyze(ClassNode cn, MethodNode m) {
        if (!m.desc.startsWith("([Ljava/lang/Object;)")) return null;
        boolean statik = (m.access & Opcodes.ACC_STATIC) != 0;
        int arrLocal = statik ? 0 : 1;

        if (!usesArrLocal(m, arrLocal)) {
            String nd = "()" + Type.getReturnType(m.desc).getDescriptor();
            return new Plan(m, List.of(), nd);
        }
        List<AbstractInsnNode> ins = ClassIO.list(m);
        int n = ins.size();
        List<Unpack> order = new ArrayList<>();
        List<AbstractInsnNode> closers = new ArrayList<>();
        Set<AbstractInsnNode> covered = new HashSet<>();

        int k = 0;
        while (k < n && isLabelish(ins.get(k))) k++;
        AbstractInsnNode head = null;
        if (k < n && isAload(ins.get(k), arrLocal)) { head = ins.get(k); k++; }
        int chainCount = 0;
        while (true) {
            while (k < n && isLabelish(ins.get(k))) k++;
            if (k >= n || !isDup(ins.get(k).getOpcode())) break;
            Unit u = parseUnit(ins, k, true);
            if (u == null) break;
            if (head != null) {
                List<AbstractInsnNode> nn = new ArrayList<>();
                nn.add(head);
                nn.addAll(u.nodes());
                u = new Unit(u.index(), u.type(), u.local(), nn, u.end());
                head = null;
            }
            order.add(new Unpack(u.index(), u.type(), u.local(), u.nodes()));
            covered.addAll(u.nodes());
            k = u.end();
            chainCount++;
        }
        if (head != null) return null;
        if (chainCount > 0) {

            while (k < n && isLabelish(ins.get(k))) k++;
            if (k >= n || ins.get(k).getOpcode() != Opcodes.POP) return null;
            if (!popCloseSafe(cn, m, ins, k, k)) return null;
            closers.add(ins.get(k));
            covered.add(ins.get(k));
            k++;
        }

        List<Unpack> fresh = new ArrayList<>();
        int j = k;
        while (j < n) {
            AbstractInsnNode x = ins.get(j);
            if (isLabelish(x)) { j++; continue; }
            if (x.getOpcode() == Opcodes.ALOAD && x instanceof VarInsnNode
                    && ((VarInsnNode) x).var == arrLocal && !covered.contains(x)) {
                Unit u = parseUnit(ins, j, false);
                if (u == null) return null;
                fresh.add(new Unpack(u.index(), u.type(), u.local(), u.nodes()));
                covered.addAll(u.nodes());
                j = u.end();
                continue;
            }
            j++;
        }

        for (AbstractInsnNode x : ins)
            if (x.getOpcode() == Opcodes.AALOAD && !covered.contains(x)) return null;
        order.addAll(fresh);
        if (order.isEmpty()) return null;

        TreeSet<Integer> idxs = new TreeSet<>();
        for (Unpack u : order) if (!idxs.add(u.index())) return null;
        if (idxs.first() != 0 || idxs.last() != idxs.size() - 1) return null;

        for (AbstractInsnNode x : ins) {
            if (covered.contains(x)) continue;
            if (x instanceof VarInsnNode v && v.var == arrLocal) return null;
            if (x instanceof IincInsnNode ii && ii.var == arrLocal) return null;
        }

        List<Unpack> fixed = new ArrayList<>();
        for (Unpack u : order) {
            Type t = u.type();
            if (u.local() >= 0 && (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY)) {
                Type pu = unboxedType(ins, u.local());
                if (pu != null) t = pu;
            }
            fixed.add(new Unpack(u.index(), t, u.local(), u.nodes()));
        }
        fixed.sort(Comparator.comparingInt(Unpack::index));
        StringBuilder nd = new StringBuilder("(");
        for (Unpack u : fixed) nd.append(u.type().getDescriptor());
        nd.append(")").append(Type.getReturnType(m.desc).getDescriptor());
        return new Plan(m, fixed, nd.toString(), closers);
    }

    private static boolean isLabelish(AbstractInsnNode n) {
        return n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode;
    }

    private static boolean isStore(AbstractInsnNode n) {
        int op = n.getOpcode();
        return op == Opcodes.ASTORE || op == Opcodes.ISTORE || op == Opcodes.LSTORE
                || op == Opcodes.FSTORE || op == Opcodes.DSTORE;
    }

    private static boolean popCloseSafe(ClassNode cn, MethodNode m, List<AbstractInsnNode> ins,
                                        int e, int pe) {
        Set<LabelNode> bounds = new HashSet<>();
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            bounds.add(t.start); bounds.add(t.end); bounds.add(t.handler);
        }
        Set<LabelNode> tgts = ClassIO.jumpTargets(m);
        for (int q = e; q <= pe; q++) {
            AbstractInsnNode n = ins.get(q);
            if (n instanceof LabelNode && (bounds.contains(n) || tgts.contains(n))) return false;
        }
        return true;
    }

    private static int storeVar(AbstractInsnNode n) {
        return ((VarInsnNode) n).var;
    }

    private static Type unboxedType(List<AbstractInsnNode> ins, int local) {
        for (int k = 0; k + 1 < ins.size(); k++) {
            AbstractInsnNode a = ins.get(k), b = ins.get(k + 1);
            boolean load = (a.getOpcode() == Opcodes.ALOAD && a instanceof VarInsnNode && ((VarInsnNode) a).var == local);
            if (load && b.getOpcode() == Opcodes.INVOKEVIRTUAL && b instanceof MethodInsnNode) {
                Type t = UNBOX.get(((MethodInsnNode) b).name);
                if (t != null) return t;
            }
        }
        return null;
    }

    private static boolean isAload(AbstractInsnNode n, int local) {
        return n.getOpcode() == Opcodes.ALOAD && n instanceof VarInsnNode && ((VarInsnNode) n).var == local;
    }

    private static boolean usesArrLocal(MethodNode m, int arrLocal) {
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof VarInsnNode v && v.var == arrLocal) return true;
            if (n instanceof IincInsnNode ii && ii.var == arrLocal) return true;
        }
        return false;
    }

    public static boolean rewriteCallee(ClassNode cn, Plan p) {
        MethodNode m = p.callee();
        if (Rewriter.hasJsrRet(m)) return false;
        boolean statik = (m.access & Opcodes.ACC_STATIC) != 0;
        int arrLocal = statik ? 0 : 1;
        int base = statik ? 0 : 1;

        int[] slots = new int[p.order().size()];
        int w = 0;
        for (int i = 0; i < slots.length; i++) { slots[i] = base + w; w += p.order().get(i).type().getSize(); }

        for (int i = 0; i < p.order().size(); i++) {
            int local = p.order().get(i).local();
            if (local < 0) continue;
            int stores = 0;
            for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                int op = n.getOpcode();
                if (n instanceof VarInsnNode && ((VarInsnNode) n).var == local
                        && (op == Opcodes.ASTORE || op == Opcodes.ISTORE || op == Opcodes.LSTORE
                            || op == Opcodes.FSTORE || op == Opcodes.DSTORE)) stores++;
                else if (op == Opcodes.IINC && n instanceof IincInsnNode && ((IincInsnNode) n).var == local) stores++;
            }
            if (stores != 1) return false;
        }

        Set<AbstractInsnNode> unpackNodes = new HashSet<>();
        for (Unpack u : p.order()) unpackNodes.addAll(u.nodes());
        unpackNodes.addAll(p.closers());

        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (unpackNodes.contains(n)) continue;
            if (n instanceof VarInsnNode v && v.var == arrLocal) return false;
            if (n instanceof IincInsnNode ii && ii.var == arrLocal) return false;
        }
        Map<Integer, Integer> remap = new HashMap<>();
        for (int i = 0; i < p.order().size(); i++) {
            int local = p.order().get(i).local();
            if (local >= 0) remap.put(local, slots[i]);
        }
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (unpackNodes.contains(n)) continue;
            int op = n.getOpcode();
            if (n instanceof VarInsnNode v) {
                if ((op == Opcodes.ALOAD || op == Opcodes.ILOAD || op == Opcodes.LLOAD
                        || op == Opcodes.FLOAD || op == Opcodes.DLOAD || op == Opcodes.ASTORE
                        || op == Opcodes.ISTORE || op == Opcodes.LSTORE || op == Opcodes.FSTORE
                        || op == Opcodes.DSTORE) && remap.containsKey(v.var)) v.var = remap.get(v.var);
            } else if (n instanceof IincInsnNode ii && remap.containsKey(ii.var)) {
                ii.var = remap.get(ii.var);
            }
        }

        for (int i = 0; i < p.order().size(); i++) {
            Unpack u = p.order().get(i);
            if (u.local() >= 0) continue;
            AbstractInsnNode load = loadFor(u.type(), slots[i]);
            if (load == null) return false;
            m.instructions.insertBefore(u.nodes().get(0), load);
        }

        for (Unpack u : p.order())
            for (AbstractInsnNode n : u.nodes()) m.instructions.remove(n);
        for (AbstractInsnNode c : p.closers()) m.instructions.remove(c);
        m.desc = p.newDesc();
        return true;
    }

    private static AbstractInsnNode loadFor(Type t, int local) {
        return switch (t.getSort()) {
            case Type.INT, Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT ->
                new VarInsnNode(Opcodes.ILOAD, local);
            case Type.LONG -> new VarInsnNode(Opcodes.LLOAD, local);
            case Type.FLOAT -> new VarInsnNode(Opcodes.FLOAD, local);
            case Type.DOUBLE -> new VarInsnNode(Opcodes.DLOAD, local);
            case Type.OBJECT, Type.ARRAY -> new VarInsnNode(Opcodes.ALOAD, local);
            default -> null;
        };
    }

    static String declaringOwner(Map<String, ClassNode> classes, String owner,
                                 String name, String desc) {
        ClassNode cn = classes.get(owner + ".class");
        Set<String> seen = new HashSet<>();
        while (cn != null && seen.add(cn.name)) {
            for (MethodNode m : cn.methods)
                if (m.name.equals(name) && m.desc.equals(desc)) return cn.name;
            if (cn.interfaces != null) {
                for (String itf : cn.interfaces) {
                    ClassNode icn = classes.get(itf + ".class");
                    if (icn != null) for (MethodNode m : icn.methods)
                        if (m.name.equals(name) && m.desc.equals(desc)) return icn.name;
                }
            }
            cn = cn.superName == null ? null : classes.get(cn.superName + ".class");
        }
        return null;
    }

    public static int rewriteCallers(Map<String, ClassNode> classes, Map<String, String> newDescs) {
        int n = 0;
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                if (Rewriter.hasJsrRet(m)) continue;
                List<AbstractInsnNode> ins = ClassIO.list(m);
                for (int k = 0; k < ins.size(); k++) {
                    AbstractInsnNode cur = ins.get(k);
                    if (cur.getOpcode() != Opcodes.INVOKESTATIC
                            && cur.getOpcode() != Opcodes.INVOKEVIRTUAL
                            && cur.getOpcode() != Opcodes.INVOKEINTERFACE) continue;
                    if (!(cur instanceof MethodInsnNode mi)) continue;
                    if (!mi.desc.startsWith("([Ljava/lang/Object;)")) continue;
                    String nd = newDescs.get(mi.owner + "." + mi.name + mi.desc);
                    if (nd == null) {

                        String decl = declaringOwner(classes, mi.owner, mi.name, mi.desc);
                        if (decl != null) nd = newDescs.get(decl + "." + mi.name + mi.desc);
                    }
                    if (nd == null) continue;
                    int arity = Type.getArgumentTypes(nd).length;

                    if (arity == 0) {
                        int arrNew0 = -1;
                        for (int j = k - 1; j >= 0; j--) {
                            AbstractInsnNode q = ins.get(j);
                            int op = q.getOpcode();
                            if (op < 0) continue;
                            if (op == Opcodes.ANEWARRAY && q instanceof TypeInsnNode
                                    && ((TypeInsnNode) q).desc.equals("java/lang/Object")) {
                                arrNew0 = j;
                                break;
                            } else {
                                break;
                            }
                        }
                        if (arrNew0 < 0) continue;

                        int sj = arrNew0 - 1;
                        while (sj >= 0 && ins.get(sj).getOpcode() < 0) sj--;
                        Integer sz0 = (sj >= 0) ? ClassIO.constInt(ins.get(sj)) : null;
                        if (sz0 == null || sz0 != 0) continue;

                        boolean hasStore = false;
                        for (int j = sj; j < k; j++) {
                            if (ins.get(j).getOpcode() == Opcodes.AASTORE) { hasStore = true; break; }
                        }
                        if (hasStore) continue;
                        AbstractInsnNode from0 = ins.get(sj);
                        if (!rangeClean(m, from0, cur)) continue;
                        mi.desc = nd;
                        AbstractInsnNode x = from0;
                        while (true) {
                            AbstractInsnNode nx = x.getNext();
                            if (x != cur && x.getOpcode() >= 0) m.instructions.remove(x);
                            if (x == cur) break;
                            x = nx;
                        }
                        n++;
                        ins = ClassIO.list(m);
                        k = -1;
                        continue;
                    }

                    int aastore = -1;
                    for (int j = k - 1; j >= 0; j--) {
                        if (ins.get(j).getOpcode() == Opcodes.AASTORE) { aastore = j; break; }
                        int op = ins.get(j).getOpcode();
                        if (op == Opcodes.ANEWARRAY || op < 0) break;
                    }
                    if (aastore < 0) continue;
                    int arrNew = -1, arrSize = -1;
                    for (int j = aastore; j >= 0; j--) {
                        int op = ins.get(j).getOpcode();
                        if (op == Opcodes.ANEWARRAY && ins.get(j) instanceof TypeInsnNode
                                && ((TypeInsnNode) ins.get(j)).desc.equals("java/lang/Object")) {
                            arrNew = j;
                            if (j > 0) {
                                Integer sz = ClassIO.constInt(ins.get(j - 1));
                                if (sz != null) arrSize = sz;
                            }
                            break;
                        }
                    }
                    if (arrNew < 0) continue;

                    if (arrSize < 0) continue;

                    if (arrSize != arity) continue;

                    AbstractInsnNode from = ins.get(arrNew);
                    if (arrNew > 0 && ClassIO.constInt(ins.get(arrNew - 1)) != null
                            && arrSize >= 0) from = ins.get(arrNew - 1);

                    if (!rangeClean(m, from, cur)) continue;
                    mi.desc = nd;
                    AbstractInsnNode x = from;
                    while (true) {
                        AbstractInsnNode nx = x.getNext();

                        if (x != cur && x.getOpcode() >= 0) m.instructions.remove(x);
                        if (x == cur) break;
                        x = nx;
                    }
                    n++;
                    ins = ClassIO.list(m);
                    k = -1;
                }
            }
        }
        return n;
    }

    private static boolean rangeClean(MethodNode m, AbstractInsnNode from, AbstractInsnNode to) {
        Set<LabelNode> bounds = new HashSet<>();
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            bounds.add(t.start); bounds.add(t.end); bounds.add(t.handler);
        }
        Set<LabelNode> tgts = ClassIO.jumpTargets(m);
        AbstractInsnNode n = from;
        while (true) {
            if (n instanceof LabelNode && (bounds.contains(n) || tgts.contains(n))) return false;
            if (n == to) break;
            n = n.getNext();
            if (n == null) return false;
        }
        return true;
    }
}
