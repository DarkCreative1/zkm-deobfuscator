package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class FlowSimplifier {
    private FlowSimplifier() {}

    public sealed interface Const permits IntConst, LongConst, FloatConst, DoubleConst, NullConst {}
    public record IntConst(int v) implements Const {}
    public record LongConst(long v) implements Const {}
    public record FloatConst(float v) implements Const {}
    public record DoubleConst(double v) implements Const {}
    public record NullConst() implements Const {}

    public static Map<String, Const> clinitConstants(ClassNode cn) {
        Map<String, Const> o = new HashMap<>();
        MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (cl == null) return o;
        Map<String, Integer> writes = new HashMap<>();
        Map<String, Const> vals = new HashMap<>();
        List<AbstractInsnNode> ins = ClassIO.list(cl);
        for (int k = 1; k < ins.size(); k++) {
            AbstractInsnNode n = ins.get(k);
            if (n.getOpcode() == Opcodes.PUTSTATIC && n instanceof FieldInsnNode) {
                FieldInsnNode f = (FieldInsnNode) n;
                if (!f.owner.equals(cn.name)) continue;
                String key = f.owner + "." + f.name;
                writes.merge(key, 1, Integer::sum);
                Const c = constOfChain(ins, k - 1);
                if (c != null) vals.put(key, c);
            }
        }

        Set<String> elsewhere = new HashSet<>();
        for (MethodNode m : cn.methods) {
            if (m == cl) continue;
            for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                if ((n.getOpcode() == Opcodes.PUTSTATIC) && n instanceof FieldInsnNode) {
                    FieldInsnNode f = (FieldInsnNode) n;
                    if (f.owner.equals(cn.name)) elsewhere.add(f.owner + "." + f.name);
                }
            }
        }
        for (Map.Entry<String, Const> e : vals.entrySet()) {
            if (writes.getOrDefault(e.getKey(), 0) == 1 && !elsewhere.contains(e.getKey()))
                o.put(e.getKey(), e.getValue());
        }
        return o;
    }

    static Map<String, Const> unwrittenDefaults(Map<String, ClassNode> classes, boolean usesReflection) {
        Map<String, Const> o = new HashMap<>();
        if (usesReflection) return o;
        return unwrittenDefaultsFiltered(classes, Set.of());
    }

    static Map<String, Const> unwrittenDefaultsFiltered(Map<String, ClassNode> classes,
                                                        Set<String> reflective) {
        Map<String, Const> o = new HashMap<>();
        Map<String, Integer> writes = new HashMap<>();
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n.getOpcode() == Opcodes.PUTSTATIC && n instanceof FieldInsnNode f) {
                        writes.merge(resolveOwner(classes, f.owner, f.name), 1, Integer::sum);
                    }
                }
            }
        }
        for (ClassNode cn : classes.values()) {
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                if (reflective.contains(f.name)) continue;
                String key = cn.name + "." + f.name;
                if (writes.getOrDefault(key, 0) > 0) continue;
                Const c = constOfValue(f.value);
                if (c == null) c = defaultFor(f.desc);
                if (c != null) o.put(key, c);
            }
        }
        return o;
    }

    static int optimisticFold(Map<String, ClassNode> classes, boolean usesReflection) {
        if (usesReflection) return 0;
        return optimisticFoldFiltered(classes, Set.of());
    }

    static int optimisticFoldFiltered(Map<String, ClassNode> classes, Set<String> reflective) {
        if (hasNative(classes)) return 0;
        boolean debug = Boolean.getBoolean("zkmdeobf.debugOpt");
        Map<String, byte[]> snap = new HashMap<>();
        try {
            for (Map.Entry<String, ClassNode> e : classes.entrySet())
                snap.put(e.getKey(), ClassIO.toBytes(e.getValue()));
        } catch (Throwable t) {
            return 0;
        }
        Map<String, Integer> writes = countWrites(classes);
        Map<String, Const> hypo = new HashMap<>();
        for (ClassNode cn : classes.values()) {
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                if (reflective.contains(f.name)) continue;
                String key = cn.name + "." + f.name;
                if (writes.getOrDefault(key, 0) == 0) continue;
                Const seed = constOfValue(f.value);
                if (seed == null) seed = defaultFor(f.desc);
                if (seed != null) hypo.put(key, seed);
            }
        }
        if (hypo.isEmpty()) return 0;
        if (debug) System.err.println("[opt] hipotez=" + hypo.size());
        Set<String> used = new HashSet<>();
        constUseRecorder = used;
        int total = 0;
        try {
            for (int round = 0; round < 6; round++) {
                int n = 0;
                for (ClassNode cn : classes.values()) {
                    Map<String, Const> cc = new HashMap<>(hypo);
                    cc.putAll(clinitConstants(cn));
                    Map<String, String> gg = trivialGetters(cn);
                    for (MethodNode m : cn.methods) {
                        n += foldMethod(cn, m, cc, gg);
                        n += Rewriter.stripNops(m);
                        n += Rewriter.propagateCopies(classes, cn, m);

                        n += Rewriter.propagateHypoConsts(classes, cn, m, hypo);
                        n += Rewriter.removeDeadStores(cn, m);
                        n += Rewriter.removeDeadHypoStores(cn, m, hypo);
                        n += foldMethod(cn, m, cc, gg);
                        Rewriter.collapseGotos(m);
                        n += Rewriter.removeDeadCode(m);
                    }
                }
                total += n;
                if (n == 0) break;
            }
        } finally {
            constUseRecorder = null;
        }
        if (!validateOptimistic(classes, used)) {
            if (debug) {
                Map<String, Integer> w = countWrites(classes);
                List<String> bad = new ArrayList<>();
                for (String key : used)
                    if (w.getOrDefault(key, 0) > 0) bad.add(key + "=" + w.get(key));
                System.err.println("[opt] RET: tuketilen=" + used.size() + " kalan-yazimli=" + bad);
            }

            for (Map.Entry<String, ClassNode> e : classes.entrySet()) {
                byte[] b = snap.get(e.getKey());
                if (b == null) continue;
                try {
                    ClassNode fresh = new ClassNode();
                    new org.objectweb.asm.ClassReader(b).accept(fresh, 0);
                    e.getValue().fields.clear();
                    e.getValue().fields.addAll(fresh.fields);
                    e.getValue().methods.clear();
                    e.getValue().methods.addAll(fresh.methods);
                } catch (Throwable t) {
                    return 0;
                }
            }
            return 0;
        }
        return total;
    }

    private static boolean hasNative(Map<String, ClassNode> classes) {
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                if ((m.access & Opcodes.ACC_NATIVE) != 0) return true;
        return false;
    }

    private static Map<String, Integer> countWrites(Map<String, ClassNode> classes) {
        Map<String, Integer> o = new HashMap<>();
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n.getOpcode() == Opcodes.PUTSTATIC && n instanceof FieldInsnNode f)
                        o.merge(resolveOwner(classes, f.owner, f.name), 1, Integer::sum);
                }
            }
        }
        return o;
    }

    private static boolean validateOptimistic(Map<String, ClassNode> classes, Set<String> used) {
        if (used.isEmpty()) return true;
        Map<String, Integer> writes = countWrites(classes);
        Map<String, Map<String, Const>> clinits = new HashMap<>();
        for (ClassNode cn : classes.values()) clinits.put(cn.name, clinitConstants(cn));
        for (String key : used) {
            int dot = key.lastIndexOf('.');
            if (dot < 0) return false;
            String owner = key.substring(0, dot);
            Map<String, Const> cc = clinits.get(owner);
            if (cc != null && cc.containsKey(key)) continue;
            if (writes.getOrDefault(key, 0) == 0) continue;
            return false;
        }
        return true;
    }
    private static String resolveOwner(Map<String, ClassNode> classes, String owner, String name) {
        ClassNode cn = classes.get(owner + ".class");
        Set<String> seen = new HashSet<>();
        while (cn != null && seen.add(cn.name)) {
            for (FieldNode f : cn.fields) if (f.name.equals(name)) return cn.name + "." + name;
            cn = cn.superName == null ? null : classes.get(cn.superName + ".class");
        }
        return owner + "." + name;
    }

    private static Const constOfValue(Object v) {
        if (v instanceof Integer i) return new IntConst(i);
        if (v instanceof Long l) return new LongConst(l);
        if (v instanceof Float f) return new FloatConst(f);
        if (v instanceof Double d) return new DoubleConst(d);
        return null;
    }

    private static Const defaultFor(String desc) {
        return switch (desc.charAt(0)) {
            case 'Z', 'B', 'C', 'S', 'I' -> new IntConst(0);
            case 'J' -> new LongConst(0L);
            case 'F' -> new FloatConst(0f);
            case 'D' -> new DoubleConst(0d);
            case 'L', '[' -> new NullConst();
            default -> null;
        };
    }

    static Set<String> constUseRecorder = null;

    private static void noteUsed(AbstractInsnNode n) {
        if (constUseRecorder == null || !(n instanceof FieldInsnNode f)) return;
        if (n.getOpcode() == Opcodes.GETSTATIC) constUseRecorder.add(f.owner + "." + f.name);
    }
    private static Const constOf(AbstractInsnNode n) {
        Integer v = ClassIO.constInt(n);
        if (v != null) return new IntConst(v);
        if (n.getOpcode() == Opcodes.ACONST_NULL) return new NullConst();
        if (n.getOpcode() == Opcodes.LCONST_0) return new LongConst(0L);
        if (n.getOpcode() == Opcodes.LCONST_1) return new LongConst(1L);
        if (n instanceof LdcInsnNode l && l.cst instanceof Long lo) return new LongConst(lo);
        if (n.getOpcode() == Opcodes.FCONST_0) return new FloatConst(0f);
        if (n.getOpcode() == Opcodes.FCONST_1) return new FloatConst(1f);
        if (n.getOpcode() == Opcodes.FCONST_2) return new FloatConst(2f);
        if (n instanceof LdcInsnNode lf && lf.cst instanceof Float fo) return new FloatConst(fo);
        if (n.getOpcode() == Opcodes.DCONST_0) return new DoubleConst(0d);
        if (n.getOpcode() == Opcodes.DCONST_1) return new DoubleConst(1d);
        if (n instanceof LdcInsnNode ld && ld.cst instanceof Double doo) return new DoubleConst(doo);
        return null;
    }

    static Const constOfChain(List<AbstractInsnNode> ins, int k) {
        return constOfChain(ins, k, 0);
    }

    private static Const constOfChain(List<AbstractInsnNode> ins, int k, int depth) {
        if (k < 0 || k >= ins.size() || depth > 8) return null;
        AbstractInsnNode n = ins.get(k);
        Const direct = constOf(n);
        if (direct != null) return direct;
        int op = n.getOpcode();
        boolean isIntOp = op == Opcodes.IADD || op == Opcodes.ISUB || op == Opcodes.IMUL
                || op == Opcodes.IDIV || op == Opcodes.IREM || op == Opcodes.IAND
                || op == Opcodes.IOR || op == Opcodes.IXOR;
        boolean isLongOp = op == Opcodes.LADD || op == Opcodes.LSUB || op == Opcodes.LMUL
                || op == Opcodes.LAND || op == Opcodes.LOR || op == Opcodes.LXOR;
        if (!isIntOp && !isLongOp) return null;
        int kb = prevProducing(ins, k - 1);
        if (kb < 0) return null;
        Const rb = constOfChain(ins, kb, depth + 1);
        if (rb == null) return null;
        int ka = prevProducing(ins, kb - 1);
        if (ka < 0) return null;
        Const ra = constOfChain(ins, ka, depth + 1);
        if (ra == null) return null;
        if (isIntOp && ra instanceof IntConst a && rb instanceof IntConst b) {
            Integer r = switch (op) {
                case Opcodes.IADD -> a.v() + b.v();
                case Opcodes.ISUB -> a.v() - b.v();
                case Opcodes.IMUL -> a.v() * b.v();
                case Opcodes.IDIV -> b.v() != 0 ? a.v() / b.v() : null;
                case Opcodes.IREM -> b.v() != 0 ? a.v() % b.v() : null;
                case Opcodes.IAND -> a.v() & b.v();
                case Opcodes.IOR -> a.v() | b.v();
                default -> a.v() ^ b.v();
            };
            return r == null ? null : new IntConst(r);
        }
        if (isLongOp && ra instanceof LongConst a && rb instanceof LongConst b) {
            long r = switch (op) {
                case Opcodes.LADD -> a.v() + b.v();
                case Opcodes.LSUB -> a.v() - b.v();
                case Opcodes.LMUL -> a.v() * b.v();
                case Opcodes.LAND -> a.v() & b.v();
                case Opcodes.LOR -> a.v() | b.v();
                default -> a.v() ^ b.v();
            };
            return new LongConst(r);
        }
        return null;
    }

    private static int prevProducing(List<AbstractInsnNode> ins, int k) {
        for (int j = k; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            return j;
        }
        return -1;
    }

    public static Map<String, String> trivialGetters(ClassNode cn) {
        Map<String, String> o = new HashMap<>();
        for (MethodNode m : cn.methods) {
            if (!m.desc.startsWith("()") || (m.access & Opcodes.ACC_STATIC) == 0) continue;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            List<AbstractInsnNode> real = new ArrayList<>();
            for (AbstractInsnNode n : ins) {
                if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
                real.add(n);
            }
            if (real.size() == 2 && real.get(0).getOpcode() == Opcodes.GETSTATIC
                    && real.get(0) instanceof FieldInsnNode
                    && (real.get(1).getOpcode() >= Opcodes.IRETURN && real.get(1).getOpcode() <= Opcodes.ARETURN)) {
                FieldInsnNode f = (FieldInsnNode) real.get(0);
                o.put(cn.name + "." + m.name + m.desc, f.owner + "." + f.name);
            }
        }
        return o;
    }

    public static int foldMethod(ClassNode cn, MethodNode m,
                                 Map<String, Const> consts, Map<String, String> getters) {
        if (Rewriter.hasJsrRet(m)) return 0;
        int n = 0;
        n += foldBranches(cn, m, consts, getters);
        n += foldConstants(m);
        n += foldLongConstants(m);
        n += foldJumps(m);
        n += foldSwitches(m);
        return n;
    }

    static int foldConstants(MethodNode m) {
        int n = 0;
        boolean changed = true;
        while (changed) {
            changed = false;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            for (int k = 2; k < ins.size(); k++) {
                AbstractInsnNode c = ins.get(k);
                int op = c.getOpcode();
                if (op != Opcodes.IADD && op != Opcodes.ISUB && op != Opcodes.IMUL
                        && op != Opcodes.IDIV && op != Opcodes.IREM
                        && op != Opcodes.IAND && op != Opcodes.IOR && op != Opcodes.IXOR
                        && op != Opcodes.ISHL && op != Opcodes.ISHR && op != Opcodes.IUSHR) continue;
                Integer b = ClassIO.constInt(ins.get(k - 1));
                Integer a = ClassIO.constInt(ins.get(k - 2));
                if (a == null || b == null) continue;

                if (!rangeClean(m, ins.get(k - 2), c)) continue;
                Integer r = switch (op) {
                    case Opcodes.IADD -> a + b;
                    case Opcodes.ISUB -> a - b;
                    case Opcodes.IMUL -> a * b;
                    case Opcodes.IDIV -> b != 0 ? a / b : null;
                    case Opcodes.IREM -> b != 0 ? a % b : null;
                    case Opcodes.IAND -> a & b;
                    case Opcodes.IOR -> a | b;
                    case Opcodes.IXOR -> a ^ b;
                    case Opcodes.ISHL -> a << (b & 31);
                    case Opcodes.ISHR -> a >> (b & 31);
                    default -> a >>> (b & 31);
                };
                if (r == null) continue;
                AbstractInsnNode first = ins.get(k - 2);
                AbstractInsnNode second = ins.get(k - 1);
                LdcInsnNode ldc = new LdcInsnNode(r);
                m.instructions.insertBefore(first, ldc);
                m.instructions.remove(first);
                m.instructions.remove(second);
                m.instructions.remove(c);
                n++;
                changed = true;
                break;
            }
        }
        return n;
    }

    static int foldLongConstants(MethodNode m) {
        int n = 0;
        boolean changed = true;
        while (changed) {
            changed = false;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            for (int k = 2; k < ins.size(); k++) {
                AbstractInsnNode c = ins.get(k);
                int op = c.getOpcode();
                if (op != Opcodes.LADD && op != Opcodes.LSUB && op != Opcodes.LMUL
                        && op != Opcodes.LAND && op != Opcodes.LOR && op != Opcodes.LXOR) continue;
                Long b = constLong(ins.get(k - 1));
                Long a = constLong(ins.get(k - 2));
                if (a == null || b == null) continue;
                if (!rangeClean(m, ins.get(k - 2), c)) continue;
                long r = switch (op) {
                    case Opcodes.LADD -> a + b;
                    case Opcodes.LSUB -> a - b;
                    case Opcodes.LMUL -> a * b;
                    case Opcodes.LAND -> a & b;
                    case Opcodes.LOR -> a | b;
                    default -> a ^ b;
                };
                AbstractInsnNode first = ins.get(k - 2);
                AbstractInsnNode second = ins.get(k - 1);
                LdcInsnNode ldc = new LdcInsnNode(r);
                m.instructions.insertBefore(first, ldc);
                m.instructions.remove(first);
                m.instructions.remove(second);
                m.instructions.remove(c);
                n++;
                changed = true;
                break;
            }
        }
        return n;
    }

    private static Long constLong(AbstractInsnNode n) {
        if (n.getOpcode() == Opcodes.LCONST_0) return 0L;
        if (n.getOpcode() == Opcodes.LCONST_1) return 1L;
        if (n instanceof LdcInsnNode l && l.cst instanceof Long lo) return lo;
        return null;
    }

    static int foldJumps(MethodNode m) {
        int n = 0;
        List<AbstractInsnNode> ins = ClassIO.list(m);
        for (int k = 1; k < ins.size(); k++) {
            AbstractInsnNode cur = ins.get(k);
            if (!(cur instanceof JumpInsnNode j)) continue;
            int op = cur.getOpcode();
            if (op < Opcodes.IFEQ || op > Opcodes.IFLE) continue;
            Integer cv = ClassIO.constInt(ins.get(k - 1));
            if (cv == null) continue;
            if (!rangeClean(m, ins.get(k - 1), cur)) continue;
            boolean taken = switch (op) {
                case Opcodes.IFEQ -> cv == 0;
                case Opcodes.IFNE -> cv != 0;
                case Opcodes.IFLT -> cv < 0;
                case Opcodes.IFGE -> cv >= 0;
                case Opcodes.IFGT -> cv > 0;
                default -> cv <= 0;
            };
            m.instructions.remove(ins.get(k - 1));
            if (taken) m.instructions.set(cur, new JumpInsnNode(Opcodes.GOTO, j.label));
            else m.instructions.remove(cur);
            n += 2;
            ins = ClassIO.list(m);
            k = 0;
        }
        return n;
    }

    static int foldSwitches(MethodNode m) {
        int n = 0;
        List<AbstractInsnNode> ins = ClassIO.list(m);
        for (int k = 1; k < ins.size(); k++) {
            AbstractInsnNode cur = ins.get(k);
            LabelNode tgt = null;
            if (cur instanceof TableSwitchInsnNode t) {
                Integer cv = ClassIO.constInt(ins.get(k - 1));
                if (cv == null) continue;
                tgt = (cv >= t.min && cv <= t.max) ? t.labels.get(cv - t.min) : t.dflt;
            } else if (cur instanceof LookupSwitchInsnNode t) {
                Integer cv = ClassIO.constInt(ins.get(k - 1));
                if (cv == null) continue;
                tgt = t.dflt;
                for (int i = 0; i < t.keys.size(); i++)
                    if (t.keys.get(i) == cv) { tgt = t.labels.get(i); break; }
            } else {
                continue;
            }
            if (!rangeClean(m, ins.get(k - 1), cur)) continue;
            m.instructions.remove(ins.get(k - 1));
            m.instructions.set(cur, new JumpInsnNode(Opcodes.GOTO, tgt));
            n += 2;
            ins = ClassIO.list(m);
            k = 0;
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

    static int foldBranches(ClassNode cn, MethodNode m,
                            Map<String, Const> consts, Map<String, String> getters) {
        if (Rewriter.hasJsrRet(m)) return 0;
        int n = 0;
        List<AbstractInsnNode> ins = ClassIO.list(m);
        for (int k = 0; k < ins.size(); k++) {
            AbstractInsnNode cur = ins.get(k);
            int op = cur.getOpcode();
            if (!(cur instanceof JumpInsnNode)) continue;
            if (op < Opcodes.IFEQ || op > Opcodes.IF_ACMPNE) continue;
            JumpInsnNode j = (JumpInsnNode) cur;
            Const c = null;
            List<AbstractInsnNode> operands = new ArrayList<>();
            AbstractInsnNode prev = prevReal(ins, k);
            if (op >= Opcodes.IFEQ && op <= Opcodes.IFLE && prev != null
                    && prev.getOpcode() == Opcodes.LCMP) {

                int pi = indexOf(ins, prev);
                AbstractInsnNode qb = prevReal(ins, pi);
                AbstractInsnNode qa = qb == null ? null : prevReal(ins, indexOf(ins, qb));
                Long va = longOperand(cn, consts, qa);
                Long vb = longOperand(cn, consts, qb);
                if (va != null && vb != null) {
                    int cmp = Long.compare(va, vb);
                    boolean taken = switch (op) {
                        case Opcodes.IFEQ -> cmp == 0;
                        case Opcodes.IFNE -> cmp != 0;
                        case Opcodes.IFLT -> cmp < 0;
                        case Opcodes.IFGE -> cmp >= 0;
                        case Opcodes.IFGT -> cmp > 0;
                        default -> cmp <= 0;
                    };
                    List<AbstractInsnNode> ops2 = new ArrayList<>();
                    if (isProducedOperand(qa)) ops2.add(qa);
                    if (isProducedOperand(qb)) ops2.add(qb);
                    ops2.add(prev);
                    noteUsed(qa);
                    noteUsed(qb);
                    takenHelper(m, j, ops2, taken);
                    n += ops2.size() + 1;
                    ins = ClassIO.list(m);
                    k = -1;
                    continue;
                }
            }
            if (op >= Opcodes.IFEQ && op <= Opcodes.IFLE && prev != null
                    && (prev.getOpcode() == Opcodes.FCMPL || prev.getOpcode() == Opcodes.FCMPG
                        || prev.getOpcode() == Opcodes.DCMPL || prev.getOpcode() == Opcodes.DCMPG)) {

                int pi = indexOf(ins, prev);
                AbstractInsnNode qb = prevReal(ins, pi);
                AbstractInsnNode qa = qb == null ? null : prevReal(ins, indexOf(ins, qb));
                Double va = doubleOperand(cn, consts, qa);
                Double vb = doubleOperand(cn, consts, qb);
                if (va != null && vb != null) {
                    int cmp;
                    boolean nan = va.isNaN() || vb.isNaN();
                    if (nan) cmp = (prev.getOpcode() == Opcodes.FCMPG || prev.getOpcode() == Opcodes.DCMPG) ? 1 : -1;
                    else cmp = Double.compare(va, vb);
                    boolean taken = switch (op) {
                        case Opcodes.IFEQ -> cmp == 0;
                        case Opcodes.IFNE -> cmp != 0;
                        case Opcodes.IFLT -> cmp < 0;
                        case Opcodes.IFGE -> cmp >= 0;
                        case Opcodes.IFGT -> cmp > 0;
                        default -> cmp <= 0;
                    };
                    List<AbstractInsnNode> ops2 = new ArrayList<>();
                    if (isProducedDouble(qa)) ops2.add(qa);
                    if (isProducedDouble(qb)) ops2.add(qb);
                    ops2.add(prev);
                    noteUsed(qa);
                    noteUsed(qb);
                    takenHelper(m, j, ops2, taken);
                    n += ops2.size() + 1;
                    ins = ClassIO.list(m);
                    k = -1;
                    continue;
                }
            }
            if (op >= Opcodes.IF_ICMPEQ && op <= Opcodes.IF_ICMPLE && prev != null) {

                Integer cv = ClassIO.constInt(prev);
                AbstractInsnNode p2 = cv == null ? null : prevReal(ins, indexOf(ins, prev));
                FieldInsnNode ff = (p2 != null && p2.getOpcode() == Opcodes.GETSTATIC
                        && p2 instanceof FieldInsnNode) ? (FieldInsnNode) p2 : null;
                if (ff != null) {
                    c = consts.get(ff.owner + "." + ff.name);
                    if (c instanceof IntConst) {
                        Boolean t = evalIcmp(op, ((IntConst) c).v(), cv);
                        if (t != null) {
                            operands.add(prev);
                            operands.add(p2);
                            noteUsed(p2);
                            takenHelper(m, j, operands, t);
                            n += operands.size() + 1;
                            continue;
                        }
                    }
                }
            }
            String usedKey = null;

            AbstractInsnNode eff = null;
            if (op >= Opcodes.IFEQ && op <= Opcodes.IFLE) {
                eff = Rewriter.findProducerWords(m, ins, k, 1);
            }
            if (eff != null) {
                if (eff.getOpcode() == Opcodes.GETSTATIC && eff instanceof FieldInsnNode) {
                    FieldInsnNode f = (FieldInsnNode) eff;
                    c = consts.get(f.owner + "." + f.name);
                    if (c != null) { operands.add(eff); usedKey = f.owner + "." + f.name; }
                } else if (eff.getOpcode() == Opcodes.INVOKESTATIC && eff instanceof MethodInsnNode) {
                    MethodInsnNode mi = (MethodInsnNode) eff;
                    String fk = getters.get(mi.owner + "." + mi.name + mi.desc);
                    if (fk != null) c = consts.get(fk);
                    if (c != null) { operands.add(eff); usedKey = fk; }
                }
            }
            if (c == null && op >= Opcodes.IFEQ && op <= Opcodes.IFLE) {

                AbstractInsnNode p2 = prev;
                if (p2 != null && (p2.getOpcode() == Opcodes.NOP || p2 instanceof IincInsnNode))
                    p2 = prevSkippingNeutral(ins, k);
                if (p2 != null && p2.getOpcode() == Opcodes.GETSTATIC && p2 instanceof FieldInsnNode) {
                    FieldInsnNode f = (FieldInsnNode) p2;
                    c = consts.get(f.owner + "." + f.name);
                    if (c != null) { operands.add(p2); usedKey = f.owner + "." + f.name; }
                } else if (p2 != null && p2.getOpcode() == Opcodes.INVOKESTATIC
                        && p2 instanceof MethodInsnNode) {
                    MethodInsnNode mi = (MethodInsnNode) p2;
                    String fk = getters.get(mi.owner + "." + mi.name + mi.desc);
                    if (fk != null) c = consts.get(fk);
                    if (c != null) { operands.add(p2); usedKey = fk; }
                }
            }
            if (c == null) continue;
            Boolean taken = evalBranch(op, c, null);
            if (taken == null) continue;
            if (usedKey != null && constUseRecorder != null) constUseRecorder.add(usedKey);

            for (AbstractInsnNode o : operands) m.instructions.remove(o);
            n += operands.size();
            if (taken) {
                JumpInsnNode g = new JumpInsnNode(Opcodes.GOTO, j.label);
                m.instructions.set(j, g);
                n++;
            } else {
                m.instructions.remove(j);
                n++;
            }
        }
        return n;
    }

    private static void takenHelper(MethodNode m, JumpInsnNode j,
                                      List<AbstractInsnNode> operands, boolean taken) {
        for (AbstractInsnNode o : operands) m.instructions.remove(o);
        if (taken) m.instructions.set(j, new JumpInsnNode(Opcodes.GOTO, j.label));
        else m.instructions.remove(j);
    }

    private static Long longOperand(ClassNode cn, Map<String, Const> consts, AbstractInsnNode n) {
        if (n == null) return null;
        Long c = constLong(n);
        if (c != null) return c;
        if (n.getOpcode() == Opcodes.GETSTATIC && n instanceof FieldInsnNode f) {
            Const k = consts.get(f.owner + "." + f.name);
            if (k instanceof LongConst lc) return lc.v();
        }
        return null;
    }

    private static boolean isProducedOperand(AbstractInsnNode n) {
        if (n == null) return false;
        if (constLong(n) != null) return true;
        return n.getOpcode() == Opcodes.GETSTATIC;
    }

    private static Double doubleOperand(ClassNode cn, Map<String, Const> consts, AbstractInsnNode n) {
        if (n == null) return null;
        if (n.getOpcode() == Opcodes.FCONST_0) return 0d;
        if (n.getOpcode() == Opcodes.FCONST_1) return 1d;
        if (n.getOpcode() == Opcodes.FCONST_2) return 2d;
        if (n.getOpcode() == Opcodes.DCONST_0) return 0d;
        if (n.getOpcode() == Opcodes.DCONST_1) return 1d;
        if (n instanceof LdcInsnNode l) {
            if (l.cst instanceof Float f) return (double) f;
            if (l.cst instanceof Double d) return d;
            if (l.cst instanceof Integer i) return (double) i;
            if (l.cst instanceof Long lo) return (double) lo;
        }
        if (n.getOpcode() == Opcodes.GETSTATIC && n instanceof FieldInsnNode f) {
            Const k = consts.get(f.owner + "." + f.name);
            if (k instanceof DoubleConst dc) return dc.v();
            if (k instanceof FloatConst fc) return (double) fc.v();
            if (k instanceof IntConst ic) return (double) ic.v();
            if (k instanceof LongConst lc) return (double) lc.v();
        }
        return null;
    }

    private static boolean isProducedDouble(AbstractInsnNode n) {
        if (n == null) return false;
        int op = n.getOpcode();
        if (op == Opcodes.FCONST_0 || op == Opcodes.FCONST_1 || op == Opcodes.FCONST_2
                || op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1) return true;
        if (n instanceof LdcInsnNode l
                && (l.cst instanceof Float || l.cst instanceof Double
                    || l.cst instanceof Integer || l.cst instanceof Long)) return true;
        return op == Opcodes.GETSTATIC;
    }

    private static int indexOf(List<AbstractInsnNode> ins, AbstractInsnNode n) {
        for (int i = 0; i < ins.size(); i++) if (ins.get(i) == n) return i;
        return -1;
    }

    private static AbstractInsnNode prevReal(List<AbstractInsnNode> ins, int k) {
        for (int j = k - 1; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (!(n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode)) return n;
        }
        return null;
    }

    private static AbstractInsnNode prevSkippingNeutral(List<AbstractInsnNode> ins, int k) {
        for (int j = k - 1; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            int op = n.getOpcode();
            if (op == Opcodes.NOP) continue;
            if (n instanceof IincInsnNode) continue;
            return n;
        }
        return null;
    }

    private static Boolean evalBranch(int op, Const c, Void unused) {
        if (c instanceof IntConst v) {
            int x = v.v();
            return switch (op) {
                case Opcodes.IFEQ -> x == 0;
                case Opcodes.IFNE -> x != 0;
                case Opcodes.IFLT -> x < 0;
                case Opcodes.IFGE -> x >= 0;
                case Opcodes.IFGT -> x > 0;
                case Opcodes.IFLE -> x <= 0;
                default -> null;
            };
        }
        if (c instanceof NullConst) {
            return switch (op) {
                case Opcodes.IFNULL -> true;
                case Opcodes.IFNONNULL -> false;
                default -> null;
            };
        }
        return null;
    }

    private static Boolean evalIcmp(int op, int a, int b) {
        return switch (op) {
            case Opcodes.IF_ICMPEQ -> a == b;
            case Opcodes.IF_ICMPNE -> a != b;
            case Opcodes.IF_ICMPLT -> a < b;
            case Opcodes.IF_ICMPGE -> a >= b;
            case Opcodes.IF_ICMPGT -> a > b;
            case Opcodes.IF_ICMPLE -> a <= b;
            default -> null;
        };
    }
}
