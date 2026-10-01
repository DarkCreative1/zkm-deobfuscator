package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class Rewriter {
    private Rewriter() {}

    public static boolean hasJsrRet(MethodNode m) {
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            int op = n.getOpcode();
            if (op == Opcodes.JSR || op == Opcodes.RET) return true;
        }
        return false;
    }

    public static boolean inlineJsr(MethodNode m) {
        if (!hasJsrRet(m)) return false;
        try {
            MethodNode out = new MethodNode(m.access, m.name, m.desc, m.signature,
                    (String[]) (m.exceptions == null ? null : m.exceptions.toArray(new String[0])));
            m.accept(new org.objectweb.asm.commons.JSRInlinerAdapter(out,
                    m.access, m.name, m.desc, m.signature,
                    (String[]) (m.exceptions == null ? null : m.exceptions.toArray(new String[0]))));
            m.instructions = out.instructions;
            m.tryCatchBlocks = out.tryCatchBlocks;
            m.localVariables = out.localVariables;
            m.visibleLocalVariableAnnotations = out.visibleLocalVariableAnnotations;
            m.invisibleLocalVariableAnnotations = out.invisibleLocalVariableAnnotations;
            m.maxStack = out.maxStack;
            m.maxLocals = out.maxLocals;
            return !hasJsrRet(m);
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean patchCallSite(MethodNode m, AbstractInsnNode from,
                                        AbstractInsnNode invoke, Object constant) {
        if (hasJsrRet(m)) return false;
        if (!(constant instanceof String || constant instanceof Integer || constant instanceof Long
                || constant instanceof Float || constant instanceof Double)) return false;

        boolean reach = false;
        for (AbstractInsnNode n = from; n != null; n = n.getNext()) {
            if (n == invoke) { reach = true; break; }
        }
        if (!reach) return false;

        Set<LabelNode> bounds = new HashSet<>();
        if (m.tryCatchBlocks != null) {
            for (TryCatchBlockNode t : m.tryCatchBlocks) {
                bounds.add(t.start);
                bounds.add(t.end);
                bounds.add(t.handler);
            }
        }
        AbstractInsnNode n = from.getNext();
        while (n != null && n != invoke.getNext()) {
            if (n instanceof LabelNode && bounds.contains(n)) return false;
            if (ClassIO.jumpTargets(m).contains(n)) return false;
            n = n.getNext();
        }

        LdcInsnNode ldc = new LdcInsnNode(constant);
        m.instructions.insertBefore(from, ldc);
        n = from;
        while (true) {
            AbstractInsnNode nx = n.getNext();
            if (n.getOpcode() >= 0) m.instructions.remove(n);
            if (n == invoke) break;
            n = nx;
        }
        return true;
    }

    public static boolean patchCallSiteKeepMiddle(MethodNode m, AbstractInsnNode argPush,
                                                  AbstractInsnNode keyPush,
                                                  AbstractInsnNode invoke, Object constant) {
        if (hasJsrRet(m)) return false;
        if (!(constant instanceof String || constant instanceof Integer || constant instanceof Long
                || constant instanceof Float || constant instanceof Double)) return false;
        if (argPush == null || keyPush == null || invoke == null) return false;

        Set<LabelNode> bounds = new HashSet<>();
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            bounds.add(t.start); bounds.add(t.end); bounds.add(t.handler);
        }
        Set<LabelNode> tgts = ClassIO.jumpTargets(m);
        for (AbstractInsnNode x = argPush; x != null && x != invoke.getNext(); x = x.getNext()) {
            if (x instanceof LabelNode && (bounds.contains(x) || tgts.contains(x))) return false;
        }
        m.instructions.insertBefore(argPush, new LdcInsnNode(constant));
        m.instructions.remove(argPush);
        m.instructions.remove(keyPush);
        m.instructions.remove(invoke);
        return true;
    }

    public static int stripFakeHandlers(ClassNode cn, MethodNode m) {
        if (m.tryCatchBlocks == null || m.tryCatchBlocks.isEmpty()) return 0;
        Set<LabelNode> targets = ClassIO.jumpTargets(m);
        List<TryCatchBlockNode> dead = new ArrayList<>();
        Map<LabelNode, AbstractInsnNode> athrowAt = new HashMap<>();
        for (TryCatchBlockNode t : m.tryCatchBlocks) {
            if (t.type == null) continue;
            AbstractInsnNode cur = nextReal(t.handler);
            if (cur != null && cur.getOpcode() == Opcodes.ATHROW) {
                AbstractInsnNode nx = nextReal(cur);

                if (nx == null || nx instanceof LabelNode) {
                    dead.add(t);
                    athrowAt.put(t.handler, cur);
                }
            }
        }
        for (TryCatchBlockNode t : dead) m.tryCatchBlocks.remove(t);

        Set<LabelNode> stillUsed = new HashSet<>();
        if (m.tryCatchBlocks != null)
            for (TryCatchBlockNode t : m.tryCatchBlocks) stillUsed.add(t.handler);
        stillUsed.addAll(targets);
        for (Map.Entry<LabelNode, AbstractInsnNode> e : athrowAt.entrySet()) {
            if (!stillUsed.contains(e.getKey())) m.instructions.remove(e.getValue());
        }
        return dead.size();
    }

    private static AbstractInsnNode nextReal(AbstractInsnNode from) {
        AbstractInsnNode n = from.getNext();
        while (n != null && (n instanceof LineNumberNode || n instanceof FrameNode)) n = n.getNext();
        return n;
    }

    public static int stripNops(MethodNode m) {
        if (hasJsrRet(m)) return 0;
        List<AbstractInsnNode> del = new ArrayList<>();
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() == Opcodes.NOP) del.add(n);
        }
        for (AbstractInsnNode d : del) m.instructions.remove(d);
        return del.size();
    }

    public static int propagateCopies(MethodNode m) {
        return propagateCopies(null, null, m);
    }

    public static int propagateCopies(Map<String, ClassNode> classes, ClassNode cn, MethodNode m) {
        if (hasJsrRet(m)) return 0;
        Map<String, Set<String>> modCache = new HashMap<>();
        Set<LabelNode> blocking = blockingLabels(m);
        int paramSlots = (m.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        for (Type t : Type.getArgumentTypes(m.desc)) paramSlots += t.getSize();
        int n = 0;
        boolean changed = true;
        int iter = 0;
        while (changed && iter++ < 10) {
            changed = false;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            for (int k = 0; k < ins.size(); k++) {
                AbstractInsnNode st = ins.get(k);
                if (!(st instanceof VarInsnNode vs) || !isStore(st.getOpcode())) continue;
                int y = vs.var;
                if (countStores(ins, y) != 1 || y < paramSlots) continue;
                AbstractInsnNode prod = findProducer(m, ins, k);
                if (prod == null) {
                    if (Boolean.getBoolean("zkmdeobf.debugCopy")) System.err.println("[copy] k=" + k + " producer-missing");
                    continue;
                }

                if (!propagatable(prod, st.getOpcode())) {
                    if (Boolean.getBoolean("zkmdeobf.debugCopy")) System.err.println("[copy] k=" + k + " type-mismatch");
                    continue;
                }
                int pk = ins.indexOf(prod);

                boolean preLoad = false;
                for (int j = 0; j < pk; j++) {
                    AbstractInsnNode u = ins.get(j);
                    if (u instanceof VarInsnNode vu && vu.var == y && isLoad(u.getOpcode())) {
                        preLoad = true;
                        break;
                    }
                }
                if (preLoad) continue;

                List<AbstractInsnNode> loads = new ArrayList<>();
                boolean ok = true;
                for (int j = k + 1; j < ins.size(); j++) {
                    AbstractInsnNode u = ins.get(j);
                    if (u instanceof LabelNode && !blocking.contains(u)) continue;
                    if (u instanceof VarInsnNode vu && vu.var == y) {
                        if (!isLoad(u.getOpcode()) || !loadCompatible(prod, u.getOpcode())) {
                            ok = false;
                            break;
                        }
                        loads.add(u);
                    }
                    if (killsProducer(ins, prod, st, k, j)) { ok = false; break; }

                    if (prod instanceof FieldInsnNode pf && prod.getOpcode() == Opcodes.GETSTATIC
                            && (u instanceof MethodInsnNode || u instanceof InvokeDynamicInsnNode)
                            && callMayWrite(classes, modCache, u, pf.owner, pf.name)) {
                        ok = false;
                        break;
                    }

                    if (prod instanceof FieldInsnNode pf2 && prod.getOpcode() == Opcodes.GETSTATIC
                            && (cn == null || !pf2.owner.equals(cn.name))
                            && tryCovered(m, ins, ins.indexOf(prod), j)) {
                        ok = false;
                        break;
                    }
                    if (isBlockEnd(u, blocking)) {
                        for (int q = j; q < ins.size(); q++) {
                            AbstractInsnNode w = ins.get(q);
                            if (w instanceof VarInsnNode vw && vw.var == y && isLoad(w.getOpcode())) {
                                ok = false;
                                break;
                            }
                        }
                        break;
                    }
                }
                if (!ok || loads.isEmpty()) {
                    if (Boolean.getBoolean("zkmdeobf.debugCopy"))
                        System.err.println("[copy] k=" + k + " ok=" + ok + " loads=" + loads.size());
                    continue;
                }
                for (AbstractInsnNode ld : loads) {
                    m.instructions.insertBefore(ld, cloneProducer(prod));
                    m.instructions.remove(ld);
                    n++;
                }
                m.instructions.remove(prod);
                m.instructions.remove(st);
                n += 2;
                changed = true;
                break;
            }
        }
        return n;
    }

    private static boolean propagatable(AbstractInsnNode prod, int storeOp) {
        if (prod instanceof VarInsnNode v && isLoad(prod.getOpcode()))
            return sameKind(prod.getOpcode(), storeOp);
        if (prod instanceof FieldInsnNode f && prod.getOpcode() == Opcodes.GETSTATIC)
            return loadCompatibleForDesc(f.desc, storeOp);
        if (prod instanceof LdcInsnNode l)
            return loadCompatibleForConst(l.cst, storeOp);
        int op = prod.getOpcode();
        return (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5 && storeOp == Opcodes.ISTORE)
                || (op == Opcodes.BIPUSH && storeOp == Opcodes.ISTORE)
                || (op == Opcodes.SIPUSH && storeOp == Opcodes.ISTORE)
                || (op == Opcodes.ACONST_NULL && storeOp == Opcodes.ASTORE)
                || ((op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1) && storeOp == Opcodes.LSTORE)
                || ((op == Opcodes.FCONST_0 || op == Opcodes.FCONST_1 || op == Opcodes.FCONST_2)
                    && storeOp == Opcodes.FSTORE)
                || ((op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1) && storeOp == Opcodes.DSTORE);
    }

    private static boolean loadCompatible(AbstractInsnNode prod, int loadOp) {
        if (prod instanceof VarInsnNode v) return loadOp == prod.getOpcode();
        if (prod instanceof FieldInsnNode f && prod.getOpcode() == Opcodes.GETSTATIC)
            return loadCompatibleForDesc(f.desc, loadOp == Opcodes.ILOAD ? Opcodes.ISTORE
                    : loadOp == Opcodes.LLOAD ? Opcodes.LSTORE
                    : loadOp == Opcodes.FLOAD ? Opcodes.FSTORE
                    : loadOp == Opcodes.DLOAD ? Opcodes.DSTORE : Opcodes.ASTORE);
        if (prod instanceof LdcInsnNode l) {
            Object c = l.cst;
            return (c instanceof Integer && loadOp == Opcodes.ILOAD)
                    || (c instanceof Long && loadOp == Opcodes.LLOAD)
                    || (c instanceof Float && loadOp == Opcodes.FLOAD)
                    || (c instanceof Double && loadOp == Opcodes.DLOAD)
                    || ((c instanceof String || c instanceof Type) && loadOp == Opcodes.ALOAD);
        }
        int op = prod.getOpcode();
        return (op >= Opcodes.ICONST_M1 && op <= Opcodes.SIPUSH && loadOp == Opcodes.ILOAD)
                || (op == Opcodes.ACONST_NULL && loadOp == Opcodes.ALOAD)
                || ((op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1) && loadOp == Opcodes.LLOAD)
                || ((op == Opcodes.FCONST_0 || op == Opcodes.FCONST_1 || op == Opcodes.FCONST_2)
                    && loadOp == Opcodes.FLOAD)
                || ((op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1) && loadOp == Opcodes.DLOAD);
    }

    private static boolean loadCompatibleForDesc(String desc, int storeOp) {
        return switch (desc.charAt(0)) {
            case 'Z', 'B', 'C', 'S', 'I' -> storeOp == Opcodes.ISTORE;
            case 'J' -> storeOp == Opcodes.LSTORE;
            case 'F' -> storeOp == Opcodes.FSTORE;
            case 'D' -> storeOp == Opcodes.DSTORE;
            default -> storeOp == Opcodes.ASTORE;
        };
    }

    private static boolean loadCompatibleForConst(Object c, int storeOp) {
        return (c instanceof Integer && storeOp == Opcodes.ISTORE)
                || (c instanceof Long && storeOp == Opcodes.LSTORE)
                || (c instanceof Float && storeOp == Opcodes.FSTORE)
                || (c instanceof Double && storeOp == Opcodes.DSTORE)
                || ((c instanceof String || c instanceof Type) && storeOp == Opcodes.ASTORE);
    }

    private static AbstractInsnNode cloneProducer(AbstractInsnNode prod) {
        if (prod instanceof VarInsnNode v) return new VarInsnNode(prod.getOpcode(), v.var);
        if (prod instanceof FieldInsnNode f)
            return new FieldInsnNode(prod.getOpcode(), f.owner, f.name, f.desc);
        if (prod instanceof LdcInsnNode l) return new LdcInsnNode(l.cst);
        if (prod instanceof IntInsnNode x) return new IntInsnNode(prod.getOpcode(), x.operand);
        return new InsnNode(prod.getOpcode());
    }

    private static boolean killsProducer(List<AbstractInsnNode> ins, AbstractInsnNode prod,
                                         AbstractInsnNode st, int storeIdx, int j) {
        if (prod instanceof VarInsnNode v) {
            AbstractInsnNode u = ins.get(j);
            return u instanceof VarInsnNode vu && vu.var == v.var && isStore(u.getOpcode())
                    || u instanceof IincInsnNode ii && ii.var == v.var;
        }
        if (prod instanceof FieldInsnNode f && prod.getOpcode() == Opcodes.GETSTATIC) {
            AbstractInsnNode u = ins.get(j);
            return u instanceof FieldInsnNode fu && u.getOpcode() == Opcodes.PUTSTATIC
                    && fu.owner.equals(f.owner) && fu.name.equals(f.name);
        }
        return false;
    }

    private static boolean isBlockEnd(AbstractInsnNode u) {
        return u instanceof LabelNode || u.getOpcode() == Opcodes.ATHROW
                || u.getOpcode() == Opcodes.RET
                || (u.getOpcode() >= Opcodes.IRETURN && u.getOpcode() <= Opcodes.RETURN)
                || u instanceof JumpInsnNode || u instanceof TableSwitchInsnNode
                || u instanceof LookupSwitchInsnNode;
    }

    private static boolean callMayWrite(Map<String, ClassNode> classes,
                                        Map<String, Set<String>> cache,
                                        AbstractInsnNode u, String owner, String name) {
        if (u instanceof InvokeDynamicInsnNode id)
            return !id.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory");
        if (!(u instanceof MethodInsnNode mi)) return false;
        if (isPureWrtStatics(u)) return false;

        if (isReflectiveApi(mi)) return true;
        boolean fieldIsApp = !owner.startsWith("java/")
                && !owner.startsWith("javax/") && !owner.startsWith("jdk/")
                && !owner.startsWith("sun/");
        boolean callIsJdk = mi.owner.startsWith("java/") || mi.owner.startsWith("javax/")
                || mi.owner.startsWith("jdk/") || mi.owner.startsWith("sun/");

        if (callIsJdk && fieldIsApp) return false;
        if (classes == null) return true;

        ClassNode target = classes.get(mi.owner + ".class");
        if (target == null) {

            return true;
        }
        return modSet(classes, cache, target, new HashSet<>()).contains(owner + "." + name);
    }

    private static boolean isReflectiveApi(MethodInsnNode mi) {
        String k = mi.owner + "." + mi.name;
        return k.equals("java/lang/Class.forName")
                || k.equals("java/lang/Class.getMethod")
                || k.equals("java/lang/Class.getDeclaredMethod")
                || k.equals("java/lang/Class.getField")
                || k.equals("java/lang/Class.getDeclaredField")
                || k.equals("java/lang/Class.getMethods")
                || k.equals("java/lang/Class.getDeclaredMethods")
                || k.equals("java/lang/Class.getFields")
                || k.equals("java/lang/Class.getDeclaredFields")
                || k.equals("java/lang/reflect/Method.invoke")
                || k.equals("java/lang/reflect/Field.get")
                || k.equals("java/lang/reflect/Field.set")
                || k.equals("java/lang/reflect/Field.getBoolean")
                || k.equals("java/lang/reflect/Field.getInt")
                || k.equals("java/lang/reflect/Field.setBoolean")
                || k.equals("java/lang/reflect/Field.setInt");
    }

    private static Set<String> modSet(Map<String, ClassNode> classes,
                                      Map<String, Set<String>> cache,
                                      ClassNode cn, Set<String> visiting) {
        Set<String> hit = cache.get(cn.name);
        if (hit != null) return hit;
        if (!visiting.add(cn.name)) return Set.of();
        Set<String> o = new HashSet<>();
        for (MethodNode m : cn.methods) {
            for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                if (n instanceof FieldInsnNode f && n.getOpcode() == Opcodes.PUTSTATIC)
                    o.add(f.owner + "." + f.name);
                else if (n instanceof MethodInsnNode mi
                        && (mi.getOpcode() == Opcodes.INVOKESTATIC
                            || mi.getOpcode() == Opcodes.INVOKESPECIAL)
                        && !isPureWrtStatics(n)) {
                    ClassNode t = classes.get(mi.owner + ".class");
                    if (t == null) { o.add("*bilinmeyen*"); }
                    else o.addAll(modSet(classes, cache, t, visiting));
                } else if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode) {
                    if (!isPureWrtStatics(n)) o.add("*bilinmeyen*");
                }
            }
        }
        visiting.remove(cn.name);
        cache.put(cn.name, o);
        return o;
    }

    private static boolean tryCovered(MethodNode m, List<AbstractInsnNode> ins, int a, int b) {
        if (m.tryCatchBlocks == null || m.tryCatchBlocks.isEmpty()) return false;
        for (TryCatchBlockNode t : m.tryCatchBlocks) {
            int s = ins.indexOf(t.start), e = ins.indexOf(t.end);
            if (s < 0 || e < 0) continue;
            if (s <= a && b < e) return true;
            if (a <= s && s <= b) return true;
        }
        return false;
    }

    private static boolean isPureWrtStatics(AbstractInsnNode u) {
        if (u instanceof InvokeDynamicInsnNode id)
            return id.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory");
        if (!(u instanceof MethodInsnNode mi)) return false;
        String o = mi.owner;
        return o.equals("java/lang/String") || o.equals("java/lang/StringBuilder")
                || o.equals("java/lang/StringBuffer") || o.equals("java/lang/Integer")
                || o.equals("java/lang/Long") || o.equals("java/lang/Float")
                || o.equals("java/lang/Double") || o.equals("java/lang/Character")
                || o.equals("java/lang/Boolean") || o.equals("java/lang/Math")
                || o.equals("java/util/Objects") || o.equals("java/util/Arrays")
                || o.equals("java/lang/Object");
    }

    public static AbstractInsnNode findProducer(List<AbstractInsnNode> ins, int storeIdx) {
        int o = 0;
        for (int j = storeIdx - 1; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (n instanceof LabelNode || n instanceof JumpInsnNode
                    || n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode
                    || n instanceof LineNumberNode || n instanceof FrameNode) {
                if (n instanceof LineNumberNode || n instanceof FrameNode) continue;
                return null;
            }
            int op = n.getOpcode();
            if (op == Opcodes.ATHROW || op == Opcodes.RET || op == Opcodes.JSR
                    || (op >= Opcodes.IRETURN && op <= Opcodes.RETURN)) return null;
            int[] s = stackSizes(n);
            if (s == null) return null;
            int p = s[0], q = s[1];
            if (o < q) {
                if (o != 0) return null;
                if (n instanceof VarInsnNode && isLoad(op)) return n;
                if (n instanceof FieldInsnNode && op == Opcodes.GETSTATIC) return n;
                if (n instanceof LdcInsnNode) return n;
                if (isConstPush(n)) return n;
                return null;
            }
            o = o - q + p;
        }
        return null;
    }

    static Set<LabelNode> blockingLabels(MethodNode m) {
        Set<LabelNode> o = new HashSet<>(ClassIO.jumpTargets(m));
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            o.add(t.start);
            o.add(t.end);
            o.add(t.handler);
        }
        return o;
    }

    private static boolean isBlockEnd(AbstractInsnNode u, Set<LabelNode> blocking) {
        if (u instanceof LabelNode) return blocking.contains(u);
        return isBlockEnd(u);
    }

    public static AbstractInsnNode findProducerWords(MethodNode m, List<AbstractInsnNode> ins,
                                                     int consumeIdx, int words) {
        Set<LabelNode> blocking = blockingLabels(m);
        int o = 0;
        int need = words;
        for (int j = consumeIdx - 1; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (n instanceof LineNumberNode || n instanceof FrameNode) continue;
            if (n instanceof LabelNode) {
                if (blocking.contains(n)) return null;
                continue;
            }
            if (n instanceof JumpInsnNode
                    || n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode) {
                return null;
            }
            int op = n.getOpcode();
            if (op == Opcodes.ATHROW || op == Opcodes.RET || op == Opcodes.JSR
                    || (op >= Opcodes.IRETURN && op <= Opcodes.RETURN)) return null;
            int[] s = stackSizes(n);
            if (s == null) return null;
            int p = s[0], q = s[1];
            if (o < q) {
                if (o != 0) return null;
                if (o + q == need && q == 1) {
                    if (n instanceof VarInsnNode && isLoad(op)) return n;
                    if (n instanceof FieldInsnNode && op == Opcodes.GETSTATIC) return n;
                    if (n instanceof LdcInsnNode) return n;
                    if (isConstPush(n)) return n;
                }
                return null;
            }
            o = o - q + p;
        }
        return null;
    }

    public static AbstractInsnNode findProducer(MethodNode m, List<AbstractInsnNode> ins, int storeIdx) {
        AbstractInsnNode st = ins.get(storeIdx);
        int words = (st != null && (st.getOpcode() == Opcodes.LSTORE || st.getOpcode() == Opcodes.DSTORE))
                ? 2 : 1;
        return findProducerWords(m, ins, storeIdx, words);
    }

    private static boolean isConstPush(AbstractInsnNode n) {
        int op = n.getOpcode();
        return (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5)
                || op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1
                || op == Opcodes.FCONST_0 || op == Opcodes.FCONST_1 || op == Opcodes.FCONST_2
                || op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1
                || op == Opcodes.BIPUSH || op == Opcodes.SIPUSH || op == Opcodes.ACONST_NULL;
    }

    static int[] stackSizes(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (n instanceof LdcInsnNode l) {
            Object c = l.cst;
            int q = (c instanceof Long || c instanceof Double) ? 2 : 1;
            return new int[]{0, q};
        }
        if (n instanceof IntInsnNode) {
            if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return new int[]{0, 1};
            if (op == Opcodes.NEWARRAY) return new int[]{1, 1};
            return null;
        }
        if (n instanceof VarInsnNode) {
            return switch (op) {
                case Opcodes.ILOAD, Opcodes.FLOAD, Opcodes.ALOAD -> new int[]{0, 1};
                case Opcodes.LLOAD, Opcodes.DLOAD -> new int[]{0, 2};
                case Opcodes.ISTORE, Opcodes.FSTORE, Opcodes.ASTORE -> new int[]{1, 0};
                case Opcodes.LSTORE, Opcodes.DSTORE -> new int[]{2, 0};
                case Opcodes.RET -> null;
                default -> null;
            };
        }
        if (n instanceof FieldInsnNode f) {
            int w = wordSize(f.desc);
            if (op == Opcodes.GETSTATIC) return new int[]{0, w};
            if (op == Opcodes.PUTSTATIC) return new int[]{w, 0};
            if (op == Opcodes.GETFIELD) return new int[]{1, w};
            if (op == Opcodes.PUTFIELD) return new int[]{1 + w, 0};
            return null;
        }
        if (n instanceof MethodInsnNode mi) {
            int pops = 0;
            for (Type t : Type.getArgumentTypes(mi.desc)) pops += t.getSize();
            if (op != Opcodes.INVOKESTATIC) pops += 1;
            Type rt = Type.getReturnType(mi.desc);
            int pushes = rt.getSort() == Type.VOID ? 0 : rt.getSize();
            return new int[]{pops, pushes};
        }
        if (n instanceof InvokeDynamicInsnNode id) {
            int pops = 0;
            for (Type t : Type.getArgumentTypes(id.desc)) pops += t.getSize();
            Type rt = Type.getReturnType(id.desc);
            int pushes = rt.getSort() == Type.VOID ? 0 : rt.getSize();
            return new int[]{pops, pushes};
        }
        if (n instanceof TypeInsnNode) {
            if (op == Opcodes.NEW) return new int[]{0, 1};
            if (op == Opcodes.ANEWARRAY) return new int[]{1, 1};
            if (op == Opcodes.CHECKCAST || op == Opcodes.INSTANCEOF) return new int[]{1, 1};
            return null;
        }
        if (n instanceof MultiANewArrayInsnNode m) return new int[]{m.dims, 1};
        if (n instanceof IincInsnNode) return new int[]{0, 0};
        return switch (op) {
            case Opcodes.NOP -> new int[]{0, 0};
            case Opcodes.ACONST_NULL,
                 Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1,
                 Opcodes.ICONST_2, Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
                 Opcodes.BIPUSH, Opcodes.SIPUSH -> new int[]{0, 1};
            case Opcodes.LCONST_0, Opcodes.LCONST_1,
                 Opcodes.DCONST_0, Opcodes.DCONST_1 -> new int[]{0, 2};
            case Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2 -> new int[]{0, 1};
            case Opcodes.POP -> new int[]{1, 0};

            case Opcodes.POP2 -> new int[]{2, 0};
            case Opcodes.DUP_X1 -> new int[]{2, 3};
            case Opcodes.DUP_X2 -> new int[]{3, 4};
            case Opcodes.DUP2 -> new int[]{2, 4};
            case Opcodes.DUP2_X1 -> new int[]{3, 5};
            case Opcodes.DUP2_X2 -> new int[]{4, 6};
            case Opcodes.DUP -> new int[]{1, 2};
            case Opcodes.SWAP -> new int[]{2, 2};
            case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
                 Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR, Opcodes.ISHL, Opcodes.ISHR,
                 Opcodes.IUSHR, Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV,
                 Opcodes.FREM, Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG,
                 Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT,
                 Opcodes.IF_ICMPGE, Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE,
                 Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE -> new int[]{2, 1};
            case Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
                 Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR, Opcodes.DADD, Opcodes.DSUB,
                 Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM -> new int[]{4, 2};
            case Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR -> new int[]{3, 2};
            case Opcodes.INEG, Opcodes.FNEG, Opcodes.I2F, Opcodes.I2B, Opcodes.I2C, Opcodes.I2S,
                 Opcodes.F2I, Opcodes.ARRAYLENGTH, Opcodes.MONITORENTER,
                 Opcodes.MONITOREXIT -> new int[]{1, 1};
            case Opcodes.LNEG, Opcodes.DNEG, Opcodes.I2L, Opcodes.I2D, Opcodes.F2L, Opcodes.F2D,
                 Opcodes.L2D, Opcodes.D2L -> new int[]{2, 2};
            case Opcodes.L2I, Opcodes.L2F, Opcodes.D2I, Opcodes.D2F -> new int[]{2, 1};
            case Opcodes.IALOAD, Opcodes.FALOAD, Opcodes.AALOAD, Opcodes.BALOAD,
                 Opcodes.CALOAD, Opcodes.SALOAD -> new int[]{2, 1};
            case Opcodes.LALOAD, Opcodes.DALOAD -> new int[]{2, 2};
            case Opcodes.IASTORE, Opcodes.FASTORE, Opcodes.AASTORE, Opcodes.BASTORE,
                 Opcodes.CASTORE, Opcodes.SASTORE -> new int[]{3, 0};
            case Opcodes.LASTORE, Opcodes.DASTORE -> new int[]{4, 0};
            default -> null;
        };
    }

    private static int wordSize(String desc) {
        char c = desc.charAt(0);
        return (c == 'J' || c == 'D') ? 2 : 1;
    }

    public static int propagateHypoConsts(Map<String, ClassNode> classes, ClassNode cn,
                                          MethodNode m, Map<String, ?> hypo) {
        if (hasJsrRet(m) || hypo.isEmpty()) return 0;
        int n = 0;
        boolean changed = true;
        int iter = 0;
        int paramSlots = (m.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        for (org.objectweb.asm.Type t : org.objectweb.asm.Type.getArgumentTypes(m.desc))
            paramSlots += t.getSize();
        while (changed && iter++ < 10) {
            changed = false;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            for (int k = 0; k < ins.size(); k++) {
                AbstractInsnNode st = ins.get(k);
                if (!(st instanceof VarInsnNode vs) || !isStore(st.getOpcode())) continue;
                int y = vs.var;
                if (y < paramSlots || countStores(ins, y) != 1) continue;
                AbstractInsnNode prod = findProducer(m, ins, k);
                if (!(prod instanceof FieldInsnNode pf) || prod.getOpcode() != Opcodes.GETSTATIC)
                    continue;
                String key = pf.owner + "." + pf.name;
                if (!hypo.containsKey(key)) continue;
                if (!propagatable(prod, st.getOpcode())) continue;

                List<AbstractInsnNode> loads = new ArrayList<>();
                boolean ok = true;
                for (int j = 0; j < ins.size(); j++) {
                    AbstractInsnNode u = ins.get(j);
                    if (u instanceof VarInsnNode vu && vu.var == y) {
                        if (isLoad(u.getOpcode())) {
                            if (!loadCompatible(prod, u.getOpcode())) { ok = false; break; }

                            if (j < k) { ok = false; break; }
                            loads.add(u);
                        } else if (u != st) {

                            ok = false;
                            break;
                        }
                    }
                }
                if (!ok || loads.isEmpty()) continue;
                for (AbstractInsnNode ld : loads) {
                    m.instructions.insertBefore(ld, cloneProducer(prod));
                    m.instructions.remove(ld);
                    n++;
                }
                m.instructions.remove(prod);
                m.instructions.remove(st);
                n += 2;
                changed = true;
                break;
            }
        }
        return n;
    }

    public static int removeDeadHypoStores(ClassNode cn, MethodNode m, Map<String, ?> hypo) {
        if (hasJsrRet(m) || hypo.isEmpty()) return 0;
        int n = 0;
        boolean changed = true;
        int iter = 0;
        while (changed && iter++ < 10) {
            changed = false;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            for (int k = 0; k < ins.size(); k++) {
                AbstractInsnNode st = ins.get(k);
                if (!(st instanceof VarInsnNode) || !isStore(st.getOpcode())) continue;
                int y = ((VarInsnNode) st).var;
                boolean loaded = false;
                for (int j = k + 1; j < ins.size(); j++) {
                    AbstractInsnNode u = ins.get(j);
                    if (u instanceof VarInsnNode vu && vu.var == y && isLoad(u.getOpcode())) {
                        loaded = true;
                        break;
                    }
                }
                if (loaded) continue;
                AbstractInsnNode prod = findProducer(m, ins, k);
                if (!(prod instanceof FieldInsnNode pf) || prod.getOpcode() != Opcodes.GETSTATIC)
                    continue;
                if (!hypo.containsKey(pf.owner + "." + pf.name)) continue;
                m.instructions.remove(prod);
                m.instructions.remove(st);
                n += 2;
                changed = true;
                break;
            }
        }
        return n;
    }

    public static int removeDeadStores(ClassNode cn, MethodNode m) {
        if (hasJsrRet(m)) return 0;
        int n = 0;
        boolean changed = true;
        int iter = 0;
        while (changed && iter++ < 10) {
            changed = false;
            List<AbstractInsnNode> ins = ClassIO.list(m);
            for (int k = 1; k < ins.size(); k++) {
                AbstractInsnNode st = ins.get(k);
                if (!(st instanceof VarInsnNode vs) || !isStore(st.getOpcode())) continue;
                int y = vs.var;
                boolean loaded = false;
                for (int j = k + 1; j < ins.size(); j++) {
                    AbstractInsnNode u = ins.get(j);
                    if (u instanceof VarInsnNode vu && vu.var == y) {
                        if (isLoad(u.getOpcode())) { loaded = true; break; }
                    }
                }
                if (loaded) continue;
                AbstractInsnNode prod = findProducer(m, ins, k);
                if (prod == null || !removableProducer(cn, prod)) continue;
                m.instructions.remove(prod);
                m.instructions.remove(st);
                n += 2;
                changed = true;
                break;
            }
        }
        return n;
    }

    private static boolean removableProducer(ClassNode cn, AbstractInsnNode prod) {
        int op = prod.getOpcode();
        if (prod instanceof VarInsnNode) return isLoad(op);
        if (prod instanceof LdcInsnNode) return true;
        if (prod instanceof FieldInsnNode f)
            return op == Opcodes.GETSTATIC && cn != null && f.owner.equals(cn.name);
        return isConstPush(prod);
    }

    private static boolean isLoad(int op) {
        return op == Opcodes.ILOAD || op == Opcodes.LLOAD || op == Opcodes.FLOAD
                || op == Opcodes.DLOAD || op == Opcodes.ALOAD;
    }

    private static boolean isStore(int op) {
        return op == Opcodes.ISTORE || op == Opcodes.LSTORE || op == Opcodes.FSTORE
                || op == Opcodes.DSTORE || op == Opcodes.ASTORE;
    }

    private static boolean sameKind(int loadOp, int storeOp) {
        return (loadOp == Opcodes.ILOAD && storeOp == Opcodes.ISTORE)
                || (loadOp == Opcodes.LLOAD && storeOp == Opcodes.LSTORE)
                || (loadOp == Opcodes.FLOAD && storeOp == Opcodes.FSTORE)
                || (loadOp == Opcodes.DLOAD && storeOp == Opcodes.DSTORE)
                || (loadOp == Opcodes.ALOAD && storeOp == Opcodes.ASTORE);
    }

    private static int countStores(List<AbstractInsnNode> ins, int local) {
        int c = 0;
        for (AbstractInsnNode n : ins) {
            if (n instanceof VarInsnNode v && v.var == local && isStore(n.getOpcode())) c++;
            if (n instanceof IincInsnNode ii && ii.var == local) c++;
        }
        return c;
    }

    public static int collapseGotos(MethodNode m) {
        int n = 0;
        Map<LabelNode, LabelNode> gotoTarget = new HashMap<>();
        for (AbstractInsnNode i = m.instructions.getFirst(); i != null; i = i.getNext()) {
            if (i.getOpcode() == Opcodes.GOTO && i instanceof JumpInsnNode) {
                LabelNode t = ((JumpInsnNode) i).label;
                AbstractInsnNode nx = nextReal(i);
                if (nx == t) {

                    AbstractInsnNode del = i;
                    i = i.getNext();
                    m.instructions.remove(del);
                    n++;
                    continue;
                }
                LabelNode prev = labelOf(i);
                if (prev != null) gotoTarget.put(prev, t);
            }
        }

        for (AbstractInsnNode i = m.instructions.getFirst(); i != null; i = i.getNext()) {
            if (i.getOpcode() == Opcodes.GOTO && i instanceof JumpInsnNode) {
                JumpInsnNode j = (JumpInsnNode) i;
                Set<LabelNode> seen = new HashSet<>();
                LabelNode t = j.label;
                while (gotoTarget.containsKey(t) && seen.add(t)) t = gotoTarget.get(t);
                if (t != j.label) { j.label = t; n++; }
            }
        }
        return n;
    }

    private static LabelNode labelOf(AbstractInsnNode insn) {
        AbstractInsnNode n = insn.getPrevious();
        while (n != null && !(n instanceof LabelNode)) {
            if (n.getOpcode() >= 0) break;
            n = n.getPrevious();
        }
        return n instanceof LabelNode ? (LabelNode) n : null;
    }

    public static int removeDeadResolverClasses(Map<String, ClassNode> classes) {
        Set<String> extMethodRefs = new HashSet<>();
        Set<String> extFieldRefs = new HashSet<>();
        Set<String> extBsm = new HashSet<>();
        Set<String> extHandles = new HashSet<>();
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof MethodInsnNode mi && !mi.owner.equals(cn.name))
                        extMethodRefs.add(mi.owner);
                    else if (n instanceof FieldInsnNode f && !f.owner.equals(cn.name))
                        extFieldRefs.add(f.owner);
                    else if (n instanceof InvokeDynamicInsnNode id
                            && !id.bsm.getOwner().equals(cn.name))
                        extBsm.add(id.bsm.getOwner());
                    else if (n instanceof LdcInsnNode l
                            && l.cst instanceof org.objectweb.asm.Handle h
                            && !h.getOwner().equals(cn.name))
                        extHandles.add(h.getOwner());
                    else if (n instanceof TypeInsnNode t && t.desc.startsWith("L")) {
                        String o = t.desc.substring(1, t.desc.length() - 1);
                        if (!o.equals(cn.name)) {  }
                    }
                }
            }
            if (cn.superName != null && !cn.superName.equals("java/lang/Object"))
                {  }
        }
        List<String> dead = new ArrayList<>();
        for (ClassNode cn : classes.values()) {
            boolean isRes;
            try {
                isRes = ReferenceResolver.isResolverClass(cn);
            } catch (Throwable t) {
                continue;
            }
            if (!isRes) continue;
            if (extMethodRefs.contains(cn.name)) continue;
            if (extFieldRefs.contains(cn.name)) continue;
            if (extBsm.contains(cn.name)) continue;
            if (extHandles.contains(cn.name)) continue;

            boolean typed = false;
            for (ClassNode o : classes.values()) {
                if (o == cn) continue;
                for (MethodNode m : o.methods) {
                    for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                        if (n instanceof TypeInsnNode t && t.desc.equals("L" + cn.name + ";")) { typed = true; break; }
                        if (n instanceof FieldInsnNode f && f.desc.contains("L" + cn.name + ";")) { typed = true; break; }
                        if (n instanceof MethodInsnNode mi
                                && (mi.desc.contains("L" + cn.name + ";"))) { typed = true; break; }
                    }
                    if (typed) break;
                }
                if (typed) break;
            }
            if (typed) continue;
            dead.add(cn.name + ".class");
        }
        for (String k : dead) classes.remove(k);
        return dead.size();
    }

    public static int stripClinitLocalStatics(Map<String, ClassNode> classes, Set<String> original) {
        int n = 0;
        for (ClassNode cn : classes.values()) {
            MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
            if (cl == null) continue;

            Set<String> extReads = new HashSet<>();
            Set<String> extWrites = new HashSet<>();
            for (ClassNode c2 : classes.values()) {
                for (MethodNode m : c2.methods) {
                    if (c2 == cn && m == cl) continue;
                    for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
                        if (!(x instanceof FieldInsnNode f)) continue;
                        if (x.getOpcode() == Opcodes.GETSTATIC) extReads.add(f.owner + "." + f.name);
                        else if (x.getOpcode() == Opcodes.PUTSTATIC) extWrites.add(f.owner + "." + f.name);
                    }
                }
            }
            List<AbstractInsnNode> ins = ClassIO.list(cl);
            Set<FieldNode> targets = new LinkedHashSet<>();
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                String key = cn.name + "." + f.name;
                if (extReads.contains(key)) continue;

                if (extWrites.contains(key)) continue;
                if (original != null && original.contains(key)) continue;
                boolean written = false;
                for (AbstractInsnNode x : ins)
                    if (x.getOpcode() == Opcodes.PUTSTATIC && x instanceof FieldInsnNode fx
                            && fx.owner.equals(cn.name) && fx.name.equals(f.name)) written = true;
                if (!written) continue;
                if (!isScalar(f.desc)) continue;
                targets.add(f);
            }
            for (FieldNode f : targets) {
                boolean wrote = false;
                for (AbstractInsnNode x : ClassIO.list(cl)) {
                    if (!(x instanceof FieldInsnNode fx)) continue;
                    if (!fx.owner.equals(cn.name) || !fx.name.equals(f.name)) continue;
                    if (x.getOpcode() == Opcodes.PUTSTATIC) {
                        cl.instructions.set(x, new InsnNode(
                                wideField(f.desc) ? Opcodes.POP2 : Opcodes.POP));
                        wrote = true;
                        n++;
                    } else if (x.getOpcode() == Opcodes.GETSTATIC && !wrote) {

                        cl.instructions.set(x, defaultOf(f.desc));
                        n++;
                    }
                }
            }
        }
        return n;
    }

    private static boolean isScalar(String desc) {
        char c = desc.charAt(0);
        return c == 'J' || c == 'D' || c == 'F' || c == 'I' || c == 'Z'
                || c == 'B' || c == 'C' || c == 'S';
    }

    private static AbstractInsnNode defaultOf(String desc) {
        return switch (desc.charAt(0)) {
            case 'J' -> new LdcInsnNode(0L);
            case 'D' -> new InsnNode(Opcodes.DCONST_0);
            case 'F' -> new InsnNode(Opcodes.FCONST_0);
            default -> new InsnNode(Opcodes.ICONST_0);
        };
    }

    public static Map<String, Object> dynamicScalarStatics(Map<String, ClassNode> classes,
                                                           ClassLoader loader,
                                                           Set<String> needed) {
        Map<String, Object> o = new HashMap<>();
        if (loader == null || needed.isEmpty()) return o;
        for (ClassNode cn : classes.values()) {
            List<FieldNode> targets = new ArrayList<>();
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0 || !isScalar(f.desc)) continue;
                if (!needed.contains(cn.name + "." + f.name)) continue;
                targets.add(f);
            }
            if (targets.isEmpty()) continue;
            try {
                Class<?> c = Class.forName(cn.name.replace('/', '.'), true, loader);
                for (FieldNode f : targets) {
                    try {
                        java.lang.reflect.Field rf = c.getDeclaredField(f.name);
                        rf.setAccessible(true);
                        Object v = rf.get(null);
                        if (v != null) o.put(cn.name + "." + f.name, v);
                    } catch (Throwable ignored) { }
                }
            } catch (Throwable ignored) {

            }
        }
        return o;
    }

    public static Set<String> inlinedScalarCandidates(Map<String, ClassNode> classes,
                                                      Set<String> original) {
        Set<String> r = new HashSet<>();
        if (original == null) return r;
        Set<String> read = new HashSet<>();
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext())
                    if (x instanceof FieldInsnNode f && x.getOpcode() == Opcodes.GETSTATIC)
                        read.add(f.owner + "." + f.name);
        for (ClassNode cn : classes.values())
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0 || !isScalar(f.desc)) continue;
                String k = cn.name + "." + f.name;
                if (original.contains(k)) continue;
                if (!read.contains(k)) continue;
                r.add(k);
            }
        return r;
    }

    public static int inlineScalarStatics(Map<String, ClassNode> classes,
                                          Set<String> keys, Map<String, Object> values) {
        if (keys.isEmpty() || values.isEmpty()) return 0;
        Map<String, String> desc = new HashMap<>();
        for (ClassNode cn : classes.values())
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0 || !isScalar(f.desc)) continue;
                desc.put(cn.name + "." + f.name, f.desc);
            }
        int n = 0;
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
                    if (x.getOpcode() != Opcodes.GETSTATIC || !(x instanceof FieldInsnNode fi)) continue;
                    String k = fi.owner + "." + fi.name;
                    if (!keys.contains(k)) continue;
                    AbstractInsnNode lit = literalFor(values.get(k), desc.get(k));
                    if (lit == null) continue;
                    m.instructions.set(x, lit);
                    n++;
                }
        return n;
    }

    private static AbstractInsnNode literalFor(Object v, String d) {
        if (d == null || v == null) return null;
        char c = d.charAt(0);
        if (v instanceof Long l && c == 'J') return new LdcInsnNode(l);
        if (v instanceof Integer i) return new LdcInsnNode(i);
        if (v instanceof Boolean bo && c == 'Z') return new InsnNode(bo ? Opcodes.ICONST_1 : Opcodes.ICONST_0);
        return null;
    }

    public static int stripDeadClinitWrites(Map<String, ClassNode> classes) {
        Set<String> unread = unreadStaticFields(classes);
        int n = 0;
        for (ClassNode cn : classes.values()) {
            MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
            if (cl == null) continue;
            boolean changed = true;
            int guard = 0;
            while (changed && guard++ < 12) {
                changed = false;
                List<AbstractInsnNode> ins = ClassIO.list(cl);
                for (int k = 0; k < ins.size(); k++) {
                    AbstractInsnNode x = ins.get(k);
                    if (x.getOpcode() != Opcodes.PUTSTATIC || !(x instanceof FieldInsnNode fi)) continue;
                    if (!fi.owner.equals(cn.name)) continue;
                    if (!unread.contains(cn.name + "." + fi.name)) continue;
                    AbstractInsnNode prod = findProducer(cl, ins, k);
                    if (prod == null) {

                        int pop = wideField(fi.desc) ? Opcodes.POP2 : Opcodes.POP;
                        cl.instructions.set(x, new InsnNode(pop));
                        n++;
                        changed = true;
                        break;
                    }

                    Set<LabelNode> bounds = new HashSet<>();
                    if (cl.tryCatchBlocks != null) for (TryCatchBlockNode t : cl.tryCatchBlocks) {
                        bounds.add(t.start); bounds.add(t.end); bounds.add(t.handler);
                    }
                    Set<LabelNode> tgts = ClassIO.jumpTargets(cl);
                    boolean clean = true;
                    for (AbstractInsnNode y = prod; y != null; y = y.getNext()) {
                        if (y instanceof LabelNode && (bounds.contains(y) || tgts.contains(y))) {
                            clean = false; break;
                        }
                        if (y == x) break;
                    }
                    if (!clean) {

                        cl.instructions.set(x, new InsnNode(wideField(fi.desc)
                                ? Opcodes.POP2 : Opcodes.POP));
                        n++;
                        changed = true;
                        break;
                    }
                    AbstractInsnNode del = prod;
                    while (true) {
                        AbstractInsnNode nx = del.getNext();
                        if (del.getOpcode() >= 0) mRemove(cl, del);
                        if (del == x) break;
                        del = nx;
                    }
                    n += 2;
                    changed = true;
                    break;
                }
            }
            if (changed) {
                stripNops(cl);
                collapseGotos(cl);
                removeDeadCode(cl);
            }
        }
        return n;
    }

    private static void mRemove(MethodNode m, AbstractInsnNode n) {
        m.instructions.remove(n);
    }

    private static boolean wideField(String desc) {
        char c = desc.charAt(0);
        return c == 'J' || c == 'D';
    }

    public static Set<String> unreadStaticFields(Map<String, ClassNode> classes) {
        Set<String> reads = new HashSet<>();
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext())
                    if (n instanceof FieldInsnNode f
                            && (n.getOpcode() == Opcodes.GETSTATIC || n.getOpcode() == Opcodes.GETFIELD))
                        reads.add(f.owner + "." + f.name);
        Set<String> o = new HashSet<>();
        for (ClassNode cn : classes.values())
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                String k = cn.name + "." + f.name;
                if (!reads.contains(k)) o.add(k);
            }
        return o;
    }

    public static int removeDeadClinits(Map<String, ClassNode> classes, boolean reflective) {
        if (reflective) return 0;
        Set<String> unread = unreadStaticFields(classes);
        int n = 0;
        for (ClassNode cn : classes.values()) {
            List<MethodNode> del = new ArrayList<>();
            for (MethodNode cl : cn.methods) {
                if (!cl.name.equals("<clinit>") || !cl.desc.equals("()V")) continue;
                int puts = 0;
                boolean ok = true;
                if (cl.tryCatchBlocks != null && !cl.tryCatchBlocks.isEmpty()) ok = false;
                for (AbstractInsnNode x = cl.instructions.getFirst(); x != null && ok; x = x.getNext()) {
                    int op = x.getOpcode();
                    if (op < 0) continue;
                    if (op == Opcodes.ATHROW || op == Opcodes.JSR || op == Opcodes.RET) { ok = false; break; }
                    if (x instanceof InvokeDynamicInsnNode || x instanceof MultiANewArrayInsnNode) { ok = false; break; }
                    if (x instanceof MethodInsnNode mi) {
                        String o = mi.owner;
                        boolean pure = o.equals("java/lang/String") || o.equals("java/lang/StringBuilder")
                                || o.equals("java/lang/StringBuffer") || o.equals("java/lang/Integer")
                                || o.equals("java/lang/Long") || o.equals("java/lang/Float")
                                || o.equals("java/lang/Double") || o.equals("java/lang/Character")
                                || o.equals("java/lang/Boolean") || o.equals("java/lang/Math")
                                || o.equals("java/util/Objects") || o.equals("java/util/Arrays")
                                || o.equals("java/lang/Object") || o.equals("java/lang/Class");
                        if (!pure) { ok = false; break; }
                    } else if (x instanceof FieldInsnNode f) {
                        if (op == Opcodes.PUTSTATIC) {
                            if (!f.owner.equals(cn.name)) { ok = false; break; }
                            if (!unread.contains(cn.name + "." + f.name)) { ok = false; break; }
                            puts++;
                        } else if (op == Opcodes.GETSTATIC) {
                            if (!f.owner.equals(cn.name) && !f.owner.startsWith("java/")) { ok = false; break; }
                        } else { ok = false; break; }
                    } else if (x instanceof TypeInsnNode t && op == Opcodes.NEW) {
                        if (!t.desc.equals("java/lang/String") && !t.desc.equals("java/lang/StringBuilder")
                                && !t.desc.equals("java/lang/StringBuffer")) { ok = false; break; }
                    }
                }
                if (ok && puts > 0) del.add(cl);
            }
            for (MethodNode m : del) { cn.methods.remove(m); n++; }
        }
        return n;
    }

    public static int removeEmptyClinits(Map<String, ClassNode> classes) {
        int n = 0;
        for (ClassNode cn : classes.values()) {
            List<MethodNode> del = new ArrayList<>();
            for (MethodNode m : cn.methods) {
                if (!m.name.equals("<clinit>") || !m.desc.equals("()V")) continue;
                boolean empty = true;
                for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
                    if (x.getOpcode() < 0) continue;
                    if (x.getOpcode() == Opcodes.RETURN) continue;
                    empty = false;
                    break;
                }
                if (empty) del.add(m);
            }
            for (MethodNode m : del) { cn.methods.remove(m); n++; }
        }
        return n;
    }

    public static int polish(MethodNode m) {
        if (hasJsrRet(m)) return 0;
        int n = 0;
        boolean changed = true;
        int iter = 0;
        while (changed && iter++ < 8) {
            changed = false;

            for (AbstractInsnNode i = m.instructions.getFirst(); i != null; i = i.getNext()) {
                if (i.getOpcode() != Opcodes.GOTO || !(i instanceof JumpInsnNode)) continue;
                JumpInsnNode g = (JumpInsnNode) i;
                if (!gotoIsNoOp(m, g)) continue;
                m.instructions.remove(g);
                n++;
                changed = true;
                break;
            }
            if (changed) continue;

            int d = removeDeadCode(m);
            if (d > 0) { n += d; changed = true; continue; }

            int s = stripNops(m);
            if (s > 0) { n += s; changed = true; }
        }

        n += dropOrphanLabels(m);
        return n;
    }

    private static boolean gotoIsNoOp(MethodNode m, JumpInsnNode g) {
        AbstractInsnNode n = g.getNext();
        while (n != null) {
            if (n == g.label) return true;
            if (n.getOpcode() >= 0) return false;
            n = n.getNext();
        }
        return false;
    }

    public static int dropOrphanLabels(MethodNode m) {
        Set<LabelNode> used = ClassIO.jumpTargets(m);
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            used.add(t.start);
            used.add(t.end);
            used.add(t.handler);
        }
        if (m.localVariables != null) for (LocalVariableNode lv : m.localVariables) {
            used.add(lv.start);
            used.add(lv.end);
        }
        List<LabelNode> dead = new ArrayList<>();
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (!(n instanceof LabelNode l)) continue;
            if (used.contains(l)) continue;
            if (m.localVariables != null) {
                boolean lvUses = false;
                for (LocalVariableNode lv : m.localVariables)
                    if (lv.start == l || lv.end == l) { lvUses = true; break; }
                if (lvUses) continue;
            }
            dead.add(l);
        }
        for (LabelNode l : dead) m.instructions.remove(l);
        return dead.size();
    }

    public static int removeDeadMethods(Map<String, ClassNode> classes) {
        Set<String> called = new HashSet<>();
        Set<String> bsmTargets = new HashSet<>();
        Set<String> ldcNames = new HashSet<>();
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof MethodInsnNode mi)
                        called.add(mi.owner + "." + mi.name + mi.desc);
                    else if (n instanceof InvokeDynamicInsnNode id)
                        bsmTargets.add(id.bsm.getOwner() + "." + id.bsm.getName());
                    else if (n instanceof LdcInsnNode l) {
                        if (l.cst instanceof String s) ldcNames.add(s);
                        else if (l.cst instanceof org.objectweb.asm.Handle h) {
                            called.add(h.getOwner() + "." + h.getName() + h.getDesc());
                            bsmTargets.add(h.getOwner() + "." + h.getName());
                        }
                    }
                }
            }
        }
        int n = 0;
        boolean changed = true;
        int guard = 0;
        while (changed && guard++ < 10) {
            changed = false;

            called.clear();
            for (ClassNode cn : classes.values()) {
                for (MethodNode m : cn.methods) {
                    for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
                        if (x instanceof MethodInsnNode mi)
                            called.add(mi.owner + "." + mi.name + mi.desc);
                        else if (x instanceof LdcInsnNode l
                                && l.cst instanceof org.objectweb.asm.Handle h)
                            called.add(h.getOwner() + "." + h.getName() + h.getDesc());
                    }
                }
            }
            for (ClassNode cn : classes.values()) {
                List<MethodNode> del = new ArrayList<>();
                for (MethodNode m : cn.methods) {
                    if (m.name.equals("<init>") || m.name.equals("<clinit>")) continue;
                    if ((m.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT
                            | Opcodes.ACC_SYNTHETIC)) != 0) continue;
                    if ((m.access & Opcodes.ACC_PRIVATE) == 0) continue;
                    if (isSerialMethod(m.name)) continue;
                    String key = cn.name + "." + m.name + m.desc;
                    if (called.contains(key)) continue;
                    if (bsmTargets.contains(cn.name + "." + m.name)) continue;
                    if (ldcNames.contains(m.name)) continue;
                    del.add(m);
                }
                for (MethodNode d : del) {
                    cn.methods.remove(d);
                    n++;
                    changed = true;
                }
            }
        }
        return n;
    }

    private static boolean isSerialMethod(String name) {
        return name.equals("readObject") || name.equals("writeObject")
                || name.equals("readResolve") || name.equals("writeReplace")
                || name.equals("readObjectNoData");
    }

    public static int inlineNeverWrittenStatics(Map<String, ClassNode> classes, boolean reflective) {
        if (reflective) return 0;
        Set<String> written = new HashSet<>();
        boolean refl = false;
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
                    if (x instanceof FieldInsnNode f && x.getOpcode() == Opcodes.PUTSTATIC)
                        written.add(f.owner + "." + f.name);
                    if (x instanceof MethodInsnNode mi) {
                        String k = mi.owner + "." + mi.name;
                        if (k.equals("java/lang/reflect/Field.set")
                                || k.equals("java/lang/Class.getDeclaredField")
                                || k.equals("java/lang/Class.getField")) refl = true;
                    }
                }
        if (refl) return 0;
        Set<String> cand = new HashSet<>();
        Map<String, String> desc = new HashMap<>();
        for (ClassNode cn : classes.values())
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                if (!isScalar(f.desc)) continue;
                String k = cn.name + "." + f.name;
                if (written.contains(k)) continue;
                cand.add(k);
                desc.put(k, f.desc);
            }
        if (cand.isEmpty()) return 0;
        int n = 0;
        for (ClassNode cn : classes.values())
            for (MethodNode m : cn.methods)
                for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
                    if (x.getOpcode() != Opcodes.GETSTATIC || !(x instanceof FieldInsnNode fi)) continue;
                    String k = fi.owner + "." + fi.name;
                    if (!cand.contains(k)) continue;
                    m.instructions.set(x, defaultOf(desc.get(k)));
                    n++;
                }
        return n;
    }

    public static Set<String> listedButUnusable(Map<String, ClassNode> classes,
                                                 Set<String> reads, Set<String> writes,
                                                 Set<String> original) {
        Set<String> bad = new HashSet<>();
        if (original == null) return bad;
        for (ClassNode cn : classes.values())
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                if ((f.access & Opcodes.ACC_FINAL) != 0) continue;
                String k = cn.name + "." + f.name;
                if (!original.contains(k)) continue;
                if (reads.contains(k) || writes.contains(k)) continue;
                bad.add(k);
            }
        return bad;
    }

    public static int removeDeadFields(Map<String, ClassNode> classes, Set<String> regened,
                                       Set<String> manufactured) {
        return removeDeadFields(classes, regened, manufactured, null);
    }

    public static int removeDeadFields(Map<String, ClassNode> classes, Set<String> regened,
                                       Set<String> manufactured, Set<String> original) {
        Set<String> reads = new HashSet<>();
        Set<String> writes = new HashSet<>();
        Set<String> ldcNames = new HashSet<>();
        boolean hasReflectionApi = false;
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof FieldInsnNode f
                            && (n.getOpcode() == Opcodes.GETSTATIC || n.getOpcode() == Opcodes.GETFIELD))
                        reads.add(f.owner + "." + f.name);
                    if (n instanceof FieldInsnNode f && n.getOpcode() == Opcodes.PUTSTATIC)
                        writes.add(f.owner + "." + f.name);
                    if (n instanceof LdcInsnNode l && l.cst instanceof String s) ldcNames.add(s);
                    if (n instanceof MethodInsnNode mi) {
                        String k = mi.owner + "." + mi.name;
                        if (k.equals("java/lang/Class.forName")
                                || k.equals("java/lang/Class.getMethod")
                                || k.equals("java/lang/Class.getDeclaredMethod")
                                || k.equals("java/lang/Class.getField")
                                || k.equals("java/lang/Class.getDeclaredField")
                                || k.equals("java/lang/Class.getMethods")
                                || k.equals("java/lang/Class.getDeclaredMethods")
                                || k.equals("java/lang/Class.getFields")
                                || k.equals("java/lang/Class.getDeclaredFields")
                                || k.equals("java/lang/reflect/Method.invoke")
                                || k.equals("java/lang/reflect/Field.get")
                                || k.equals("java/lang/reflect/Field.set")) {
                            hasReflectionApi = true;
                        }
                    }
                }
            }
        }

        Set<String> bogus = listedButUnusable(classes, reads, writes, original);
        int n = 0;
        for (ClassNode cn : classes.values()) {
            List<FieldNode> del = new ArrayList<>();
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                if ((f.access & Opcodes.ACC_SYNTHETIC) != 0) continue;
                if (f.name.equals("serialVersionUID")) continue;
                String key = cn.name + "." + f.name;
                if (reads.contains(key)) continue;

                if (original != null && original.contains(key) && !bogus.contains(key)) continue;

                if (original == null && regened.contains(cn.name) && f.value != null
                        && (f.access & Opcodes.ACC_STATIC) != 0
                        && (f.access & Opcodes.ACC_FINAL) != 0) continue;

                if (hasReflectionApi && !f.desc.startsWith("[") && ldcNames.contains(f.name)) continue;
                boolean isManufactured = manufactured.contains(key);

                if (original != null) {

                    if (!isManufactured) {  }
                } else {
                    if ((f.access & Opcodes.ACC_PRIVATE) == 0 && !isManufactured) continue;
                }

                if (writes.contains(key) && !regened.contains(cn.name)) continue;
                del.add(f);
            }
            for (FieldNode f : del) {
                cn.fields.remove(f);
                n++;
            }
        }
        return n;
    }

    public static int removeDeadCode(MethodNode m) {
        if (hasJsrRet(m)) return 0;
        Set<AbstractInsnNode> reach = new HashSet<>();
        Deque<AbstractInsnNode> q = new ArrayDeque<>();
        if (m.instructions.getFirst() != null) q.add(m.instructions.getFirst());
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) q.add(t.handler);
        while (!q.isEmpty()) {
            AbstractInsnNode cur = q.poll();
            while (cur != null && reach.add(cur)) {
                int op = cur.getOpcode();
                if (cur instanceof JumpInsnNode) {
                    q.add(((JumpInsnNode) cur).label);
                    if (op == Opcodes.GOTO) break;
                    cur = cur.getNext();
                } else if (cur instanceof TableSwitchInsnNode) {
                    TableSwitchInsnNode t = (TableSwitchInsnNode) cur;
                    q.add(t.dflt);
                    for (LabelNode l : t.labels) q.add(l);
                    break;
                } else if (cur instanceof LookupSwitchInsnNode) {
                    LookupSwitchInsnNode t = (LookupSwitchInsnNode) cur;
                    q.add(t.dflt);
                    for (LabelNode l : t.labels) q.add(l);
                    break;
                } else if (op == Opcodes.RET || op == Opcodes.ATHROW
                        || (op >= Opcodes.IRETURN && op <= Opcodes.RETURN)) {
                    break;
                } else {
                    cur = cur.getNext();
                }
            }
        }
        List<AbstractInsnNode> del = new ArrayList<>();
        for (AbstractInsnNode i = m.instructions.getFirst(); i != null; i = i.getNext()) {
            if (i.getOpcode() < 0) continue;
            if (!reach.contains(i)) del.add(i);
        }
        for (AbstractInsnNode d : del) m.instructions.remove(d);
        return del.size();
    }
}
