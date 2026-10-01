package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class ClinitRegenerator {
    private ClinitRegenerator() {}

    public static boolean regenerate(ClassNode cn, Map<String, ClassNode> classes, ClassLoader loader) {
        MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (cl == null) return false;
        if (realCount(cl) <= 1) return false;
        boolean debug = Boolean.getBoolean("zkmdeobf.debugOpt");
        String why = pureReason(cn, cl);
        if (why != null) {
            if (debug) System.err.println("[rejen] " + cn.name + " not-pure: " + why);
            return false;
        }
        Map<String, Object> st = MiniInterpreter.emulateClinit(classes, loader, cn);
        if (st == null) {

            st = dynamicStatics(cn, loader);
            if (st == null) {
                if (debug) System.err.println("[rejen] " + cn.name + " emulasyon-BAIL: " + MiniInterpreter.lastBail());
                return false;
            }
            if (debug) System.err.println("[rejen] " + cn.name + " dinamik-donus");
        }
        Set<String> live = liveFields(cn, classes);
        List<AbstractInsnNode> emit = new ArrayList<>();

        Set<String> constRestored = new HashSet<>();
        for (FieldNode f : cn.fields) {
            if ((f.access & Opcodes.ACC_STATIC) == 0 || (f.access & Opcodes.ACC_FINAL) == 0) continue;
            if (!isConstDesc(f.desc)) continue;
            if (hasOutsideWrite(cn, classes, f.name)) continue;
            if (!st.containsKey(cn.name + "." + f.name)) continue;
            Object cv = constValue(f.desc, st.get(cn.name + "." + f.name));
            if (cv != null) {
                f.value = cv;
                constRestored.add(f.name);
                if (debug) System.err.println("[rejen] " + cn.name + " constValue " + f.name + "=" + cv);
            }
        }
        for (FieldNode f : cn.fields) {
            if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
            String key = cn.name + "." + f.name;
            if (!live.contains(key)) continue;
            if (constRestored.contains(f.name)) continue;
            if (!hasClinitWrite(cl, cn.name, f.name)) continue;
            if (!st.containsKey(key)) return false;
            if (!emitValue(emit, f.desc, st.get(key))) return false;
            emit.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, f.name, f.desc));
        }
        emit.add(new InsnNode(Opcodes.RETURN));
        cl.instructions.clear();
        for (AbstractInsnNode n : emit) cl.instructions.add(n);
        cl.tryCatchBlocks = new ArrayList<>();
        if (cl.localVariables != null) cl.localVariables.clear();
        return true;
    }

    private static Map<String, Object> dynamicStatics(ClassNode cn, ClassLoader loader) {
        if (loader == null) return null;
        try {
            Class<?> c = Class.forName(cn.name.replace('/', '.'), true, loader);
            Map<String, Object> o = new HashMap<>();
            for (FieldNode f : cn.fields) {
                if ((f.access & Opcodes.ACC_STATIC) == 0) continue;
                char d = f.desc.charAt(0);
                if (d == '[' || d == 'L') continue;
                try {
                    java.lang.reflect.Field rf = c.getDeclaredField(f.name);
                    rf.setAccessible(true);
                    Object v = rf.get(null);
                    if (v != null) o.put(cn.name + "." + f.name, v);
                } catch (Throwable ignored) {  }
            }
            return o.isEmpty() ? null : o;
        } catch (Throwable t) {
            return null;
        }
    }

    private static int realCount(MethodNode m) {        int c = 0;
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() >= 0) c++;
        }
        return c;
    }

    private static boolean hasClinitWrite(MethodNode cl, String owner, String name) {
        for (AbstractInsnNode n = cl.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() == Opcodes.PUTSTATIC && n instanceof FieldInsnNode f
                    && f.owner.equals(owner) && f.name.equals(name)) return true;
        }
        return false;
    }

    private static boolean hasOutsideWrite(ClassNode cn, Map<String, ClassNode> classes, String name) {
        for (ClassNode c2 : classes.values()) {
            for (MethodNode m : c2.methods) {
                if (c2 == cn && m.name.equals("<clinit>")) continue;
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n.getOpcode() == Opcodes.PUTSTATIC && n instanceof FieldInsnNode f
                            && f.owner.equals(cn.name) && f.name.equals(name)) return true;
                }
            }
        }
        return false;
    }

    private static boolean isConstDesc(String desc) {
        char c = desc.charAt(0);
        return c == 'Z' || c == 'B' || c == 'C' || c == 'S' || c == 'I'
                || c == 'J' || c == 'F' || c == 'D' || desc.equals("Ljava/lang/String;");
    }

    private static Object constValue(String desc, Object v) {
        if (v == null || v == MiniInterpreter.NULL) return null;
        char c = desc.charAt(0);

        if (v instanceof Character ch) {
            return (c == 'C') ? (Object) ch : null;
        }
        if (v instanceof Boolean b) {
            return (c == 'Z') ? (Object) b : null;
        }
        if (c == 'C' && v instanceof Integer i) return (char) (int) i;
        if (c == 'Z' && v instanceof Integer i) return i != 0;
        if ((c == 'Z' || c == 'B' || c == 'C' || c == 'S' || c == 'I') && v instanceof Integer) return v;
        if (c == 'J' && v instanceof Long) return v;
        if (c == 'F' && v instanceof Float) return v;
        if (c == 'D' && v instanceof Double) return v;
        if (desc.equals("Ljava/lang/String;") && v instanceof String) return v;
        return null;
    }

    private static Set<String> liveFields(ClassNode cn, Map<String, ClassNode> classes) {
        Set<String> o = new HashSet<>();
        for (ClassNode c2 : classes.values()) {
            for (MethodNode m : c2.methods) {
                if (m.name.equals("<clinit>") && c2 == cn) continue;
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    int op = n.getOpcode();
                    if ((op == Opcodes.GETSTATIC || op == Opcodes.PUTSTATIC
                            || op == Opcodes.GETFIELD || op == Opcodes.PUTFIELD)
                            && n instanceof FieldInsnNode f && f.owner.equals(cn.name)) {
                        o.add(cn.name + "." + f.name);
                    }
                }
            }
        }
        return o;
    }

    private static boolean isPureClinit(ClassNode cn, MethodNode cl) {
        return pureReason(cn, cl) == null;
    }

    private static String pureReason(ClassNode cn, MethodNode cl) {
        for (AbstractInsnNode n = cl.instructions.getFirst(); n != null; n = n.getNext()) {
            int op = n.getOpcode();
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            switch (op) {
                case Opcodes.NOP, Opcodes.ACONST_NULL,
                     Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1,
                     Opcodes.ICONST_2, Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
                     Opcodes.LCONST_0, Opcodes.LCONST_1,
                     Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2,
                     Opcodes.DCONST_0, Opcodes.DCONST_1,
                     Opcodes.BIPUSH, Opcodes.SIPUSH, Opcodes.LDC,
                     Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD,
                     Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE,
                     Opcodes.POP, Opcodes.POP2, Opcodes.DUP, Opcodes.DUP_X1, Opcodes.DUP_X2,
                     Opcodes.DUP2, Opcodes.DUP2_X1, Opcodes.DUP2_X2, Opcodes.SWAP,
                     Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
                     Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR, Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR,
                     Opcodes.INEG, Opcodes.IINC,
                     Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
                     Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR, Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR,
                     Opcodes.LNEG, Opcodes.LCMP,
                     Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV, Opcodes.FREM, Opcodes.FNEG,
                     Opcodes.FCMPL, Opcodes.FCMPG,
                     Opcodes.DADD, Opcodes.DSUB, Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM, Opcodes.DNEG,
                     Opcodes.DCMPL, Opcodes.DCMPG,
                     Opcodes.I2L, Opcodes.I2F, Opcodes.I2D, Opcodes.L2I, Opcodes.L2F, Opcodes.L2D,
                     Opcodes.F2I, Opcodes.F2L, 141, Opcodes.D2I, 143, 144,
                     Opcodes.I2B, Opcodes.I2C, Opcodes.I2S,
                     Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
                     Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT,
                     Opcodes.IF_ICMPGE, Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE,
                     Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE, Opcodes.IFNULL, Opcodes.IFNONNULL,
                     Opcodes.GOTO, Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH,
                     Opcodes.RETURN,
                     Opcodes.ARRAYLENGTH,
                     Opcodes.IALOAD, Opcodes.LALOAD, Opcodes.FALOAD, Opcodes.DALOAD,
                     Opcodes.AALOAD, Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD,
                     Opcodes.IASTORE, Opcodes.LASTORE, Opcodes.FASTORE, Opcodes.DASTORE,
                     Opcodes.AASTORE, Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE,
                     Opcodes.NEWARRAY, Opcodes.ANEWARRAY,
                     Opcodes.CHECKCAST, Opcodes.INSTANCEOF,
                     Opcodes.GETSTATIC, Opcodes.PUTSTATIC,
                     Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL,
                     Opcodes.INVOKESTATIC, Opcodes.INVOKEINTERFACE,
                     Opcodes.NEW -> {  }
                     default -> { return "op:" + op; }
            }
            if (n instanceof FieldInsnNode f) {
                if (op == Opcodes.PUTSTATIC && !f.owner.equals(cn.name)) return "putstatic:" + f.owner;
                if (op == Opcodes.GETSTATIC && !f.owner.equals(cn.name) && !f.owner.startsWith("java/"))
                    return "getstatic:" + f.owner;
                if (op == Opcodes.GETFIELD || op == Opcodes.PUTFIELD) return "field:" + op;
            }
            if (n instanceof MethodInsnNode mi) {
                if (!isPureCall(mi)) return "call:" + mi.owner + "." + mi.name;
            }
            if (n instanceof TypeInsnNode t && op == Opcodes.NEW) {
                if (!t.desc.equals("java/lang/String") && !t.desc.equals("java/lang/StringBuilder")
                        && !t.desc.equals("java/lang/StringBuffer")) return "new:" + t.desc;
            }
            if (n instanceof InvokeDynamicInsnNode) return "indy";
            if (n instanceof MultiANewArrayInsnNode) return "multianewarray";
        }
        return null;
    }

    private static boolean isPureCall(MethodInsnNode mi) {
        String o = mi.owner;
        if (o.equals("java/lang/String") || o.equals("java/lang/StringBuilder")
                || o.equals("java/lang/StringBuffer") || o.equals("java/lang/Integer")
                || o.equals("java/lang/Long") || o.equals("java/lang/Float")
                || o.equals("java/lang/Double") || o.equals("java/lang/Character")
                || o.equals("java/lang/Boolean") || o.equals("java/lang/Math")
                || o.equals("java/util/Objects") || o.equals("java/util/Arrays")
                || o.equals("java/lang/Object")) return true;
        return false;
    }

    private static boolean emitValue(List<AbstractInsnNode> emit, String desc, Object v) {
        if (v == null || v == MiniInterpreter.NULL) {
            emit.add(new InsnNode(Opcodes.ACONST_NULL));
            return true;
        }
        if (v instanceof Integer i) { emit.add(new LdcInsnNode(i)); return true; }
        if (v instanceof Long l) { emit.add(new LdcInsnNode(l)); return true; }
        if (v instanceof Float f) { emit.add(new LdcInsnNode(f)); return true; }
        if (v instanceof Double d) { emit.add(new LdcInsnNode(d)); return true; }
        if (v instanceof String s) { emit.add(new LdcInsnNode(s)); return true; }
        if (v instanceof MiniInterpreter.Arr a) return emitArray(emit, desc, a.data);
        return false;
    }

    private static boolean emitArray(List<AbstractInsnNode> emit, String desc, Object data) {
        if (data instanceof int[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 10));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode(x[i]));
                emit.add(new InsnNode(Opcodes.IASTORE));
            }
            return true;
        }
        if (data instanceof long[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 11));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode(x[i]));
                emit.add(new InsnNode(Opcodes.LASTORE));
            }
            return true;
        }
        if (data instanceof byte[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 8));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode((int) x[i]));
                emit.add(new InsnNode(Opcodes.BASTORE));
            }
            return true;
        }
        if (data instanceof char[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 5));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode((int) x[i]));
                emit.add(new InsnNode(Opcodes.CASTORE));
            }
            return true;
        }
        if (data instanceof boolean[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 4));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode(x[i] ? 1 : 0));
                emit.add(new InsnNode(Opcodes.BASTORE));
            }
            return true;
        }
        if (data instanceof float[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 6));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode(x[i]));
                emit.add(new InsnNode(Opcodes.FASTORE));
            }
            return true;
        }
        if (data instanceof double[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 7));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode(x[i]));
                emit.add(new InsnNode(Opcodes.DASTORE));
            }
            return true;
        }
        if (data instanceof short[] x) {
            emit.add(new LdcInsnNode(x.length));
            emit.add(new IntInsnNode(Opcodes.NEWARRAY, 9));
            for (int i = 0; i < x.length; i++) {
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                emit.add(new LdcInsnNode((int) x[i]));
                emit.add(new InsnNode(Opcodes.SASTORE));
            }
            return true;
        }
        if (data instanceof Object[] x) {
            String elem = desc.equals("[Ljava/lang/String;") ? "java/lang/String"
                    : desc.equals("[Ljava/lang/Object;") ? "java/lang/Object"
                    : desc.equals("[Ljava/lang/Integer;") ? "java/lang/Integer"
                    : desc.equals("[Ljava/lang/Long;") ? "java/lang/Long" : null;
            if (elem == null) return false;
            emit.add(new LdcInsnNode(x.length));
            emit.add(new TypeInsnNode(Opcodes.ANEWARRAY, elem));
            for (int i = 0; i < x.length; i++) {
                Object e = x[i];
                if (e != null && !(e instanceof String) && !(e instanceof Integer) && !(e instanceof Long))
                    return false;
                emit.add(new InsnNode(Opcodes.DUP));
                emit.add(new LdcInsnNode(i));
                if (e == null) {
                    emit.add(new InsnNode(Opcodes.ACONST_NULL));
                } else if (e instanceof String s) {
                    emit.add(new LdcInsnNode(s));
                } else if (e instanceof Integer iv) {
                    emit.add(new LdcInsnNode(iv));
                    emit.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                            "valueOf", "(I)Ljava/lang/Integer;", false));
                } else {
                    emit.add(new LdcInsnNode((Long) e));
                    emit.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                            "valueOf", "(J)Ljava/lang/Long;", false));
                }
                emit.add(new InsnNode(Opcodes.AASTORE));
            }
            return true;
        }
        return false;
    }
}
