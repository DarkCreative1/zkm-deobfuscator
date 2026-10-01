package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URLClassLoader;
import java.util.*;

public final class ReferenceResolver {
    private ReferenceResolver() {}

    public static boolean isResolverClass(ClassNode cn) {
        boolean hasIdx = false, hasRes = false;
        for (MethodNode m : cn.methods) {
            org.objectweb.asm.Type[] at = org.objectweb.asm.Type.getArgumentTypes(m.desc);
            boolean allLong = at.length >= 1;
            for (org.objectweb.asm.Type t : at) if (t.getSort() != org.objectweb.asm.Type.LONG) { allLong = false; break; }
            if (!allLong) continue;
            if (org.objectweb.asm.Type.getReturnType(m.desc).getSort() == org.objectweb.asm.Type.INT) hasIdx = true;
            String ret = org.objectweb.asm.Type.getReturnType(m.desc).getInternalName();
            if (ret.equals("java/lang/Class") || ret.equals("java/lang/reflect/Field")
                    || ret.equals("java/lang/reflect/Method")
                    || ret.equals("java/lang/reflect/Constructor")) hasRes = true;
        }
        return hasIdx && hasRes;
    }

    public record IndySite(MethodNode m, InvokeDynamicInsnNode indy,
                           List<AbstractInsnNode> keyPushes, List<Long> keys, String resolverClass) {}

    public static List<IndySite> indySites(Map<String, ClassNode> classes, ClassNode cn, MethodNode m) {
        List<IndySite> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(m);

        List<Integer> realIdx = new ArrayList<>();
        for (int i = 0; i < ins.size(); i++) {
            AbstractInsnNode n = ins.get(i);
            if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
            if (n.getOpcode() == Opcodes.NOP) continue;
            realIdx.add(i);
        }
        for (int r = 0; r < realIdx.size(); r++) {
            int k = realIdx.get(r);
            AbstractInsnNode n = ins.get(k);
            if (n.getOpcode() != Opcodes.INVOKEDYNAMIC || !(n instanceof InvokeDynamicInsnNode)) continue;
            InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) n;
            String bsmOwner = id.bsm.getOwner();
            if (bsmOwner.startsWith("java/lang/invoke/")) continue;
            ClassNode rc = classes.get(bsmOwner + ".class");
            if (rc == null || !isResolverClass(rc)) continue;

            Type[] args = Type.getArgumentTypes(id.desc);
            if (args.length == 0 || args[args.length - 1].getSort() != Type.LONG) continue;
            int nk = 1;
            while (args.length - 1 - nk >= 0 && args[args.length - 1 - nk].getSort() == Type.LONG) nk++;
            if (nk > 4 || r < nk) continue;
            List<AbstractInsnNode> pushes = new ArrayList<>();
            List<Long> keys = new ArrayList<>();
            boolean ok = true;
            for (int j = r - nk; j < r; j++) {
                AbstractInsnNode pk = ins.get(realIdx.get(j));
                Long key = longKey(pk);
                if (key == null) { ok = false; break; }
                pushes.add(pk);
                keys.add(key);
            }
            if (!ok) continue;
            o.add(new IndySite(m, id, pushes, keys, rc.name));
        }
        return o;
    }

    private static Long longKey(AbstractInsnNode pk) {
        if (pk instanceof LdcInsnNode l && l.cst instanceof Long lo) return lo;
        Integer v = ClassIO.constInt(pk);
        if (v != null) return (long) v;
        return null;
    }

    public record Resolved(Method method, java.lang.reflect.Field field,
                           Class<?> clazz, java.lang.reflect.Constructor<?> ctor) {
        public Resolved(Method method, java.lang.reflect.Field field) {
            this(method, field, null, null);
        }
    }

    public static Resolved resolve(URLClassLoader dyn, String resolverClass, long... keys) {
        try {
            Class<?> c = Class.forName(resolverClass.replace('/', '.'), true, dyn);
            for (Method m : c.getDeclaredMethods()) {
                if (!Modifier.isStatic(m.getModifiers()) || m.getParameterCount() != keys.length) continue;
                boolean allLong = true;
                for (Class<?> p : m.getParameterTypes()) if (p != long.class) { allLong = false; break; }
                if (!allLong) continue;
                m.setAccessible(true);
                try {
                    Object[] box = new Object[keys.length];
                    for (int i = 0; i < keys.length; i++) box[i] = keys[i];
                    if (m.getReturnType() == java.lang.reflect.Method.class) {
                        Object r = m.invoke(null, box);
                        if (r != null) return new Resolved((java.lang.reflect.Method) r, null);
                    } else if (m.getReturnType() == java.lang.reflect.Field.class) {
                        Object r = m.invoke(null, box);
                        if (r != null) return new Resolved(null, (java.lang.reflect.Field) r, null, null);
                    } else if (m.getReturnType() == Class.class) {
                        Object r = m.invoke(null, box);
                        if (r != null) return new Resolved(null, null, (Class<?>) r, null);
                    } else if (m.getReturnType() == java.lang.reflect.Constructor.class) {
                        Object r = m.invoke(null, box);
                        if (r != null)
                            return new Resolved(null, null, null, (java.lang.reflect.Constructor<?>) r);
                    }
                } catch (Exception ignored) {}
            }
        } catch (Throwable t) {  }
        return null;
    }

    public static Resolved resolveStatic(Map<String, ClassNode> classes,
                                         URLClassLoader loader,
                                         String resolverClass, long... keys) {
        try {
            ClassNode rc = classes.get(resolverClass + ".class");
            if (rc == null || !isResolverClass(rc)) return null;
            MiniInterpreter.Ctx ctx = new MiniInterpreter.Ctx(classes, loader, 0);
            MethodNode cl = ClassIO.findMethod(rc, "<clinit>", "()V");
            if (cl != null) {
                try {
                    MiniInterpreter.run(ctx, rc, cl, new Object[0]);
                } catch (MiniInterpreter.Bail b) {
                    return null;
                }
            }

            Object[] box = new Object[keys.length];
            for (int i = 0; i < keys.length; i++) box[i] = keys[i];
            for (MethodNode m : rc.methods) {
                if ((m.access & Opcodes.ACC_STATIC) == 0) continue;
                org.objectweb.asm.Type[] at = org.objectweb.asm.Type.getArgumentTypes(m.desc);
                if (at.length != keys.length) continue;
                boolean allLong = true;
                for (org.objectweb.asm.Type t : at) if (t.getSort() != org.objectweb.asm.Type.LONG) { allLong = false; break; }
                if (!allLong) continue;
                org.objectweb.asm.Type rt = org.objectweb.asm.Type.getReturnType(m.desc);
                boolean wantM = rt.getInternalName().equals("java/lang/reflect/Method");
                boolean wantF = rt.getInternalName().equals("java/lang/reflect/Field");
                boolean wantC = rt.getInternalName().equals("java/lang/Class");
                if (!wantM && !wantF && !wantC) continue;
                try {
                    Object r = MiniInterpreter.run(ctx, rc, m, box);
                    if (r instanceof java.lang.reflect.Method mm) return new Resolved(mm, null);
                    if (r instanceof java.lang.reflect.Field ff) return new Resolved(null, ff, null, null);
                    if (r instanceof Class cc) return new Resolved(null, null, cc, null);
                } catch (MiniInterpreter.Bail b) {

                }
            }
        } catch (Throwable t) {  }
        return null;
    }

    public static boolean inlineIndy(MethodNode m, InvokeDynamicInsnNode indy,
                                     List<AbstractInsnNode> keyPushes, Resolved r) {
        if (Rewriter.hasJsrRet(m)) return false;
        Type[] iargs = Type.getArgumentTypes(indy.desc);
        Type iret = Type.getReturnType(indy.desc);

        AbstractInsnNode first = keyPushes.get(0);

        Set<LabelNode> bounds = new HashSet<>();
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            bounds.add(t.start); bounds.add(t.end); bounds.add(t.handler);
        }
        Set<LabelNode> tgts = ClassIO.jumpTargets(m);
        AbstractInsnNode n = first;
        while (true) {
            if (n instanceof LabelNode && (bounds.contains(n) || tgts.contains(n))) return false;
            if (n == indy) break;
            n = n.getNext();
            if (n == null) return false;
        }
        n = first.getNext();
        while (n != null && n != indy.getNext()) {
            if (n instanceof LabelNode && (bounds.contains(n) || tgts.contains(n))) return false;
            n = n.getNext();
        }
        if (r.method() != null) {
            MethodInsnNode direct = buildDirect(r, iargs, iret, keyPushes.size());
            if (direct == null) return false;
            List<AbstractInsnNode> pre = buildCasts(r, iargs, iret, keyPushes.size());
            if (pre == null) return false;
            AbstractInsnNode anchor = first;
            for (AbstractInsnNode c : pre) { m.instructions.insertBefore(anchor, c); }
            m.instructions.insertBefore(anchor, direct);
            List<AbstractInsnNode> del = new ArrayList<>(keyPushes);
            del.add(indy);
            for (AbstractInsnNode d : del) m.instructions.remove(d);
            return true;
        }
        if (r.field() != null) {
            AbstractInsnNode direct = buildFieldDirect(r, iargs, iret, keyPushes.size());
            if (direct == null) return false;
            AbstractInsnNode anchor = first;
            m.instructions.insertBefore(anchor, direct);
            List<AbstractInsnNode> del = new ArrayList<>(keyPushes);
            del.add(indy);
            for (AbstractInsnNode d : del) m.instructions.remove(d);
            return true;
        }
        if (r.clazz() != null) {
            int nKeys = keyPushes.size();
            int nReal = iargs.length - nKeys;
            if (nReal != 0 || !iret.equals(Type.getType(Class.class))) return false;
            AbstractInsnNode anchor = first;
            m.instructions.insertBefore(anchor,
                    new LdcInsnNode(Type.getType("L" + r.clazz().getName().replace('.', '/') + ";")));
            List<AbstractInsnNode> del = new ArrayList<>(keyPushes);
            del.add(indy);
            for (AbstractInsnNode d : del) m.instructions.remove(d);
            return true;
        }
        if (r.ctor() != null) {

            int nKeys = keyPushes.size();
            int nReal = iargs.length - nKeys;
            if (nReal != 0) return false;
            if (r.ctor().getParameterCount() != 0) return false;
            String owner = r.ctor().getDeclaringClass().getName().replace('.', '/');
            AbstractInsnNode anchor = first;
            m.instructions.insertBefore(anchor, new TypeInsnNode(Opcodes.NEW, owner));
            m.instructions.insertBefore(anchor, new InsnNode(Opcodes.DUP));
            m.instructions.insertBefore(anchor, new MethodInsnNode(Opcodes.INVOKESPECIAL,
                    owner, "<init>", "()V", false));
            List<AbstractInsnNode> del = new ArrayList<>(keyPushes);
            del.add(indy);
            for (AbstractInsnNode d : del) m.instructions.remove(d);
            return true;
        }
        return false;
    }

    static AbstractInsnNode buildFieldDirect(Resolved r, Type[] iargs, Type iret, int nKeys) {
        java.lang.reflect.Field f = r.field();
        if (f == null) return null;
        String owner = f.getDeclaringClass().getName().replace('.', '/');
        String desc = Type.getDescriptor(f.getType());
        boolean statik = Modifier.isStatic(f.getModifiers());
        int nReal = iargs.length - nKeys;
        if (statik) {

            if (nReal == 0 && iret.equals(Type.getType(desc)))
                return new FieldInsnNode(Opcodes.GETSTATIC, owner, f.getName(), desc);
            if (nReal == 1 && iargs[0].equals(Type.getType(desc))
                    && iret.equals(Type.VOID_TYPE))
                return new FieldInsnNode(Opcodes.PUTSTATIC, owner, f.getName(), desc);
            return null;
        }

        if (nReal == 1 && iret.equals(Type.getType(desc)))
            return new FieldInsnNode(Opcodes.GETFIELD, owner, f.getName(), desc);
        if (nReal == 2 && iret.equals(Type.VOID_TYPE))
            return new FieldInsnNode(Opcodes.PUTFIELD, owner, f.getName(), desc);
        return null;
    }

    private static MethodInsnNode buildDirect(Resolved r, Type[] iargs, Type iret, int nKeys) {
        int nReal = iargs.length - nKeys;
        if (r.method() != null) {
            java.lang.reflect.Method mm = r.method();
            String owner = mm.getDeclaringClass().getName().replace('.', '/');
            String desc = Type.getMethodDescriptor(mm);
            Type[] real = Type.getArgumentTypes(desc);
            boolean statik = Modifier.isStatic(mm.getModifiers());

            if (statik && real.length != nReal) return null;
            if (!statik && real.length + 1 != nReal) return null;
            if (!Type.getReturnType(desc).equals(iret)) return null;
            if (statik) return new MethodInsnNode(Opcodes.INVOKESTATIC, owner, mm.getName(), desc, false);
            if (mm.getDeclaringClass().isInterface())
                return new MethodInsnNode(Opcodes.INVOKEINTERFACE, owner, mm.getName(), desc, true);
            if (Modifier.isPrivate(mm.getModifiers()))
                return new MethodInsnNode(Opcodes.INVOKESPECIAL, owner, mm.getName(), desc, false);
            return new MethodInsnNode(Opcodes.INVOKEVIRTUAL, owner, mm.getName(), desc, false);
        }
        return null;
    }

    private static List<AbstractInsnNode> buildCasts(Resolved r, Type[] iargs, Type iret, int nKeys) {
        List<AbstractInsnNode> o = new ArrayList<>();
        if (r.method() != null) {
            java.lang.reflect.Method mm = r.method();
            Type[] real = Type.getArgumentTypes(Type.getMethodDescriptor(mm));
            boolean statik = Modifier.isStatic(mm.getModifiers());
            int off = statik ? 0 : 1;
            if (!statik) {

                Type have = iargs[0];
                Type want = Type.getObjectType(mm.getDeclaringClass().getName().replace('.', '/'));
                if (!have.equals(want) && !isWidening(have, want)) return null;
            }

            for (int i = 0; i < real.length; i++) {
                Type want = real[i];
                Type have = iargs[off + i];
                if (have.equals(want) || isWidening(have, want)) continue;
                if (i != real.length - 1) return null;
                if (want.getSort() == Type.OBJECT || want.getSort() == Type.ARRAY) {
                    o.add(new TypeInsnNode(Opcodes.CHECKCAST, want.getInternalName()));
                } else {
                    return null;
                }
            }
        }
        return o;
    }

    private static boolean isWidening(Type have, Type want) {
        if (have.equals(want)) return true;
        if (want.getSort() == Type.OBJECT && want.getInternalName().equals("java/lang/Object")) return true;
        return false;
    }
}
