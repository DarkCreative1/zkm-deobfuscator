package com.zkmdeobf;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

public final class ClassIO {
    private ClassIO() {}

    // Upper bounds for untrusted inputs: a single class file above this, or a
    // jar above the total, is rejected instead of OOMing the host.
    public static final long MAX_ENTRY_BYTES = 64L << 20;
    public static final long MAX_JAR_BYTES = 512L << 20;
    public static final int MAX_JAR_ENTRIES = 200000;

    public static Map<String, ClassNode> readJar(String path) throws IOException {
        Map<String, ClassNode> out = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(path)) {
            Enumeration<JarEntry> en = jar.entries();
            long total = 0;
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                if (out.size() > MAX_JAR_ENTRIES)
                    throw new IOException("jar entry limit exceeded: " + path);
                try (InputStream in = jar.getInputStream(e)) {
                    byte[] b = readCapped(in, MAX_ENTRY_BYTES, e.getName());
                    total += b.length;
                    if (total > MAX_JAR_BYTES)
                        throw new IOException("jar size limit exceeded: " + path);
                    ClassNode cn = new ClassNode();
                    new ClassReader(b).accept(cn, 0);
                    out.put(e.getName(), cn);
                }
            }
        }
        return out;
    }

    public static Map<String, byte[]> readRaw(String path) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(path)) {
            Enumeration<JarEntry> en = jar.entries();
            long total = 0;
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (out.size() > MAX_JAR_ENTRIES)
                    throw new IOException("jar entry limit exceeded: " + path);
                try (InputStream in = jar.getInputStream(e)) {
                    byte[] b = readCapped(in, MAX_ENTRY_BYTES, e.getName());
                    total += b.length;
                    if (total > MAX_JAR_BYTES)
                        throw new IOException("jar size limit exceeded: " + path);
                    out.put(e.getName(), b);
                }
            }
        }
        return out;
    }

    static byte[] readCapped(InputStream in, long cap, String what) throws IOException {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        long n = 0;
        int r;
        while ((r = in.read(buf)) >= 0) {
            n += r;
            if (n > cap) throw new IOException("entry too large: " + what);
            o.write(buf, 0, r);
        }
        return o.toByteArray();
    }

    public static byte[] toBytes(ClassNode cn) {
        ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES) {
            @Override
            protected String getCommonSuperClass(String t1, String t2) {
                try { return super.getCommonSuperClass(t1, t2); }
                catch (Exception e) { return "java/lang/Object"; }
            }
        };
        cn.accept(w);
        return w.toByteArray();
    }

    public static final long FIXED_TIME = 1000L * 60 * 60 * 24 * 365 * 30;

    public static void writeJar(String path, Map<String, byte[]> entries) throws IOException {
        File f = new File(path);
        File parent = f.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory())
            throw new IOException("cannot create directory: " + parent);
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(f))) {
            List<String> names = new ArrayList<>(entries.keySet());
            Collections.sort(names);
            for (String n : names) {
                JarEntry e = new JarEntry(n);
                e.setTime(FIXED_TIME);
                out.putNextEntry(e);
                out.write(entries.get(n));
                out.closeEntry();
            }
        }
    }

    public static MethodNode findMethod(ClassNode cn, String name, String desc) {
        for (MethodNode m : cn.methods) if (m.name.equals(name) && m.desc.equals(desc)) return m;
        return null;
    }

    public static FieldNode findField(ClassNode cn, String name) {
        for (FieldNode f : cn.fields) if (f.name.equals(name)) return f;
        return null;
    }

    public static List<AbstractInsnNode> list(MethodNode m) {
        List<AbstractInsnNode> o = new ArrayList<>();
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) o.add(n);
        return o;
    }

    public static Integer constInt(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - 3;
        if (n instanceof IntInsnNode) {
            IntInsnNode x = (IntInsnNode) n;
            if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return x.operand;
        }
        if (n instanceof LdcInsnNode) {
            Object c = ((LdcInsnNode) n).cst;
            if (c instanceof Integer) return (Integer) c;
        }
        return null;
    }

    public static Long constLong(MethodNode m, List<AbstractInsnNode> ins, int k) {
        if (ins == null || k < 0 || k >= ins.size()) return null;
        AbstractInsnNode n = ins.get(k);
        if (n instanceof LdcInsnNode) {
            Object c = ((LdcInsnNode) n).cst;
            if (c instanceof Long) return (Long) c;
        }
        return null;
    }

    public static String methodKey(MethodInsnNode n) {
        return n.owner + "." + n.name + n.desc;
    }

    public static String fieldKey(FieldInsnNode n) {
        return n.owner + "." + n.name + ":" + n.desc;
    }

    public static Set<LabelNode> jumpTargets(MethodNode m) {
        Set<LabelNode> o = new HashSet<>();
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof JumpInsnNode) o.add(((JumpInsnNode) n).label);
            else if (n instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode t = (TableSwitchInsnNode) n;
                o.add(t.dflt);
                o.addAll(t.labels);
            } else if (n instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode t = (LookupSwitchInsnNode) n;
                o.add(t.dflt);
                o.addAll(t.labels);
            }
        }
        // Exception handler labels are jump targets too; omitting them lets
        // dead-code elimination delete live handler blocks -> VerifyError.
        if (m.tryCatchBlocks != null) for (TryCatchBlockNode t : m.tryCatchBlocks) {
            o.add(t.start); o.add(t.end); o.add(t.handler);
        }
        return o;
    }
}
