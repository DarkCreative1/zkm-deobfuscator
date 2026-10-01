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

    public static Map<String, ClassNode> readJar(String path) throws IOException {
        Map<String, ClassNode> out = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(path)) {
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                try (InputStream in = jar.getInputStream(e)) {
                    ClassNode cn = new ClassNode();
                    new ClassReader(in).accept(cn, 0);
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
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                try (InputStream in = jar.getInputStream(e)) {
                    out.put(e.getName(), in.readAllBytes());
                }
            }
        }
        return out;
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

    public static void writeJar(String path, Map<String, byte[]> entries) throws IOException {
        File f = new File(path);
        File parent = f.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory())
            throw new IOException("cannot create directory: " + parent);
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(f))) {
            List<String> names = new ArrayList<>(entries.keySet());
            Collections.sort(names);
            for (String n : names) {
                out.putNextEntry(new JarEntry(n));
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
        return o;
    }
}
