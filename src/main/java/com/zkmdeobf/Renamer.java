package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.*;

import java.util.*;
import java.util.regex.Pattern;

public final class Renamer {
    private Renamer() {}

    private static final Pattern OBF = Pattern.compile(
            "^[a-zA-Z]{1,2}$|^[IlO0$]{2,}$|.*\\$\\d+$|^[a-zA-Z]\\$[a-zA-Z]+$");
    private static final Set<String> KEEP_NAMES = Set.of(
            "add", "get", "set", "run", "foo", "id", "do", "ab", "of", "to",
            "main", "clone", "equals", "hashCode", "toString", "compareTo",
            "valueOf", "values", "value", "name", "ordinal", "describe",
            "iterator", "next", "hasNext", "close", "read", "write", "size",
            "isEmpty", "contains", "remove", "clear", "accept", "apply");

    public static boolean suspicious(String name) {
        if (name == null) return false;
        if (KEEP_NAMES.contains(name)) return false;
        // Object protocol must never be renamed: println(obj)/collections break otherwise.
        if (name.equals("toString") || name.equals("equals") || name.equals("hashCode")
                || name.equals("clone") || name.equals("finalize")) return false;
        return OBF.matcher(name).matches();
    }

    public static Map<String, String> buildMapping(Map<String, ClassNode> classes) {
        return buildMapping(classes, null);
    }

    public static Map<String, String> buildMapping(Map<String, ClassNode> classes,
                                                   ClassLoader loader) {
        Set<String> reflective = reflectiveNames(classes);
        Map<String, String> map = new HashMap<>();
        int ci = 0, mi = 0, fi = 0;
        List<String> names = new ArrayList<>(classes.keySet());
        Collections.sort(names);
        for (String n : names) {
            ClassNode cn = classes.get(n);
            String simple = cn.name.contains("/") ? cn.name.substring(cn.name.lastIndexOf('/') + 1) : cn.name;
            if (suspicious(simple) && !simple.equals("package-info") && !simple.equals("module-info")) {
                if (reflective.contains(cn.name.replace('/', '.'))
                        || reflective.contains(simple)) continue;
                String pkg = cn.name.contains("/") ? cn.name.substring(0, cn.name.lastIndexOf('/') + 1) : "";
                map.put(cn.name, pkg + "C" + String.format("%03d", ci++));
            }
        }
        for (String n : names) {
            ClassNode cn = classes.get(n);
            for (FieldNode f : cn.fields) {
                if (suspicious(f.name)) {
                    if (reflective.contains(f.name)) continue;
                    String t = f.desc.length() > 12 ? f.desc.substring(0, 12) : f.desc;
                    t = t.replace('/', '_').replace(';', '_').replace('[', 'A');
                    map.put(cn.name + "." + f.name, "f_" + String.format("%03d", fi++) + "_" + t);
                }
            }
            for (MethodNode m : cn.methods) {
                if (m.name.equals("<init>") || m.name.equals("<clinit>")) continue;
                if (m.name.equals("main") && m.desc.equals("([Ljava/lang/String;)V")) continue;
                // Native methods are bound by name (JNI); renaming breaks linkage.
                if ((m.access & Opcodes.ACC_NATIVE) != 0) continue;
                if (suspicious(m.name)) {
                    if (reflective.contains(m.name)) continue;
                    if (overridesSuper(classes, loader, cn, m)) continue;
                    map.put(cn.name + "." + m.name + m.desc,
                            "m_" + String.format("%03d", mi++));
                }
            }
        }
        return map;
    }

    static boolean overridesSuper(Map<String, ClassNode> classes, ClassLoader loader,
                                   ClassNode cn, MethodNode m) {
        if ((m.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) return false;
        if (m.name.startsWith("<")) return false;
        // Object protocol: conservative keep even when superclass is outside the jar.
        if ((m.name.equals("toString") && m.desc.equals("()Ljava/lang/String;"))
                || (m.name.equals("equals") && m.desc.equals("(Ljava/lang/Object;)Z"))
                || (m.name.equals("hashCode") && m.desc.equals("()I"))
                || (m.name.equals("clone") && m.desc.equals("()Ljava/lang/Object;"))) return true;
        Set<String> seen = new HashSet<>();
        String sup = cn.superName;
        while (sup != null && !sup.equals("java/lang/Object") && seen.add(sup)) {
            ClassNode scn = classes.get(sup + ".class");
            if (scn == null) break;
            for (MethodNode sm : scn.methods) {
                if (sm.name.equals(m.name) && sm.desc.equals(m.desc)
                        && (sm.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) == 0) return true;
            }
            if (scn.interfaces != null) {
                for (String itf : scn.interfaces) {
                    ClassNode icn = classes.get(itf + ".class");
                    if (icn != null) for (MethodNode sm : icn.methods) {
                        if (sm.name.equals(m.name) && sm.desc.equals(m.desc)) return true;
                    }
                }
            }
            sup = scn.superName;
        }
        if (cn.interfaces != null) {
            for (String itf : cn.interfaces) {
                ClassNode icn = classes.get(itf + ".class");
                if (icn != null) for (MethodNode sm : icn.methods) {
                    if (sm.name.equals(m.name) && sm.desc.equals(m.desc)) return true;
                }
            }
        }
        if (loader != null) {
            try {
                Class<?> c = Class.forName(cn.name.replace('/', '.'), false, loader);
                Class<?>[] ps = toClasses(Type.getArgumentTypes(m.desc), loader);
                for (Class<?> s = c.getSuperclass(); s != null && s != Object.class; s = s.getSuperclass()) {
                    try {
                        java.lang.reflect.Method dm = s.getDeclaredMethod(m.name, ps);
                        int mo = dm.getModifiers();
                        if (!java.lang.reflect.Modifier.isPrivate(mo)
                                && !java.lang.reflect.Modifier.isStatic(mo)) return true;
                    } catch (NoSuchMethodException ignored) {}
                }
                for (Class<?> itf : c.getInterfaces()) {
                    try {
                        itf.getDeclaredMethod(m.name, ps);
                        return true;
                    } catch (NoSuchMethodException ignored) {}
                }
            } catch (Throwable ignored) {}
            // Unknown hierarchy: conservative keep, never rename.
            return true;
        }
        return false;
    }

    private static Class<?>[] toClasses(Type[] ts, ClassLoader loader) throws ClassNotFoundException {
        Class<?>[] o = new Class<?>[ts.length];
        for (int i = 0; i < ts.length; i++) o[i] = toClass(ts[i], loader);
        return o;
    }

    private static Class<?> toClass(Type t, ClassLoader loader) throws ClassNotFoundException {
        return switch (t.getSort()) {
            case Type.VOID -> void.class;
            case Type.BOOLEAN -> boolean.class;
            case Type.CHAR -> char.class;
            case Type.BYTE -> byte.class;
            case Type.SHORT -> short.class;
            case Type.INT -> int.class;
            case Type.FLOAT -> float.class;
            case Type.LONG -> long.class;
            case Type.DOUBLE -> double.class;
            case Type.ARRAY -> Class.forName(t.getDescriptor().replace('/', '.'), false, loader);
            default -> Class.forName(t.getClassName(), false, loader);
        };
    }
    static Set<String> reflectiveNames(Map<String, ClassNode> classes) {
        boolean usesReflection = false;
        Set<String> strings = new HashSet<>();
        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof LdcInsnNode l && l.cst instanceof String s) {
                        strings.add(s);
                        if (s.contains(".") || s.length() <= 3) strings.add(s);
                    }
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
                            usesReflection = true;
                        }
                    }
                }
            }
        }
        if (!usesReflection) return Set.of();

        Set<String> o = new HashSet<>();
        for (String s : strings) {
            if (s.matches("^[A-Za-z_$][A-Za-z0-9_$]{0,7}$")) o.add(s);

            if (s.contains(".")) {
                String simple = s.substring(s.lastIndexOf('.') + 1);
                if (simple.matches("^[A-Za-z_$][A-Za-z0-9_$]{0,7}$")) o.add(simple);
            }
            if (s.contains("/")) {
                String simple = s.substring(s.lastIndexOf('/') + 1).replace(";", "");
                if (simple.matches("^[A-Za-z_$][A-Za-z0-9_$]{0,7}$")) o.add(simple);
            }
        }
        return o;
    }

    public static Map<String, ClassNode> apply(Map<String, ClassNode> classes, Map<String, String> mapping) {
        SimpleRemapper remapper = new SimpleRemapper(mapping);
        Map<String, ClassNode> out = new LinkedHashMap<>();
        for (Map.Entry<String, ClassNode> e : classes.entrySet()) {
            ClassNode cn = new ClassNode();
            e.getValue().accept(new org.objectweb.asm.commons.ClassRemapper(cn, remapper));
            out.put(cn.name + ".class", cn);
        }
        return out;
    }
}
