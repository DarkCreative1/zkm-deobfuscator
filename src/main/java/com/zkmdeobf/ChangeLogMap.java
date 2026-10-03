package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public final class ChangeLogMap {
    private ChangeLogMap() {}

    public final Map<String, String> classes = new LinkedHashMap<>();

    public final Map<String, String> byOrig = new LinkedHashMap<>();

    public final Map<String, String> methods = new LinkedHashMap<>();

    public final Map<String, String> methodsByName = new LinkedHashMap<>();

    public final Map<String, String> fields = new LinkedHashMap<>();

    public final Map<String, String> fieldsByName = new LinkedHashMap<>();

    public final Map<String, String> sources = new LinkedHashMap<>();

    public final Set<String> manufacturedFields = new HashSet<>();

    private static final Pattern CLASS_MAP =
            Pattern.compile("^Class:\\s+.*?([\\w.$]+)\\s+=>\\s+([\\w.$/]+)\\s*$");
    private static final Pattern CLASS_SAME =
            Pattern.compile("^Class:\\s+.*?([\\w.$]+)\\s+SignatureNotChanged:.*$");
    private static final Pattern SOURCE =
            Pattern.compile("^Source:\\s+\"([^\"]+)\"\\s*$");
    private static final Pattern SECTION =
            Pattern.compile("^(?:Methods|Fields)Of:\\s+([\\w.$]+)\\s*$");
    private static final Pattern DECL =
            Pattern.compile("^(?:(.*?)\\s+)?([\\w$<>]+)\\((.*)\\)\\s*$");

    public static ChangeLogMap parse(String path) throws IOException {
        ChangeLogMap m = new ChangeLogMap();
        List<String> lines = Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8);
        String ctxOrig = null, ctxObf = null;
        boolean inMethods = false, inFields = false;
        for (String raw : lines) {
            String t = raw.trim();
            if (t.isEmpty() || t.startsWith("//") || t.startsWith("Module:")
                    || t.startsWith("TraceBackClass:") || t.startsWith("ForwardClass:")
                    || t.startsWith("MemberClass:") || t.startsWith("MethodParameterChangeClasses:")) continue;
            Matcher mc = CLASS_MAP.matcher(t);
            if (mc.matches()) {
                ctxOrig = mc.group(1);
                ctxObf = mc.group(2).replace('.', '/');
                m.classes.put(ctxObf, ctxOrig.replace('.', '/'));
                m.byOrig.put(ctxOrig, ctxObf);
                inMethods = inFields = false;
                continue;
            }
            Matcher ms = CLASS_SAME.matcher(t);
            if (ms.matches()) {
                ctxOrig = ms.group(1);
                ctxObf = ctxOrig.replace('.', '/');
                m.classes.put(ctxObf, ctxObf);
                m.byOrig.put(ctxOrig, ctxObf);
                inMethods = inFields = false;
                continue;
            }
            Matcher sc = SECTION.matcher(t);
            if (sc.matches()) {
                String orig = sc.group(1);
                String obf = m.byOrig.get(orig);
                if (obf != null) { ctxOrig = orig; ctxObf = obf; }
                else { ctxOrig = null; ctxObf = null; }
                inMethods = t.startsWith("Methods");
                inFields = t.startsWith("Fields");
                continue;
            }
            Matcher so = SOURCE.matcher(t);
            if (so.matches()) {
                if (ctxObf != null) m.sources.put(ctxObf, so.group(1));
                continue;
            }
            if (t.contains("Manufactured:")) {

                if (inFields && ctxObf != null) {
                    String fn = manufacturedFieldName(t);
                    if (fn != null) m.manufacturedFields.add(ctxObf + "." + fn);
                }
                continue;
            }
            if (ctxObf == null) continue;
            if (inMethods) m.parseMethod(ctxObf, t);
            else if (inFields) m.parseField(ctxObf, t);
        }
        return m;
    }

    public final Set<String> originalFields = new HashSet<>();

    private static String manufacturedFieldName(String t) {
        int mi = t.indexOf("Manufactured:");
        String s = (mi >= 0 ? t.substring(0, mi) : t).trim();
        int arrow = s.lastIndexOf("=>");
        if (arrow >= 0) {
            String right = s.substring(arrow + 2).trim();
            if (!right.isEmpty()) return right.split("\\s+")[0];
            return null;
        }

        int ni = s.indexOf("NameNotChanged");
        if (ni >= 0) {
            String[] toks = s.substring(0, ni).trim().split("\\s+");
            if (toks.length > 0) return toks[toks.length - 1];
        }
        return null;
    }

    private void parseMethod(String obfOwner, String line) {
        String[] seg = line.split("\t=>\t");
        if (seg.length < 2) return;
        Matcher d0 = DECL.matcher(seg[0].trim());
        if (!d0.matches()) return;
        String origMods = d0.group(1) == null ? "" : d0.group(1).trim();
        String origName = d0.group(2);
        String origParams = d0.group(3);
        String origRet = origMods.contains(" ") ? origMods.substring(origMods.lastIndexOf(' ') + 1) : "void";
        String last = stripMarkers(seg[seg.length - 1].trim());
        Matcher d1 = DECL.matcher(last);
        if (!d1.matches()) return;
        String obfName = d1.group(2);
        String obfParams = d1.group(3);
        String obfDesc = null;
        if (seg.length >= 3) obfDesc = extractJvmDesc(seg[seg.length - 2]);
        if (obfDesc == null) {
            try {
                obfDesc = "(" + paramsToDesc(obfParams) + ")" + toDesc(origRet);
            } catch (IllegalArgumentException e) {
                obfDesc = null;
            }
        }
        if (origName.equals(obfName) && obfDesc != null) {
            try {
                String od = "(" + paramsToDesc(origParams) + ")" + toDesc(origRet);
                if (od.equals(obfDesc)) return;
            } catch (IllegalArgumentException e) {  }
        }
        if (obfDesc != null) methods.put(obfOwner + "." + obfName + obfDesc, origName);

        try {
            String origDesc = "(" + paramsToDesc(origParams) + ")" + toDesc(origRet);
            String k2 = obfOwner + "." + obfName + origDesc;
            String prev2 = methods.get(k2);
            if (prev2 == null || prev2.equals(origName)) methods.put(k2, origName);
        } catch (IllegalArgumentException ignored) {  }
        String fbKey = obfOwner + "." + obfName;
        if (methodsByName.containsKey(fbKey)) methodsByName.put(fbKey, null);
        else methodsByName.put(fbKey, origName);
    }

    private void parseField(String obfOwner, String line) {
        String[] seg = line.split("\t=>\t");
        if (seg.length < 2) return;

        String left = seg[0].trim();
        int sp = left.lastIndexOf(' ');
        if (sp < 0) return;
        String origName = left.substring(sp + 1);
        String typePart = left.substring(0, sp);
        int sp2 = typePart.lastIndexOf(' ');
        String origType = sp2 < 0 ? typePart : typePart.substring(sp2 + 1);
        String obfName = stripMarkers(seg[seg.length - 1].trim());
        if (obfName.isEmpty()) return;
        String obfDesc;
        try {
            obfDesc = toDesc(origType);
        } catch (IllegalArgumentException e) {
            return;
        }
        fields.put(obfOwner + "." + obfName + obfDesc, origName);
        originalFields.add(obfOwner + "." + obfName);
        String fbKey = obfOwner + "." + obfName;
        if (fieldsByName.containsKey(fbKey)) fieldsByName.put(fbKey, null);
        else fieldsByName.put(fbKey, origName);
    }

    private static String stripMarkers(String s) {
        int i = s.indexOf(" Manufactured:");
        if (i >= 0) s = s.substring(0, i);
        i = s.indexOf(" ::");
        if (i >= 0) s = s.substring(0, i);
        i = s.indexOf(" :");
        if (i >= 0) s = s.substring(0, i);
        s = s.trim();
        if (s.endsWith("*")) s = s.substring(0, s.length() - 1).trim();
        return s;
    }

    private static String extractJvmDesc(String seg) {
        int i = seg.indexOf('(');
        if (i < 0) return null;
        String d = seg.substring(i).trim();
        if (!d.matches("\\(.*\\).*")) return null;
        try {
            org.objectweb.asm.Type.getMethodDescriptor(
                    org.objectweb.asm.Type.getReturnType(d),
                    org.objectweb.asm.Type.getArgumentTypes(d));
            return d;
        } catch (Exception e) {
            return null;
        }
    }

    private static String stripGenerics(String s) {
        StringBuilder o = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') { if (depth > 0) depth--; }
            else if (depth == 0) o.append(c);
        }
        return o.toString();
    }

    static String paramsToDesc(String params) {
        params = params.trim();
        if (params.isEmpty()) return "";
        StringBuilder o = new StringBuilder();
        for (String p : splitTop(params)) o.append(toDesc(p.trim()));
        return o.toString();
    }

    private static List<String> splitTop(String s) {
        List<String> o = new ArrayList<>();
        int depth = 0, start = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') depth--;
            else if (c == ',' && depth == 0) {
                o.add(s.substring(start, i));
                start = i + 1;
            }
        }
        o.add(s.substring(start));
        return o;
    }

    static String toDesc(String src) {
        if (src == null || src.isEmpty()) throw new IllegalArgumentException("empty desc");
        src = src.trim();
        if (src.endsWith("...")) src = src.substring(0, src.length() - 3).trim() + "[]";
        // Strip generics: List<String> -> List, Map<K,V> -> Map, ? extends X -> X.
        src = stripGenerics(src).trim();
        if (src.startsWith("?")) {
            if (src.startsWith("? extends ")) src = src.substring(10).trim();
            else if (src.startsWith("? super ")) src = src.substring(8).trim();
            else src = "java.lang.Object";
            src = stripGenerics(src).trim();
        }
        int arr = 0;
        while (src.endsWith("[]")) {
            arr++;
            src = src.substring(0, src.length() - 2).trim();
        }
        String base = switch (src) {
            case "byte" -> "B";
            case "short" -> "S";
            case "int" -> "I";
            case "long" -> "J";
            case "float" -> "F";
            case "double" -> "D";
            case "char" -> "C";
            case "boolean" -> "Z";
            case "void" -> "V";
            default -> "L" + src.replace('.', '/') + ";";
        };
        return "[".repeat(arr) + base;
    }

    private String origTypes(String desc) {
        if (desc.indexOf('L') < 0) return desc;
        StringBuilder sb = new StringBuilder(desc.length() + 16);
        int i = 0;
        while (i < desc.length()) {
            char c = desc.charAt(i);
            if (c != 'L') { sb.append(c); i++; continue; }
            int end = desc.indexOf(';', i);
            if (end < 0) { sb.append(desc, i, desc.length()); break; }
            String obf = desc.substring(i + 1, end);
            String orig = classes.get(obf);
            sb.append('L').append(orig != null ? orig : obf).append(';');
            i = end + 1;
        }
        return sb.toString();
    }

    public Map<String, String> buildMapping(Map<String, ClassNode> classes) {
        Map<String, String> map = new LinkedHashMap<>();
        for (Map.Entry<String, ClassNode> e : classes.entrySet()) {
            ClassNode cn = e.getValue();
            String origCls = this.classes.get(cn.name);
            if (origCls != null && !origCls.equals(cn.name)) map.put(cn.name, origCls);
            for (FieldNode f : cn.fields) {
                String hit = fields.get(cn.name + "." + f.name + f.desc);
                if (hit == null) hit = fields.get(cn.name + "." + f.name + origTypes(f.desc));
                if (hit == null) {
                    String fb = fieldsByName.get(cn.name + "." + f.name);
                    if (fb != null) hit = fb;
                }
                if (hit != null && !hit.equals(f.name)) map.put(cn.name + "." + f.name, hit);
            }
            Map<String, Integer> nameCount = new HashMap<>();
            for (MethodNode m : cn.methods) nameCount.merge(m.name, 1, Integer::sum);
            for (MethodNode m : cn.methods) {
                if (m.name.equals("<init>") || m.name.equals("<clinit>")) continue;
                String hit = methods.get(cn.name + "." + m.name + m.desc);

                if (hit == null) hit = methods.get(cn.name + "." + m.name + origTypes(m.desc));
                if (hit == null && nameCount.getOrDefault(m.name, 0) == 1) {
                    String fb = methodsByName.get(cn.name + "." + m.name);
                    if (fb != null) hit = fb;
                }
                if (hit != null && !hit.equals(m.name)) map.put(cn.name + "." + m.name + m.desc, hit);
            }
        }

        for (ClassNode cn : classes.values()) {
            for (MethodNode m : cn.methods) {
                for (org.objectweb.asm.tree.AbstractInsnNode n =
                        m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof org.objectweb.asm.tree.FieldInsnNode fi) {
                        if (fi.getOpcode() != Opcodes.GETSTATIC && fi.getOpcode() != Opcodes.PUTSTATIC
                                && fi.getOpcode() != Opcodes.GETFIELD && fi.getOpcode() != Opcodes.PUTFIELD)
                            continue;
                        String decl = declaringFieldOwner(classes, fi.owner, fi.name);
                        if (decl == null || decl.equals(fi.owner)) continue;
                        String hit = fields.get(decl + "." + fi.name + fi.desc);
                        if (hit == null) hit = fieldsByName.get(decl + "." + fi.name);
                        if (hit != null && !hit.equals(fi.name))
                            map.put(fi.owner + "." + fi.name, hit);
                    } else if (n instanceof org.objectweb.asm.tree.MethodInsnNode mi) {
                        if (mi.name.startsWith("<")) continue;
                        String decl = declaringMethodOwner(classes, mi.owner, mi.name, mi.desc);
                        if (decl == null || decl.equals(mi.owner)) continue;
                        String hit = methods.get(decl + "." + mi.name + mi.desc);
                        if (hit == null) hit = methodsByName.get(decl + "." + mi.name);
                        if (hit != null && !hit.equals(mi.name))
                            map.put(mi.owner + "." + mi.name + mi.desc, hit);
                    }
                }
            }
        }
        return map;
    }

    private static String declaringFieldOwner(Map<String, ClassNode> classes,
                                             String owner, String name) {
        ClassNode cn = classes.get(owner + ".class");
        Set<String> seen = new HashSet<>();
        while (cn != null && seen.add(cn.name)) {
            for (FieldNode f : cn.fields)
                if (f.name.equals(name)) return cn.name;
            if (cn.interfaces != null) {
                for (String itf : cn.interfaces) {
                    ClassNode icn = classes.get(itf + ".class");
                    if (icn != null) for (FieldNode f : icn.fields)
                        if (f.name.equals(name)) return icn.name;
                }
            }
            cn = cn.superName == null ? null : classes.get(cn.superName + ".class");
        }
        return null;
    }

    private static String declaringMethodOwner(Map<String, ClassNode> classes,
                                              String owner, String name, String desc) {
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
}
