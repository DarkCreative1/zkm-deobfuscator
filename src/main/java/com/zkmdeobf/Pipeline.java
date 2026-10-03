package com.zkmdeobf;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;

public final class Pipeline {
    private Pipeline() {}

    public record Stats(int strPatched, List<String> strSkipped, int intPatched,
                        List<String> intUnresolved, int handlersRemoved,
                        int flowFolded, int deadRemoved, int refInlined,
                        int paramCalls, int paramCallees, int renamed, int classes) {}
    public record Result(Map<String, byte[]> jar, Stats stats, boolean verified, String verifyLog) {}

    public static Result deobfuscateJar(String input) throws Exception {
        Map<String, ClassNode> classes = ClassIO.readJar(input);
        Map<String, byte[]> raw = ClassIO.readRaw(input);
        staticTableCache.clear();
        tableCache.clear();
        int strP = 0, intP = 0, handR = 0, fold = 0, dead = 0, refIn = 0;
        List<String> strSkip = new ArrayList<>(), intUnres = new ArrayList<>();
        URLClassLoader dyn = dynLoader(input);
        Map<String, ClassNode> finalClasses = classes;
        boolean doRename = false;
        int renamed = 0, paramCalls = 0, paramCallees = 0;
        try {
            boolean usesReflection = !Renamer.reflectiveNames(classes).isEmpty();
            for (Map.Entry<String, ClassNode> e : classes.entrySet()) {
                ClassNode cn = e.getValue();
                try {

                for (MethodNode mm : cn.methods) Rewriter.inlineJsr(mm);

                List<LookupRecovery.Found> plains = LookupRecovery.recoverLayout(cn);
                if (plains.isEmpty()) plains = LookupRecovery.recoverDirect(cn);
                Map<StringDecryptor.LookupSite, String> bySite = new HashMap<>();
                for (LookupRecovery.Found f : plains) bySite.put(f.site(), f.plain());
                for (String lkDesc : new String[]{"(II)Ljava/lang/String;", "(III)Ljava/lang/String;"}) {
                    for (MethodNode m : cn.methods) {
                        for (StringDecryptor.LookupSite s : StringDecryptor.lookupSites(cn, m, lkDesc)) {
                            String pl = null;
                            if (dyn != null) pl = dynInvokeLookup(dyn, cn, s);
                            if (pl == null) pl = bySite.get(s);
                            if (pl == null) { strSkip.add(cn.name + "::" + s.mName() + " lookup-cozum-yok"); continue; }
                            if (Rewriter.patchCallSite(m, s.from(), s.invoke(), pl)) strP++;
                            else strSkip.add(cn.name + "::" + s.mName() + " guvensiz-aralik");
                        }
                    }
                }

                for (MethodNode m : cn.methods) {
                    for (StringDecryptor.IJStringSite s : StringDecryptor.ijStringSites(cn, m)) {
                        String pl = null;
                        if (dyn != null) pl = dynInvokeString(dyn, cn, s);
                        if (pl == null) pl = staticDesString(cn, s);
                        if (pl == null) { strSkip.add(cn.name + "::" + s.mName() + " des-cozum-yok"); continue; }
                        if (Rewriter.patchCallSite(m, s.from(), s.invoke(), pl)) strP++;
                        else strSkip.add(cn.name + "::" + s.mName() + " guvensiz-aralik");
                    }
                }

                boolean ownLookup = false;
                for (MethodNode m : cn.methods) {
                    if (m.desc.equals("(II)Ljava/lang/String;")
                            || m.desc.equals("(III)Ljava/lang/String;")
                            || m.desc.equals("(IJ)Ljava/lang/String;")) { ownLookup = true; break; }
                }
                List<String> table = null;
                if (!ownLookup) {
                    TableExtractor.Tables te = staticTableCache.get(cn.name) != null
                            ? staticTableCache.get(cn.name)
                            : TableExtractor.extract(cn);
                    if (te != null) {
                        staticTableCache.put(cn.name, te);
                        table = te.strings();
                    }
                    if (table == null || table.isEmpty())
                        table = StringDecryptor.recoverFieldTable(cn);
                }
                Map<String, List<String>> dynTables = new HashMap<>();
                TableExtractor.Tables emu = null;
                boolean emuTried = false;
                for (MethodNode m : cn.methods) {
                    for (StringDecryptor.FieldSite s : StringDecryptor.fieldArraySites(cn, m)) {
                        String pl = null;

                        if (dyn != null)
                            pl = dynTableValue(dyn, cn, dynTables, input, s.field(), s.idx());
                        if (pl == null && table != null && s.idx() >= 0 && s.idx() < table.size())
                            pl = table.get(s.idx());
                        if (pl == null) {
                            if (!emuTried) {
                                emuTried = true;
                                emu = TableExtractor.extractViaEmulation(cn, classes, dyn);
                            }
                            if (emu != null && s.idx() >= 0 && s.idx() < emu.strings().size())
                                pl = emu.strings().get(s.idx());
                        }
                        if (pl == null) { strSkip.add(cn.name + "::" + s.mName() + " table-missing"); continue; }
                        if (Rewriter.patchCallSite(m, s.from(), s.to(), pl)) strP++;
                        else strSkip.add(cn.name + "::" + s.mName() + " guvensiz-aralik");
                    }
                }

                if (dyn != null) {
                    for (MethodNode m : cn.methods) {
                        for (StringDecryptor.StrFieldSite s : StringDecryptor.stringFieldSites(cn, m)) {
                            String pl = dynStringValue(dyn, cn, s.field());
                            if (pl == null) pl = staticSingle(cn, s.field());
                            if (pl == null) { strSkip.add(cn.name + "::" + s.mName() + " field-missing"); continue; }
                            if (Rewriter.patchCallSite(m, s.getstatic(), s.getstatic(), pl)) strP++;
                            else strSkip.add(cn.name + "::" + s.mName() + " guvensiz-aralik");
                        }
                    }
                } else {
                    for (MethodNode m : cn.methods) {
                        for (StringDecryptor.StrFieldSite s : StringDecryptor.stringFieldSites(cn, m)) {
                            String pl = staticSingle(cn, s.field());
                            if (pl == null) { strSkip.add(cn.name + "::" + s.mName() + " field-missing"); continue; }
                            if (Rewriter.patchCallSite(m, s.getstatic(), s.getstatic(), pl)) strP++;
                            else strSkip.add(cn.name + "::" + s.mName() + " guvensiz-aralik");
                        }
                    }
                }

                for (MethodNode m : cn.methods) {
                    List<IntRecovery.Site> sites = new ArrayList<>();
                    sites.addAll(IntRecovery.sites(cn, m, "(IJ)I"));
                    sites.addAll(IntRecovery.sites(cn, m, "(IJ)J"));
                    for (IntRecovery.Site s : sites) {
                        Object v = staticIntValue(cn, s, classes, dyn);
                        if (v == null && dyn != null) v = dynInvoke(dyn, cn, m, s);
                        if (v == null) { intUnres.add(cn.name + "::" + s.mName() + "@" + s.arg()); continue; }
                        boolean ok;
                        if (s.hasGap()) {

                            ok = Rewriter.patchCallSiteKeepMiddle(m, s.from(),
                                    s.keyPush(), s.invoke(), v);
                        } else {
                            ok = Rewriter.patchCallSite(m, s.from(), s.invoke(), v);
                        }
                        if (ok) intP++;
                        else intUnres.add(cn.name + "::" + s.mName() + "@" + s.arg() + " guvensiz");
                    }
                }

                java.util.Set<String> reflectiveForFlow =
                        Renamer.reflectiveNames(classes);
                for (MethodNode m : cn.methods) handR += Rewriter.stripFakeHandlers(cn, m);
                Map<String, String> gg = FlowSimplifier.trivialGetters(cn);
                for (int round = 0; round < 2; round++) {
                    Map<String, FlowSimplifier.Const> cc = round == 0
                            ? FlowSimplifier.clinitConstants(cn, classes)
                            : new HashMap<>(FlowSimplifier.unwrittenDefaultsFiltered(classes, reflectiveForFlow));
                    if (round == 1) cc.putAll(FlowSimplifier.clinitConstants(cn, classes));
                    for (MethodNode m : cn.methods) {
                        fold += FlowSimplifier.foldMethod(cn, m, cc, gg);
                        fold += Rewriter.stripNops(m);
                        fold += Rewriter.propagateCopies(classes, cn, m);
                        fold += Rewriter.removeDeadStores(cn, m);
                        fold += FlowSimplifier.foldMethod(cn, m, cc, gg);
                        Rewriter.collapseGotos(m);
                        dead += Rewriter.removeDeadCode(m);
                    }
                }

                for (MethodNode m : cn.methods) {
                    for (ReferenceResolver.IndySite s
                            : ReferenceResolver.indySites(classes, cn, m)) {
                        long[] keys = keysOf(s);
                        if (keys == null) continue;
                        ReferenceResolver.Resolved r =
                                ReferenceResolver.resolveStatic(classes, dyn, s.resolverClass(), keys);
                        if (r == null && dyn != null)
                            r = ReferenceResolver.resolve(dyn, s.resolverClass(), keys);
                        if (r == null) continue;
                        if (ReferenceResolver.inlineIndy(m, s.indy(), s.keyPushes(), r)) refIn++;
                    }
                }
                } catch (Throwable t) {
                    strSkip.add(cn.name + " class-error:" + t.getClass().getSimpleName());
                }
            }

            ChangeLogMap changelog = null;
            String mapPath = System.getProperty("zkmdeobf.changelog");
            if (mapPath != null) {
                try {
                    changelog = ChangeLogMap.parse(mapPath);
                } catch (Throwable t) {
                    strSkip.add("changelog-error:" + t.getClass().getSimpleName());
                }
            }
            Set<String> manufactured = changelog == null
                    ? Set.of() : changelog.manufacturedFields;

            Set<String> regenedAll = new HashSet<>();            Set<String> origFields = changelog == null ? null : changelog.originalFields;
            try {
                dead += Rewriter.removeDeadMethods(classes);
                try {
                    java.util.Set<String> reflOpt = Renamer.reflectiveNames(classes);
                    fold += FlowSimplifier.optimisticFoldFiltered(classes, reflOpt);
                } catch (Throwable t) {
                    strSkip.add("optimistic-phase-error");
                }
                Set<String> regened = new HashSet<>();
                for (ClassNode cn : classes.values()) {
                    try {
                        if (ClinitRegenerator.regenerate(cn, classes, dyn)) {
                            dead++;
                            regened.add(cn.name);
                            regenedAll.add(cn.name);
                        }
                    } catch (Throwable t) {
                        strSkip.add(cn.name + " clinit-rejen-hatasi");
                    }
                }
                dead += Rewriter.removeDeadMethods(classes);
                dead += Rewriter.removeDeadMethods(classes);

                try {
                    dead += Rewriter.stripClinitLocalStatics(classes,
                            changelog == null ? null : changelog.originalFields);
                } catch (Throwable t) {
                    strSkip.add("clinit-yerel-hatasi");
                }

                try {
                    dead += Rewriter.stripDeadClinitWrites(classes);
                } catch (Throwable t) {
                    strSkip.add("clinit-write-cleanup-error");
                }

                try {
                    dead += Rewriter.removeDeadClinits(classes, usesReflection);
                } catch (Throwable t) {
                    strSkip.add("dead-clinit-error");
                }

                try {
                    dead += Rewriter.removeDeadResolverClasses(classes);
                } catch (Throwable t) {
                    strSkip.add("resolver-cleanup-error");
                }
                dead += Rewriter.removeDeadFields(classes, regened, manufactured, origFields);
            } catch (Throwable t) {
                strSkip.add("global-cleanup-error");
            }

            try {
            Map<String, String> newDescs = new HashMap<>();
            Map<ParamRestorer.Plan, ClassNode> plans = new LinkedHashMap<>();
            for (ClassNode cn : classes.values()) {
                try {
                    for (MethodNode m : cn.methods) {
                        ParamRestorer.Plan p = ParamRestorer.analyze(cn, m);
                        if (p != null) {
                            plans.put(p, cn);
                            newDescs.put(cn.name + "." + m.name + m.desc, p.newDesc());
                        }
                    }
                } catch (Throwable t) {
                    strSkip.add(cn.name + " param-analiz-hatasi");
                }
            }
            try {
                ParamRestorer.retainConsistent(classes, plans, newDescs);
            } catch (Throwable t) {
                strSkip.add("param-consistency-error");
            }
            try {
                int paramCalls0 = ParamRestorer.rewriteCallers(classes, newDescs);
                paramCalls += paramCalls0;
            } catch (Throwable t) {
                strSkip.add("param-caller-error");
            }
            int paramCallees0 = 0;
            for (Map.Entry<ParamRestorer.Plan, ClassNode> e : plans.entrySet()) {
                try {
                    if (ParamRestorer.rewriteCallee(e.getValue(), e.getKey())) paramCallees0++;
                } catch (Throwable t) {
                    strSkip.add(e.getValue().name + " param-callee-hatasi");
                }
            }
            paramCallees += paramCallees0;
            } catch (Throwable t) {
                strSkip.add("param-phase-error:" + t.getClass().getSimpleName());
            }

            try {
                dead += Rewriter.inlineNeverWrittenStatics(classes, usesReflection);
                dead += Rewriter.removeDeadFields(classes, regenedAll, manufactured, origFields);
            } catch (Throwable t) {
                strSkip.add("never-written-error:" + t.getClass().getSimpleName());
            }

            try {

                java.util.Set<String> scalarKeys =
                        Rewriter.inlinedScalarCandidates(classes, origFields);
                if (!scalarKeys.isEmpty()) {
                    java.util.Map<String, Object> dynScalars =
                            Rewriter.dynamicScalarStatics(classes, dyn, scalarKeys);
                    dead += Rewriter.inlineScalarStatics(classes, scalarKeys, dynScalars);
                }
                dead += Rewriter.removeDeadMethods(classes);
                dead += Rewriter.stripClinitLocalStatics(classes, origFields);
                dead += Rewriter.stripDeadClinitWrites(classes);
                dead += Rewriter.removeDeadFields(classes, regenedAll, manufactured, origFields);
                dead += Rewriter.removeDeadMethods(classes);
                dead += Rewriter.removeDeadFields(classes, regenedAll, manufactured, origFields);
            } catch (Throwable t) {
                strSkip.add("final-field-cleanup-error:" + t.getClass().getSimpleName());
            }

            try {
            doRename = !"false".equals(System.getProperty("zkmdeobf.rename", "true"));
            Map<String, String> mapping = new LinkedHashMap<>();
            if (changelog != null) {
                mapping.putAll(changelog.buildMapping(classes));
                for (Map.Entry<String, String> se : changelog.sources.entrySet()) {
                    ClassNode cn = classes.get(se.getKey() + ".class");
                    if (cn != null && se.getValue() != null && !se.getValue().isEmpty())
                        cn.sourceFile = se.getValue();
                }
            }
            if (doRename) {
                Map<String, String> heur = Renamer.buildMapping(classes, dyn);
                for (Map.Entry<String, String> he : heur.entrySet())
                    mapping.putIfAbsent(he.getKey(), he.getValue());
            }
            if (!mapping.isEmpty()) {
                renamed = mapping.size();
                finalClasses = Renamer.apply(classes, mapping);
            }
            } catch (Throwable t) {
                strSkip.add("rename-error:" + t.getClass().getSimpleName());
                doRename = false;
                renamed = 0;
                finalClasses = classes;
            }

            try {
                dead += Rewriter.removeEmptyClinits(finalClasses);
                for (ClassNode cn : finalClasses.values()) {
                    for (MethodNode m : cn.methods) {
                        dead += Rewriter.polish(m);
                    }
                }
            } catch (Throwable t) {
                strSkip.add("polish-error:" + t.getClass().getSimpleName());
            }
        } finally {
            if (dyn != null) try { dyn.close(); } catch (Exception ignored) {}
        }
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> en : raw.entrySet()) {
            String n = en.getKey();
            if (n.endsWith(".class") && finalClasses.containsKey(n)) {
                try { out.put(n, ClassIO.toBytes(finalClasses.get(n))); }
                catch (Exception ex) { out.put(n, en.getValue()); }
            } else out.put(n, en.getValue());
        }

        Map<String, byte[]> final2 = new LinkedHashMap<>();
        if (doRename || renamed > 0) {
            for (Map.Entry<String, ClassNode> e : finalClasses.entrySet()) {
                try { final2.put(e.getKey(), ClassIO.toBytes(e.getValue())); }
                catch (Exception ex) {
                    if (Boolean.getBoolean("zkmdeobf.debugWrite"))
                        System.err.println("[yazim-hatasi] " + e.getKey() + ": " + ex);
                    strSkip.add(e.getKey() + " yazim-hatasi:" + ex.getClass().getSimpleName());
                    // Never drop a class: fall back to the already-encoded (or
                    // raw) bytes from the first pass instead of emitting a jar
                    // with a missing member of the hierarchy.
                    byte[] prev = out.get(e.getKey());
                    if (prev != null) final2.put(e.getKey(), prev);
                }
            }
            for (Map.Entry<String, byte[]> en : raw.entrySet()) {
                if (!en.getKey().endsWith(".class")) final2.put(en.getKey(), en.getValue());
            }
            out = final2;
        }
        Verify v = verifyJar(out);
        Verify r = verifyRefs(out);
        if (v.ok() && !r.ok()) v = new Verify(false, v.log() + " | referans: " + r.log());
        return new Result(out, new Stats(strP, strSkip, intP, intUnres, handR, fold, dead,
                refIn, paramCalls, paramCallees, renamed, classes.size()),
                v.ok(), v.log());
    }

    private record Verify(boolean ok, String log) {}

    private static Verify verifyRefs(Map<String, byte[]> out) {
        Map<String, org.objectweb.asm.tree.ClassNode> cs = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> en : out.entrySet()) {
            if (!en.getKey().endsWith(".class")) continue;
            try {
                org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
                new org.objectweb.asm.ClassReader(en.getValue()).accept(cn, 0);
                cs.put(cn.name, cn);
            } catch (Throwable t) {
                return new Verify(false, "parse:" + en.getKey());
            }
        }
        int bad = 0;
        String first = "";
        for (org.objectweb.asm.tree.ClassNode cn : cs.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof MethodInsnNode mi) {
                        if (!cs.containsKey(mi.owner)) continue;
                        if (!memberExists(cs, mi.owner, mi.name, mi.desc, true)) {
                            bad++;
                            if (first.isEmpty())
                                first = cn.name + "." + m.name + " -> " + mi.owner + "." + mi.name + mi.desc;
                        }
                    } else if (n instanceof FieldInsnNode fi) {
                        if (!cs.containsKey(fi.owner)) continue;
                        if (!fieldExists(cs, fi.owner, fi.name)) {
                            bad++;
                            if (first.isEmpty())
                                first = cn.name + "." + m.name + " -> " + fi.owner + "." + fi.name;
                        }
                    }
                }
            }
        }
        if (bad > 0) return new Verify(false, bad + " cozulemeyen referans (" + first + ")");
        return new Verify(true, "referans butun");
    }

    private static boolean memberExists(Map<String, org.objectweb.asm.tree.ClassNode> cs,
                                        String owner, String name, String desc, boolean method) {
        Set<String> seen = new HashSet<>();
        org.objectweb.asm.tree.ClassNode cn = cs.get(owner);
        while (cn != null && seen.add(cn.name)) {
            for (MethodNode m : cn.methods)
                if (m.name.equals(name) && m.desc.equals(desc)) return true;
            if (cn.interfaces != null)
                for (String itf : cn.interfaces) {
                    org.objectweb.asm.tree.ClassNode icn = cs.get(itf);
                    if (icn != null) for (MethodNode m : icn.methods)
                        if (m.name.equals(name) && m.desc.equals(desc)) return true;
                }
            if (cn.superName == null) break;
            org.objectweb.asm.tree.ClassNode up = cs.get(cn.superName);

            if (up == null) return true;
            cn = up;
        }
        return false;
    }

    private static boolean fieldExists(Map<String, org.objectweb.asm.tree.ClassNode> cs,
                                        String owner, String name) {
        Set<String> seen = new HashSet<>();
        org.objectweb.asm.tree.ClassNode cn = cs.get(owner);
        while (cn != null && seen.add(cn.name)) {
            for (FieldNode f : cn.fields)
                if (f.name.equals(name)) return true;
            if (cn.interfaces != null)
                for (String itf : cn.interfaces) {
                    org.objectweb.asm.tree.ClassNode icn = cs.get(itf);
                    if (icn != null) for (FieldNode f : icn.fields)
                        if (f.name.equals(name)) return true;
                }
            if (cn.superName == null) break;
            org.objectweb.asm.tree.ClassNode up = cs.get(cn.superName);
            if (up == null) return true;
            cn = up;
        }
        return false;
    }

    private static Verify verifyJar(Map<String, byte[]> out) {
        int n = 0, fail = 0;
        String firstErr = "";
        for (Map.Entry<String, byte[]> en : out.entrySet()) {
            if (!en.getKey().endsWith(".class")) continue;
            n++;
            try {
                org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
                new org.objectweb.asm.ClassReader(en.getValue()).accept(cn, 0);
                ClassIO.toBytes(cn);
            } catch (Throwable t) {
                fail++;
                if (firstErr.isEmpty()) firstErr = en.getKey() + ":" + t.getClass().getSimpleName();
            }
        }
        if (n == 0) return new Verify(false, "class-missing");
        if (fail > 0) return new Verify(false, fail + "/" + n + " frame-hatasi (" + firstErr + ")");
        return new Verify(true, n + " class parse+frame OK");
    }

    private static final Map<String, TableExtractor.Tables> staticTableCache = new java.util.HashMap<>();

    static Object staticIntValue(ClassNode cn, IntRecovery.Site s) {
        return staticIntValue(cn, s, null, null);
    }

    static Object staticIntValue(ClassNode cn, IntRecovery.Site s,
                                 Map<String, ClassNode> classes, ClassLoader loader) {
        try {
            MethodNode lookup = null;
            if (s.invoke() instanceof MethodInsnNode mi) {
                for (MethodNode m : cn.methods) {
                    if (m.name.equals(mi.name) && m.desc.equals(mi.desc)) { lookup = m; break; }
                }
            }
            if (lookup == null) {
                for (MethodNode m : cn.methods) {
                    if (m.desc.equals("(IJ)I") || m.desc.equals("(IJ)J")) { lookup = m; break; }
                }
            }
            if (lookup == null) return null;
            IntRecovery.LookupParams p = IntRecovery.params(cn, lookup);
            if (p == null) return null;
            TableExtractor.Tables t = staticTableCache.get(cn.name);
            if (t == null) {
                t = TableExtractor.extract(cn);
                if (t == null && classes != null)
                    t = TableExtractor.extractViaEmulation(cn, classes, loader);
                if (t == null) return null;
                staticTableCache.put(cn.name, t);
            }
            if (t.longs().isEmpty()) return null;
            long[] enc = new long[t.longs().size()];
            for (int i = 0; i < enc.length; i++) enc[i] = t.longs().get(i);
            if (lookup.desc.equals("(IJ)I")) {
                if (IntRecovery.isDesLookup(cn, lookup))
                    return (int) IntRecovery.recoverLongDes(s.arg(), s.key(), p.mask(), p.indexXor(), enc);
                return IntRecovery.recoverInt(s.arg(), s.key(), p.mask(), p.indexXor(), enc);
            }
            if (IntRecovery.isDesLookup(cn, lookup))
                return IntRecovery.recoverLongDes(s.arg(), s.key(), p.mask(), p.indexXor(), enc);
            return IntRecovery.recoverLong(s.arg(), s.key(), p.mask(), p.indexXor(), enc);
        } catch (Exception e) {
            return null;
        }
    }

    static String staticDesString(ClassNode cn, StringDecryptor.IJStringSite s) {
        try {
            MethodNode lookup = null;
            if (s.invoke() instanceof MethodInsnNode mi) {
                for (MethodNode m : cn.methods) {
                    if (m.name.equals(mi.name) && m.desc.equals(mi.desc)) { lookup = m; break; }
                }
            }
            if (lookup == null) return null;
            IntRecovery.LookupParams p = IntRecovery.params(cn, lookup);
            if (p == null) return null;
            long l = (s.arg() ^ (s.key() & p.mask()) ^ p.indexXor());
            if (l < 0 || l > Integer.MAX_VALUE) return null;
            int idx = (int) l;

            List<String> table = null;
            TableExtractor.Tables te = staticTableCache.get(cn.name);
            if (te == null) {
                te = TableExtractor.extract(cn);
                if (te != null) staticTableCache.put(cn.name, te);
            }
            if (te != null && !te.strings().isEmpty()) table = te.strings();
            if (table == null) table = StringDecryptor.recoverFieldTable(cn);
            if (table == null || idx < 0 || idx >= table.size()) return null;
            String enc = table.get(idx);

            try {
                String pl = Crypto.desStringDecrypt(enc, s.key());
                if (Crypto.scoreAscii(pl) > 0.7) return pl;
            } catch (Exception ignored) {}

            try {
                MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
                if (cl != null) {
                    int[] keys = StringDecryptor.extractXorKeys(cl);
                    if (keys != null) {
                        String outer = Crypto.xorWithKeys(enc, keys);
                        String pl = Crypto.desStringDecrypt(outer, s.key());
                        if (Crypto.scoreAscii(pl) > 0.7) return pl;
                    }
                }
            } catch (Exception ignored) {}
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    private static long[] keysOf(ReferenceResolver.IndySite s) {
        if (s.keys() == null || s.keys().isEmpty()) return null;
        long[] o = new long[s.keys().size()];
        for (int i = 0; i < o.length; i++) o[i] = s.keys().get(i);
        return o;
    }

    static String staticSingle(ClassNode cn, String field) {
        MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
        if (cl == null) return null;
        int[] keys = StringDecryptor.extractXorKeys(cl);
        if (keys == null) return null;
        List<String> hits = new ArrayList<>();
        for (String c : StringDecryptor.clinitChunks(cn, cl)) {
            StringDecryptor.SplitResult b = StringDecryptor.bestSplitDecrypt(c, keys, 1);
            if (b != null && b.n() == 1 && b.score() >= 1.0) hits.add(b.parts().get(0));
        }

        Set<String> uniq = new HashSet<>(hits);
        if (uniq.size() == 1) return hits.get(0);
        return null;
    }

    private static URLClassLoader dynLoader(String jar) {
        // Untrusted-input escape hatch: --no-dyn disables ALL dynamic
        // recovery (class loading + reflective invocation of obfuscated code).
        if ("false".equals(System.getProperty("zkmdeobf.dyn", "true"))) return null;
        try {
            return new URLClassLoader(new URL[]{new File(jar).toURI().toURL()},
                    ClassLoader.getSystemClassLoader().getParent());
        } catch (Exception e) { return null; }
    }

    private static final Map<String, Map<String, List<String>>> tableCache = new HashMap<>();

    private static String dynTableValue(URLClassLoader dyn, ClassNode cn,
                                        Map<String, List<String>> cache, String input,
                                        String field, int idx) {
        try {
            if (idx < 0) return null;
            List<String> arr = cache.get(field);
            if (arr == null) {
                Class<?> c = Class.forName(cn.name.replace('/', '.'), true, dyn);
                Field f = null;
                for (Field ff : c.getDeclaredFields())
                    if (ff.getName().equals(field) && ff.getType() == String[].class) f = ff;
                if (f == null) return null;
                f.setAccessible(true);
                String[] a = (String[]) f.get(null);
                if (a == null) return null;
                arr = Arrays.asList(a);
                cache.put(field, arr);
            }
            return idx < arr.size() ? arr.get(idx) : null;
        } catch (Throwable t) { return null; }
    }

    private static String dynStringValue(URLClassLoader dyn, ClassNode cn, String field) {
        try {
            Class<?> c = Class.forName(cn.name.replace('/', '.'), true, dyn);
            Field f = null;
            for (Field ff : c.getDeclaredFields())
                if (ff.getName().equals(field) && ff.getType() == String.class) f = ff;
            if (f == null) return null;
            f.setAccessible(true);
            return (String) f.get(null);
        } catch (Throwable t) { return null; }
    }

    private static Object dynInvoke(URLClassLoader dyn, ClassNode cn, MethodNode m, IntRecovery.Site s) {
        try {
            String tName = null, tDesc = null;
            if (s.invoke() instanceof org.objectweb.asm.tree.MethodInsnNode mi) {
                tName = mi.name;
                tDesc = mi.desc;
            }
            Class<?> c = Class.forName(cn.name.replace('/', '.'), true, dyn);
            for (Method m2 : c.getDeclaredMethods()) {
                if (!Modifier.isStatic(m2.getModifiers()) || m2.getParameterCount() != 2) continue;
                if (tName != null && (!m2.getName().equals(tName)
                        || !Type.getMethodDescriptor(m2).equals(tDesc))) continue;
                Class<?>[] p = m2.getParameterTypes();
                if (p[0] != int.class || p[1] != long.class) continue;
                boolean wantInt = m2.getReturnType() == int.class;
                boolean wantLong = m2.getReturnType() == long.class;
                if (!wantInt && !wantLong) continue;
                m2.setAccessible(true);
                return m2.invoke(null, s.arg(), s.key());
            }
        } catch (Throwable t) {  }
        return null;
    }

    private static String dynInvokeLookup(URLClassLoader dyn, ClassNode cn,
                                          StringDecryptor.LookupSite s) {
        try {
            if (!(s.invoke() instanceof org.objectweb.asm.tree.MethodInsnNode mi)) return null;
            Class<?> c = Class.forName(cn.name.replace('/', '.'), true, dyn);
            for (Method m2 : c.getDeclaredMethods()) {
                if (!Modifier.isStatic(m2.getModifiers()) || !m2.getName().equals(mi.name)) continue;
                if (!Type.getMethodDescriptor(m2).equals(mi.desc)) continue;
                if (m2.getReturnType() != String.class) continue;
                Class<?>[] p = m2.getParameterTypes();
                m2.setAccessible(true);
                if (mi.desc.equals("(II)Ljava/lang/String;") && p.length == 2
                        && p[0] == int.class && p[1] == int.class) {
                    return (String) m2.invoke(null, s.encIdx(), s.key());
                }
                if (mi.desc.equals("(III)Ljava/lang/String;") && p.length == 3
                        && p[0] == int.class && p[1] == int.class && p[2] == int.class) {
                    // Third arg is a salt/nonce captured at the call site; never hardcode.
                    return (String) m2.invoke(null, s.encIdx(), s.key(), s.extra());
                }
            }
        } catch (Throwable t) {  }
        return null;
    }

    private static String dynInvokeString(URLClassLoader dyn, ClassNode cn,
                                          StringDecryptor.IJStringSite s) {
        try {
            String tName = null, tDesc = null;
            if (s.invoke() instanceof org.objectweb.asm.tree.MethodInsnNode mi) {
                tName = mi.name;
                tDesc = mi.desc;
            }
            Class<?> c = Class.forName(cn.name.replace('/', '.'), true, dyn);
            for (Method m2 : c.getDeclaredMethods()) {
                if (!Modifier.isStatic(m2.getModifiers()) || m2.getParameterCount() != 2) continue;
                if (tName != null && (!m2.getName().equals(tName)
                        || !Type.getMethodDescriptor(m2).equals(tDesc))) continue;
                Class<?>[] p = m2.getParameterTypes();
                if (p[0] != int.class || p[1] != long.class) continue;
                if (m2.getReturnType() != String.class) continue;
                m2.setAccessible(true);
                Object r = m2.invoke(null, s.arg(), s.key());
                return (String) r;
            }
        } catch (Throwable t) {  }
        return null;
    }
}
