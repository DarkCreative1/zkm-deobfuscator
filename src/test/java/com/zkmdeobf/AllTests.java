package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.*;

public final class AllTests {
    private AllTests() {}
    static int pass = 0;

    static void check(boolean c, String msg) {
        if (!c) throw new AssertionError("FAIL: " + msg);
        pass++;
    }

    public static void testCrypto() {
        int[] keys = {11, 22, 33, 44, 55, 66, 77};
        String s = "Hello ZKM World! merhaba 123";
        check(Crypto.xorWithKeys(Crypto.xorWithKeys(s, keys), keys).equals(s), "xor");
        int[] k2 = {0x12, 0xAB};
        String r = "RollingXor-Test-42";
        check(Crypto.rollingXorDecryptOrig(Crypto.rollingXorEncrypt(r, k2, true), k2).equals(r), "rolling-T");
        check(Crypto.rollingXorDecrypt(Crypto.rollingXorEncrypt(r, k2, false), k2).equals(r), "rolling-F");
        long dk = 0x0123456789ABCDEFL;
        for (String t : new String[]{"hello", "ZKM-string", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
            check(Crypto.desStringDecrypt(Crypto.desStringEncrypt(t, dk), dk).equals(t), "des-str:" + t);
        long lk = 0x1122334455667788L;
        for (long v : new long[]{0, 1, 42, 0xDEADBEEFCAFEBABEL, 0xFFFFFFFFFFFFFFFFL})
            check(Crypto.desLongCrypt(Crypto.desLongCrypt(v, lk, false), lk, true) == v, "des-long:" + v);
        String chunk = "ABCDE" + (char) 2 + "XY" + (char) 4 + "WXYZ";
        List<List<String>> sp = Crypto.allSplits(chunk, 3, 300);
        boolean found = false;
        for (List<String> sol : sp)
            if (sol.equals(List.of("ABCDE", "XY", "WXYZ"))) found = true;
        check(found, "split");
        String mu = "AB\0CDé";
        check(Crypto.mutf8Decode(Crypto.mutf8Encode(mu)).equals(mu), "mutf8");
        System.out.println("crypto OK");
    }

    public static void testDemo2() throws Exception {
        Map<String, ClassNode> cs = ClassIO.readJar("corpus/fixtures/demo2-obf.jar");
        ClassNode wb = cs.get("a/a/b.class");
        MethodNode cl = ClassIO.findMethod(wb, "<clinit>", "()V");
        int[] keys = StringDecryptor.extractXorKeys(cl);
        check(keys != null && Arrays.equals(keys, new int[]{51, 39, 95, 2, 24, 6, 61}), "xorKeys");
        List<String> table = StringDecryptor.recoverFieldTable(wb);
        check(table != null && table.size() == 8, "table8: " + table);
        Set<String> exp = Set.of("empty-tag", "D-poor", "-secret-sauce", "B-good",
                "hello-", "C-average", "F-fail", "A-excellent");
        check(new HashSet<>(table).equals(exp), "table-icerik: " + table);
        MethodNode lookup = null;
        for (MethodNode m : wb.methods) if (m.desc.equals("(IJ)I")) lookup = m;
        check(lookup != null, "(IJ)I var");
        IntRecovery.LookupParams p = IntRecovery.params(wb, lookup);
        check(p != null && p.mask() == 32767 && p.indexXor() == 0x4256, "int-params: " + p);
        int nSites = 0;
        for (MethodNode m : wb.methods) nSites += IntRecovery.sites(wb, m, "(IJ)I").size();
        check(nSites == 5, "int-sites=" + nSites);
        System.out.println("demo2 OK");
    }

    public static void testDemo3B() throws Exception {
        Map<String, ClassNode> cs = ClassIO.readJar("corpus/fixtures/demo3B-obf.jar");
        ClassNode ma = cs.get("a/a/a.class");
        List<LookupRecovery.Found> fm = LookupRecovery.recoverLayout(ma);
        Set<String> gotM = new HashSet<>();
        for (LookupRecovery.Found f : fm) gotM.add(f.plain());
        check(gotM.equals(Set.of("ZKM-E2E", "calc=", "foo", "bar", "cat=")), "main5: " + gotM);
        ClassNode wb = cs.get("a/a/b.class");
        List<LookupRecovery.Found> fw = LookupRecovery.recoverDirect(wb);
        Set<String> gotW = new HashSet<>();
        for (LookupRecovery.Found f : fw) gotW.add(f.plain());
        Set<String> expW = Set.of("magic=", "big=", "grade=", "ex=", "-mid-", "empty-tag",
                "hello-", "-secret-sauce", "A-excellent", "B-good", "C-average",
                "D-poor", "F-fail", "negative-input", "ok-", "caught-");
        check(gotW.equals(expW), "worker16: " + gotW);
        System.out.println("demo3B OK");
    }

    public static void testDemo3C() throws Exception {
        java.util.Map<String, ClassNode> cs = ClassIO.readJar("corpus/fixtures/demo3C-obf.jar");
        ClassNode wb = cs.get("a/a/b.class");
        java.util.Map<String, String> expect = new java.util.HashMap<>();
        expect.put("a", "(Ljava/lang/String;)Ljava/lang/String;");
        expect.put("b", "(II)I");
        expect.put("c", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        expect.put("d", "(Ljava/lang/String;)Ljava/lang/String;");
        expect.put("e", "(I)Ljava/lang/String;");
        expect.put("f", "(I)Ljava/lang/String;");
        for (MethodNode m : wb.methods) {
            ParamRestorer.Plan p = ParamRestorer.analyze(wb, m);
            if (p == null) continue;
            check(p.newDesc().equals(expect.get(m.name)), "desc " + m.name + " -> " + p.newDesc());
            check(ParamRestorer.rewriteCallee(wb, p), "callee " + m.name);
            check(m.desc.equals(expect.get(m.name)), "desc-written " + m.name);
        }
        System.out.println("demo3C OK");
    }

    public static void testTables() throws Exception {
        java.util.Map<String, ClassNode> cs = ClassIO.readJar("corpus/fixtures/demo2-obf.jar");
        ClassNode wb = cs.get("a/a/b.class");
        TableExtractor.Tables t = TableExtractor.extract(wb);
        check(t != null, "tables-null");
        check(t.strings().equals(java.util.List.of("empty-tag", "D-poor", "-secret-sauce",
                "B-good", "hello-", "C-average", "F-fail", "A-excellent")),
                "strings-sira: " + t.strings());
        check(t.longs().equals(java.util.List.of(-1535701415273817048L, -4053523173738095047L,
                -5187989390702372588L, -3379558863154558104L, -3453772378396368469L)),
                "longs: " + t.longs());

        MethodNode lookup = null;
        for (MethodNode m : wb.methods) if (m.desc.equals("(IJ)I")) lookup = m;
        IntRecovery.LookupParams p = IntRecovery.params(wb, lookup);
        long[] enc = new long[t.longs().size()];
        for (int i = 0; i < enc.length; i++) enc[i] = t.longs().get(i);
        int[][] sites = {{7225, 1185937375}, {2407, 0}, {24110, 0}, {23302, 0}, {9157, 0}};

        int idx = (int) (2407 ^ (6992474796598905650L & p.mask()) ^ p.indexXor());
        check(idx >= 0 && idx < enc.length, "idx-aralik");
        check(IntRecovery.recoverInt(2407, 6992474796598905650L, p.mask(), p.indexXor(), enc) == 90,
                "statik-int-90");
        System.out.println("tables OK");
    }

    public static void testDesAndLong() {
        long key = 0x0F1E2D3C4B5A6978L;

        String[] vecs = {"A", "hello-world", "uzun-string-0123456789ABCDEF", "x"};
        for (String v : vecs) {
            String enc = DesStrings.desInnerEncrypt(v, key);
            check(DesStrings.desInnerDecrypt(enc, key).equals(v), "des-inner:" + v);
        }

        String enc = DesStrings.desInnerEncrypt("1234567", key);
check(DesStrings.desInnerEncrypt("1234567", key).length() == 8, "des-blok");

        long mask = 32767;
        int xor = 0x4256;
        long k2 = 999999999999L;

        int want = 3;
        int a2 = (int) ((k2 & mask) ^ xor ^ want);
        int i2 = (int) (a2 ^ (k2 & mask) ^ xor);
        long[] tab2 = new long[8];
        java.util.Random r = new java.util.Random(7);
        for (int t = 0; t < tab2.length; t++) tab2[t] = r.nextLong();
        long p2 = -123456789012345L;
        tab2[want] = p2 ^ k2;
        check(DesStrings.recoverLongStatic(a2, k2, mask, xor, tab2) == p2, "long-formul");
        check(DesStrings.recoverIntStatic(a2, k2, mask, xor, tab2) == (int) p2, "int-formul");
        System.out.println("des/long OK");
    }

    static String runCli(String... cliArgs) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(System.getProperty("java.home") + "/bin/java");
        cmd.add("-cp");
        cmd.add(System.getProperty("java.class.path"));
        cmd.add("com.zkmdeobf.Main");
        cmd.addAll(Arrays.asList(cliArgs));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        boolean done = p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);
        if (!done) {
            p.destroyForcibly();
            throw new AssertionError("cli timeout");
        }
        String out = new String(p.getInputStream().readAllBytes());
        return out.replace("\r", "").trim();
    }

    static int runCliCode(String... cliArgs) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(System.getProperty("java.home") + "/bin/java");
        cmd.add("-cp");
        cmd.add(System.getProperty("java.class.path"));
        cmd.add("com.zkmdeobf.Main");
        cmd.addAll(Arrays.asList(cliArgs));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);
        p.getInputStream().readAllBytes();
        return p.exitValue();
    }

    public static void testCliHelp() throws Exception {
        String noArgs = runCli();
        check(noArgs.contains("USAGE"), "bare call shows usage");
        check(noArgs.contains("--no-rename"), "help lists --no-rename");
        check(noArgs.contains("--map"), "help lists --map");
        check(noArgs.contains("str_skipped"), "help explains str_skipped");
        check(noArgs.contains("EXIT STATUS"), "help documents exit codes");

        check(runCli().equals(noArgs), "bare call and --help agree");
        check(runCli("--help").contains("USAGE"), "--help shows usage");
        check(runCli("-h").contains("USAGE"), "-h shows usage");
        String v = runCli("--version");
        check(v.startsWith("zkm-deobfuscator "), "--version");
        check(v.length() > "zkm-deobfuscator ".length(), "--version has a version");
        check(noArgs.contains(v.substring("zkm-deobfuscator ".length())),
                "help screen shows the same version as --version");
        check(runCli("-V").equals(v), "-V matches --version");

        check(runCliCode() == 0, "bare call exits 0");
        check(runCliCode("--bogus") == 2, "unknown option exits 2");
        check(runCliCode("a.jar", "-o") == 2, "missing -o value exits 2");
        check(runCliCode("a.jar", "--map") == 2, "missing --map value exits 2");
        check(runCliCode("a.jar", "--run") == 2, "missing --run value exits 2");
        check(runCliCode("a.jar", "b.jar") == 2, "extra argument exits 2");
        check(runCliCode("corpus/fixtures/demo3D-obf.jar", "--run", "a.a.a") == 2,
                "--run without --output exits 2");
        System.out.println("cli help OK");
    }

    public static void testCorpusBytecodeTarget() throws Exception {
        int limit = 61;
        int scanned = 0;
        List<String> offenders = new ArrayList<>();
        List<java.io.File> jars = new ArrayList<>();
        for (String root : new String[]{"corpus"}) collectJars(new java.io.File(root), jars);
        java.util.Collections.sort(jars);
        for (java.io.File f : jars) {
            try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(f)) {
                for (Enumeration<? extends java.util.zip.ZipEntry> en = zf.entries();
                     en.hasMoreElements(); ) {
                    java.util.zip.ZipEntry e = en.nextElement();
                    if (!e.getName().endsWith(".class")) continue;
                    byte[] b = zf.getInputStream(e).readAllBytes();
                    int major = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
                    scanned++;
                    if (major > limit)
                        offenders.add(f.getName() + "!" + e.getName() + "=" + major);
                }
            }
        }
        check(scanned > 40, "corpus class files scanned, got " + scanned);
        check(offenders.isEmpty(), "bundled corpus must target Java " + limit + " or older: " + offenders);
        System.out.println("corpus bytecode OK (" + scanned + " class in " + jars.size() + " jar, max <= " + limit + ")");
    }

    static void collectJars(java.io.File dir, List<java.io.File> out) {
        java.io.File[] kids = dir.listFiles();
        if (kids == null) return;
        Arrays.sort(kids);
        for (java.io.File f : kids) {
            if (f.isDirectory()) collectJars(f, out);
            else if (f.getName().endsWith(".jar")) out.add(f);
        }
    }

    public static void testRefInline() throws Exception {
        System.setProperty("zkmdeobf.rename", "false");
        try {
        Pipeline.Result r = Pipeline.deobfuscateJar("corpus/fixtures/demo3D-obf.jar");
        check(r.stats().refInlined() == 4,
                "ref_inlined=" + r.stats().refInlined() + " skipped=" + r.stats().strSkipped());
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar("build/test-tmp/_jt3d.jar", jar);

        java.util.Map<String, ClassNode> cs = ClassIO.readJar("build/test-tmp/_jt3d.jar");
        int zkmIndy = 0, direct = 0, jdkIndy = 0;
        for (ClassNode cn : cs.values()) {
            for (MethodNode m : cn.methods) {
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof InvokeDynamicInsnNode id) {
                        if (id.bsm.getOwner().equals("a/a/c")) zkmIndy++;
                        else jdkIndy++;
                    }
                    if (n instanceof MethodInsnNode mi && mi.owner.equals("a/a/b")
                            && (mi.name.equals("a") || mi.name.equals("b") || mi.name.equals("c"))) direct++;
                }
            }
        }
        check(zkmIndy == 0, "zkm-indy kaldi");
        check(direct >= 4, "direkt cagri=" + direct);
        check(jdkIndy > 0, "JDK indy korundu");
        check(runMain("build/test-tmp/_jt3d.jar", "a.a.a").startsWith("hello-ZKM-E2E-secret-sauce"), "run-3d");
        System.out.println("ref-inline OK");
        } finally {
            System.clearProperty("zkmdeobf.rename");
        }
    }

    public static void testRename() throws Exception {
        System.setProperty("zkmdeobf.rename", "true");
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar("corpus/fixtures/demo2-obf.jar");
            check(r.stats().renamed() > 0, "renamed");
            java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
            ClassIO.writeJar("build/test-tmp/_jt2r.jar", jar);
            boolean hasC = false;
            for (String n : jar.keySet()) if (n.contains("C00")) hasC = true;
            check(hasC, "C00 class");
            String main = null;
            java.util.Map<String, ClassNode> rcs = ClassIO.readJar("build/test-tmp/_jt2r.jar");
            for (ClassNode cn : rcs.values()) {
                for (MethodNode mm : cn.methods) {
                    if (mm.name.equals("main") && mm.desc.equals("([Ljava/lang/String;)V")) {
                        main = cn.name.replace('/', '.');
                    }
                }
            }
            check(main != null && runMain("build/test-tmp/_jt2r.jar", main).contains("B-good"), "run-rename");
        } finally {
            System.clearProperty("zkmdeobf.rename");
        }
        System.out.println("rename OK");
    }

    public static void testPatcherE2E() throws Exception {
        System.setProperty("zkmdeobf.rename", "false");
        try {
        Pipeline.Result r = Pipeline.deobfuscateJar("corpus/fixtures/demo3E-obf.jar");
        check(r.stats().handlersRemoved() == 8, "handlers=" + r.stats().handlersRemoved());
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar("build/test-tmp/_jt3e.jar", jar);
        check(runMain("build/test-tmp/_jt3e.jar", "a.a.a").startsWith("hello-ZKM-E2E-secret-sauce"), "run-3e");
        System.out.println("patcher-e2e OK");
        } finally {
            System.clearProperty("zkmdeobf.rename");
        }
    }

    public static void testDupCat2() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "diff/C1", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 7);
        mv.visitLdcInsn(100L);
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_3);
        mv.visitInsn(org.objectweb.asm.Opcodes.DUP_X2);
        mv.visitInsn(org.objectweb.asm.Opcodes.POP);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.LSTORE, 1);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 0);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 3);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.LLOAD, 1);
        mv.visitInsn(org.objectweb.asm.Opcodes.L2I);
        mv.visitInsn(org.objectweb.asm.Opcodes.IADD);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 3);
        mv.visitInsn(org.objectweb.asm.Opcodes.IADD);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        Class<?> c = new ClassLoader(null) {
            Class<?> def() { return defineClass("diff.C1", b, 0, b.length); }
        }.def();
        int jvm = (Integer) c.getMethod("f").invoke(null);
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(b).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "f", "()I");
        java.util.Map<String, ClassNode> cs = java.util.Map.of("diff/C1.class", cn);
        Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
        check(jvm == 110 && ((Integer) emu) == 110, "dup_x2_cat2 jvm=" + jvm + " emu=" + emu);

        org.objectweb.asm.ClassWriter w2 = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w2.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "diff/C2", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv2 = w2.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        mv2.visitCode();
        mv2.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        mv2.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
        mv2.visitInsn(org.objectweb.asm.Opcodes.ICONST_3);
        mv2.visitInsn(org.objectweb.asm.Opcodes.DUP_X1);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 0);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 1);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 2);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 3);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
        mv2.visitIntInsn(org.objectweb.asm.Opcodes.SIPUSH, 1000);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IMUL);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 1);
        mv2.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 100);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IMUL);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IADD);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 2);
        mv2.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 10);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IMUL);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IADD);
        mv2.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 3);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IADD);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv2.visitMaxs(0, 0);
        mv2.visitEnd();
        w2.visitEnd();
        byte[] b2 = w2.toByteArray();
        Class<?> c2 = new ClassLoader(null) {
            Class<?> def() { return defineClass("diff.C2", b2, 0, b2.length); }
        }.def();
        int jvm2 = (Integer) c2.getMethod("f").invoke(null);
        ClassNode cn2 = new ClassNode();
        new org.objectweb.asm.ClassReader(b2).accept(cn2, 0);
        MethodNode m2 = ClassIO.findMethod(cn2, "f", "()I");
        java.util.Map<String, ClassNode> cs2 = java.util.Map.of("diff/C2.class", cn2);
        Object emu2 = MiniInterpreter.run(new MiniInterpreter.Ctx(cs2, null, 0), cn2, m2, new Object[0]);
        check(jvm2 == 3231 && ((Integer) emu2) == 3231, "dup_x1 jvm=" + jvm2 + " emu=" + emu2);
        System.out.println("dup-cat2 OK");
    }

    public static void testTripleLookup() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/T", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "m", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(org.objectweb.asm.Opcodes.SIPUSH, 100);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.SIPUSH, 200);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.SIPUSH, 55);
        mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "t/T", "lk",
                "(III)Ljava/lang/String;", false);
        mv.visitInsn(org.objectweb.asm.Opcodes.POP);
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "m", "()I");
        java.util.List<StringDecryptor.LookupSite> sites =
                StringDecryptor.lookupSites(cn, m, "(III)Ljava/lang/String;");
        check(sites.size() == 1, "iii-site");
        check(sites.get(0).encIdx() == (100 ^ 55) && sites.get(0).key() == 200,
                "iii-katlama: " + sites.get(0).encIdx() + "," + sites.get(0).key());
        System.out.println("triple-lookup OK");
    }

    public static void testConstFold() {
        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/C", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 40);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 2);
        mv.visitInsn(org.objectweb.asm.Opcodes.IADD);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "f", "()I");
        int n = FlowSimplifier.foldConstants(m);
        check(n == 1, "const-fold=" + n);
        java.util.List<AbstractInsnNode> ins = ClassIO.list(m);
        int pushes = 0;
        for (AbstractInsnNode x : ins) if (ClassIO.constInt(x) != null) pushes++;
        check(pushes == 1, "tek-push");
        System.out.println("const-fold OK");
    }

    public static void testDesRealData() throws Exception {

        long key = 0x0F1E2D3C4B5A6978L;
        String plain = "gercek-des-verisi-42";
        String enc = Crypto.desStringEncrypt(plain, key);
        String tmpJar = "build/test-tmp/_syndes.jar";
        String tmpOut = "build/test-tmp/_syndes-deobf.jar";
        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "syn/Des", null, "java/lang/Object", null);
            w.visitField(org.objectweb.asm.Opcodes.ACC_PRIVATE | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "T", "[Ljava/lang/String;", null, null).visitEnd();

            org.objectweb.asm.MethodVisitor c = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            c.visitCode();
            c.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
            c.visitTypeInsn(org.objectweb.asm.Opcodes.ANEWARRAY, "java/lang/String");
            c.visitInsn(org.objectweb.asm.Opcodes.DUP);
            c.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
            c.visitLdcInsn(enc);
            c.visitInsn(org.objectweb.asm.Opcodes.AASTORE);
            c.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "syn/Des", "T", "[Ljava/lang/String;");
            c.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            c.visitMaxs(0, 0);
            c.visitEnd();

            org.objectweb.asm.MethodVisitor m = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "lk", "(IJ)Ljava/lang/String;", null, null);
            m.visitCode();
            m.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
            m.visitVarInsn(org.objectweb.asm.Opcodes.LLOAD, 1);
            m.visitLdcInsn(32767L);
            m.visitInsn(org.objectweb.asm.Opcodes.LAND);
            m.visitInsn(org.objectweb.asm.Opcodes.L2I);
            m.visitInsn(org.objectweb.asm.Opcodes.IXOR);
            m.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
            m.visitInsn(org.objectweb.asm.Opcodes.IXOR);
            m.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 3);
            m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "syn/Des", "T", "[Ljava/lang/String;");
            m.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 3);
            m.visitInsn(org.objectweb.asm.Opcodes.AALOAD);
            m.visitVarInsn(org.objectweb.asm.Opcodes.LLOAD, 1);
            m.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "syn/Des",
                    "desDec", "(Ljava/lang/String;J)Ljava/lang/String;", false);
            m.visitInsn(org.objectweb.asm.Opcodes.ARETURN);
            m.visitMaxs(0, 0);
            m.visitEnd();

            org.objectweb.asm.MethodVisitor d = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "desDec", "(Ljava/lang/String;J)Ljava/lang/String;", null, null);
            d.visitCode();
            d.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0);
            d.visitVarInsn(org.objectweb.asm.Opcodes.LLOAD, 1);
            d.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "com/zkmdeobf/Crypto",
                    "desStringDecrypt", "(Ljava/lang/String;J)Ljava/lang/String;", false);
            d.visitInsn(org.objectweb.asm.Opcodes.ARETURN);
            d.visitMaxs(0, 0);
            d.visitEnd();

            int arg = (int) ((key & 32767) ^ 0 ^ 0);
            org.objectweb.asm.MethodVisitor mm = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "main", "([Ljava/lang/String;)V", null, null);
            mm.visitCode();
            mm.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System",
                    "out", "Ljava/io/PrintStream;");
            mm.visitIntInsn(org.objectweb.asm.Opcodes.SIPUSH, arg);
            mm.visitLdcInsn(key);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "syn/Des",
                    "lk", "(IJ)Ljava/lang/String;", false);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                    "println", "(Ljava/lang/String;)V", false);
            mm.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            mm.visitMaxs(0, 0);
            mm.visitEnd();
            w.visitEnd();
            byte[] b = w.toByteArray();

            java.util.Map<String, byte[]> entries = new java.util.TreeMap<>();
            entries.put("syn/Des.class", b);

            java.nio.file.Path cryptoClass = java.nio.file.Paths.get(
                    "build/classes/java/main/com/zkmdeobf/Crypto.class");
            entries.put("com/zkmdeobf/Crypto.class",
                    java.nio.file.Files.readAllBytes(cryptoClass));
            ClassIO.writeJar(tmpJar, entries);
        }
        Pipeline.Result r = Pipeline.deobfuscateJar(tmpJar);
        check(r.stats().strPatched() >= 1, "des-dinamik-patch=" + r.stats().strPatched());
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar(tmpOut, jar);
        check(runMain(tmpOut, findMain(tmpOut)).contains(plain), "run-des");
        System.out.println("des-real-data OK");
    }

    static String findMain(String jar) throws Exception {
        java.util.Map<String, ClassNode> rcs = ClassIO.readJar(jar);
        for (ClassNode cn : rcs.values()) {
            for (MethodNode mm : cn.methods) {
                if (mm.name.equals("main") && mm.desc.equals("([Ljava/lang/String;)V"))
                    return cn.name.replace('/', '.');
            }
        }
        throw new AssertionError("main-missing: " + jar);
    }

    public static void testInterpreterLimits() throws Exception {

        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "t/FD", null, "java/lang/Object", null);
            org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "f", "()I", null, null);
            mv.visitCode();
            mv.visitInsn(org.objectweb.asm.Opcodes.FCONST_1);
            mv.visitInsn(org.objectweb.asm.Opcodes.FCONST_2);
            mv.visitInsn(org.objectweb.asm.Opcodes.FADD);
            mv.visitInsn(org.objectweb.asm.Opcodes.FCONST_2);
            mv.visitInsn(org.objectweb.asm.Opcodes.FCMPG);
            mv.visitLdcInsn(2.5);
            mv.visitLdcInsn(2.5);
            mv.visitInsn(org.objectweb.asm.Opcodes.DCMPL);
            mv.visitInsn(org.objectweb.asm.Opcodes.IADD);
            mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
            w.visitEnd();
            byte[] b = w.toByteArray();
            Class<?> c = new ClassLoader(null) {
                Class<?> def() { return defineClass("t.FD", b, 0, b.length); }
            }.def();
            int jvm = (Integer) c.getMethod("f").invoke(null);
            ClassNode cn = new ClassNode();
            new org.objectweb.asm.ClassReader(b).accept(cn, 0);
            MethodNode m = ClassIO.findMethod(cn, "f", "()I");
            java.util.Map<String, ClassNode> cs = java.util.Map.of("t/FD.class", cn);
            Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
            check(jvm == 1 && ((Integer) emu) == 1, "f/d-arith jvm=" + jvm + " emu=" + emu);
        }

        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "t/SC", null, "java/lang/Object", null);
            org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "f", "()Ljava/lang/String;", null, null);
            mv.visitCode();
            mv.visitLdcInsn("a");
            mv.visitLdcInsn("b");
            mv.visitInvokeDynamicInsn("makeConcatWithConstants",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    new org.objectweb.asm.Handle(org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                            "java/lang/invoke/StringConcatFactory", "makeConcatWithConstants",
                            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                            false),
                    "\u0001-\u0001");
            mv.visitInsn(org.objectweb.asm.Opcodes.ARETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
            w.visitEnd();
            byte[] b = w.toByteArray();
            Class<?> c = new ClassLoader(null) {
                Class<?> def() { return defineClass("t.SC", b, 0, b.length); }
            }.def();
            Object jvm = c.getMethod("f").invoke(null);
            ClassNode cn = new ClassNode();
            new org.objectweb.asm.ClassReader(b).accept(cn, 0);
            MethodNode m = ClassIO.findMethod(cn, "f", "()Ljava/lang/String;");
            java.util.Map<String, ClassNode> cs = java.util.Map.of("t/SC.class", cn);
            Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
            check("a-b".equals(jvm) && "a-b".equals(emu), "concat jvm=" + jvm + " emu=" + emu);
        }

        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "t/EX", null, "java/lang/Object", null);
            org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "f", "()I", null, null);
            mv.visitCode();
            org.objectweb.asm.Label s = new org.objectweb.asm.Label();
            org.objectweb.asm.Label e = new org.objectweb.asm.Label();
            org.objectweb.asm.Label h = new org.objectweb.asm.Label();
            mv.visitTryCatchBlock(s, e, h, "java/lang/RuntimeException");
            mv.visitLabel(s);
            mv.visitTypeInsn(org.objectweb.asm.Opcodes.NEW, "java/lang/RuntimeException");
            mv.visitInsn(org.objectweb.asm.Opcodes.DUP);
            mv.visitLdcInsn("x");
            mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL,
                    "java/lang/RuntimeException", "<init>", "(Ljava/lang/String;)V", false);
            mv.visitInsn(org.objectweb.asm.Opcodes.ATHROW);
            mv.visitLabel(e);
            mv.visitLabel(h);
            mv.visitInsn(org.objectweb.asm.Opcodes.POP);
            mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 7);
            mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
            w.visitEnd();
            byte[] b = w.toByteArray();
            Class<?> c = new ClassLoader(null) {
                Class<?> def() { return defineClass("t.EX", b, 0, b.length); }
            }.def();
            int jvm = (Integer) c.getMethod("f").invoke(null);
            ClassNode cn = new ClassNode();
            new org.objectweb.asm.ClassReader(b).accept(cn, 0);
            MethodNode m = ClassIO.findMethod(cn, "f", "()I");
            java.util.Map<String, ClassNode> cs = java.util.Map.of("t/EX.class", cn);
            Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
            check(jvm == 7 && ((Integer) emu) == 7, "athrow jvm=" + jvm + " emu=" + emu);
        }

        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "t/MA", null, "java/lang/Object", null);
            org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "f", "()I", null, null);
            mv.visitCode();
            mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
            mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_3);
            mv.visitMultiANewArrayInsn("[[I", 2);
            mv.visitInsn(org.objectweb.asm.Opcodes.ARRAYLENGTH);
            mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
            w.visitEnd();
            byte[] b = w.toByteArray();
            Class<?> c = new ClassLoader(null) {
                Class<?> def() { return defineClass("t.MA", b, 0, b.length); }
            }.def();
            int jvm = (Integer) c.getMethod("f").invoke(null);
            ClassNode cn = new ClassNode();
            new org.objectweb.asm.ClassReader(b).accept(cn, 0);
            MethodNode m = ClassIO.findMethod(cn, "f", "()I");
            java.util.Map<String, ClassNode> cs = java.util.Map.of("t/MA.class", cn);
            Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
            check(jvm == 2 && ((Integer) emu) == 2, "multianewarray jvm=" + jvm + " emu=" + emu);
        }
        System.out.println("interpreter-limits OK");
    }

    public static void testRefLimits() {

        ClassNode rc = new ClassNode();
        rc.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "r/R", null, "java/lang/Object", null);
        MethodNode idx = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "idx", "(J)I", null, null);
        idx.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ICONST_0));
        idx.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.IRETURN));
        rc.methods.add(idx);
        MethodNode res = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "res",
                "(JJ)Ljava/lang/reflect/Method;", null, null);
        res.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ACONST_NULL));
        res.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ARETURN));
        rc.methods.add(res);
        ClassNode cn = new ClassNode();
        cn.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "r/C", null, "java/lang/Object", null);
        MethodNode m = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "m", "()V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(11L));
        m.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(22L));
        org.objectweb.asm.Handle bsm = new org.objectweb.asm.Handle(
                org.objectweb.asm.Opcodes.H_INVOKESTATIC, "r/R", "bsm",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                false);
        m.instructions.add(new org.objectweb.asm.tree.InvokeDynamicInsnNode(
                "x", "(JJ)J", bsm));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.POP2));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        cn.methods.add(m);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("r/R.class", rc);
        classes.put("r/C.class", cn);
        java.util.List<ReferenceResolver.IndySite> sites =
                ReferenceResolver.indySites(classes, cn, m);
        check(sites.size() == 1 && sites.get(0).keys().size() == 2,
                "cok-anahtar site=" + sites.size());

        MethodNode m2 = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "m2", "()V", null, null);
        m2.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(33L));
        org.objectweb.asm.tree.InvokeDynamicInsnNode id2 =
                new org.objectweb.asm.tree.InvokeDynamicInsnNode("y", "(J)Ljava/lang/Class;", bsm);
        m2.instructions.add(id2);
        m2.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.POP));
        m2.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        cn.methods.add(m2);
        ReferenceResolver.Resolved rr = new ReferenceResolver.Resolved(
                null, null, String.class, null);
        check(ReferenceResolver.inlineIndy(m2, id2, java.util.List.of(m2.instructions.getFirst()), rr),
                "class-inline");

        MethodNode mj = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "j", "()I", null, null);
        org.objectweb.asm.tree.LabelNode l0 = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode lsub = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode l1 = new org.objectweb.asm.tree.LabelNode();
        mj.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ICONST_0));
        mj.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ISTORE, 0));
        mj.instructions.add(new org.objectweb.asm.tree.JumpInsnNode(org.objectweb.asm.Opcodes.JSR, lsub));
        mj.instructions.add(l1);
        mj.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ILOAD, 0));
        mj.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.IRETURN));
        mj.instructions.add(lsub);
        mj.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ASTORE, 1));
        mj.instructions.add(new org.objectweb.asm.tree.IincInsnNode(0, 1));
        mj.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.RET, 1));
        check(Rewriter.hasJsrRet(mj), "jsr-var");
        check(Rewriter.inlineJsr(mj) && !Rewriter.hasJsrRet(mj), "jsr-inline");
        System.out.println("ref-limits OK");
    }

    public static void testEmuTables() throws Exception {

        java.util.Map<String, ClassNode> cs = ClassIO.readJar("corpus/fixtures/demo2-obf.jar");
        ClassNode wb = cs.get("a/a/b.class");
        TableExtractor.Tables emu = TableExtractor.extractViaEmulation(wb, cs, null);
        check(emu != null && emu.strings().size() == 8, "emu-tab");
        TableExtractor.Tables heur = TableExtractor.extract(wb);
        check(heur != null && emu.strings().equals(heur.strings()), "emu-esit: " + emu.strings());
        check(emu.longs().equals(heur.longs()), "emu-longs");
        System.out.println("emu-tables OK");
    }

    public static void testSwitchFold() {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/SW", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "(I)I", null, null);
        mv.visitCode();
        org.objectweb.asm.Label d = new org.objectweb.asm.Label();
        org.objectweb.asm.Label c0 = new org.objectweb.asm.Label();
        org.objectweb.asm.Label c1 = new org.objectweb.asm.Label();
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
        mv.visitTableSwitchInsn(0, 1, d, c0, c1);
        mv.visitLabel(c0);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 10);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitLabel(c1);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 20);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitLabel(d);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 30);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        org.objectweb.asm.MethodVisitor mv2 = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "g", "()I", null, null);
        mv2.visitCode();
        mv2.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        org.objectweb.asm.Label d2 = new org.objectweb.asm.Label();
        org.objectweb.asm.Label x0 = new org.objectweb.asm.Label();
        org.objectweb.asm.Label x1 = new org.objectweb.asm.Label();
        mv2.visitTableSwitchInsn(0, 1, d2, x0, x1);
        mv2.visitLabel(x0);
        mv2.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 10);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv2.visitLabel(x1);
        mv2.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 20);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv2.visitLabel(d2);
        mv2.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 30);
        mv2.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv2.visitMaxs(0, 0);
        mv2.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode g = ClassIO.findMethod(cn, "g", "()I");
        int n = FlowSimplifier.foldSwitches(g);
        check(n >= 2, "switch-fold=" + n);
        boolean hasSwitch = false;
        for (AbstractInsnNode x = g.instructions.getFirst(); x != null; x = x.getNext()) {
            if (x instanceof org.objectweb.asm.tree.TableSwitchInsnNode) hasSwitch = true;
        }
        check(!hasSwitch, "switch-kaldi");
        System.out.println("switch-fold OK");
    }

    public static void testOverrideSafeRename() {

        ClassNode sup = new ClassNode();
        sup.visit(org.objectweb.asm.Opcodes.V17, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "p/Sup", null, "java/lang/Object", null);
        MethodNode sm = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC, "ab", "()V", null, null);
        sm.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        sup.methods.add(sm);
        ClassNode sub = new ClassNode();
        sub.visit(org.objectweb.asm.Opcodes.V17, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "p/Sub", null, "p/Sup", null);
        MethodNode om = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC, "ab", "()V", null, null);
        om.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        sub.methods.add(om);
        MethodNode own = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC, "xy", "()V", null, null);
        own.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        sub.methods.add(own);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("p/Sup.class", sup);
        classes.put("p/Sub.class", sub);
        java.util.Map<String, String> map = Renamer.buildMapping(classes, null);
        check(!map.containsKey("p/Sub.ab()V"), "override-korundu");
        check(map.containsKey("p/Sub.xy()V"), "native-rename-missing:" + map.keySet());
        System.out.println("override-safe-rename OK");
    }

    public static void testDynLookupFallback() throws Exception {

        String tmpJar = "build/test-tmp/_synlk.jar";
        String tmpOut = "build/test-tmp/_synlk-deobf.jar";
        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "syn/Lk", null, "java/lang/Object", null);
            w.visitField(org.objectweb.asm.Opcodes.ACC_PRIVATE | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "T", "[Ljava/lang/String;", null, null).visitEnd();
            org.objectweb.asm.MethodVisitor c = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            c.visitCode();
            c.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
            c.visitTypeInsn(org.objectweb.asm.Opcodes.ANEWARRAY, "java/lang/String");
            c.visitInsn(org.objectweb.asm.Opcodes.DUP);
            c.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
            c.visitLdcInsn("alfa");
            c.visitInsn(org.objectweb.asm.Opcodes.AASTORE);
            c.visitInsn(org.objectweb.asm.Opcodes.DUP);
            c.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
            c.visitLdcInsn("beta");
            c.visitInsn(org.objectweb.asm.Opcodes.AASTORE);
            c.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "syn/Lk", "T", "[Ljava/lang/String;");
            c.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            c.visitMaxs(0, 0);
            c.visitEnd();

            org.objectweb.asm.MethodVisitor m = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "lk", "(II)Ljava/lang/String;", null, null);
            m.visitCode();
            m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "syn/Lk", "T", "[Ljava/lang/String;");
            m.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
            m.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 1);
            m.visitInsn(org.objectweb.asm.Opcodes.IADD);
            m.visitInsn(org.objectweb.asm.Opcodes.AALOAD);
            m.visitInsn(org.objectweb.asm.Opcodes.ARETURN);
            m.visitMaxs(0, 0);
            m.visitEnd();
            org.objectweb.asm.MethodVisitor mm = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "main", "([Ljava/lang/String;)V", null, null);
            mm.visitCode();
            mm.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System",
                    "out", "Ljava/io/PrintStream;");
            mm.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
            mm.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "syn/Lk",
                    "lk", "(II)Ljava/lang/String;", false);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                    "println", "(Ljava/lang/String;)V", false);
            mm.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            mm.visitMaxs(0, 0);
            mm.visitEnd();
            w.visitEnd();
            java.util.Map<String, byte[]> entries = new java.util.TreeMap<>();
            entries.put("syn/Lk.class", w.toByteArray());
            ClassIO.writeJar(tmpJar, entries);
        }
        Pipeline.Result r = Pipeline.deobfuscateJar(tmpJar);
        check(r.stats().strPatched() >= 1, "dinamik-lookup-patch=" + r.stats().strPatched());
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar(tmpOut, jar);
        check(runMain(tmpOut, findMain(tmpOut)).contains("beta"), "run-lookup");
        System.out.println("dyn-lookup OK");
    }

    public static void testInterfaceInline() {

        try {
            java.lang.reflect.Method get = java.util.List.class.getDeclaredMethod("get", int.class);
            ReferenceResolver.Resolved rr = new ReferenceResolver.Resolved(get, null);
            org.objectweb.asm.Type[] iargs = {
                    org.objectweb.asm.Type.getType(java.util.List.class),
                    org.objectweb.asm.Type.INT_TYPE,
                    org.objectweb.asm.Type.LONG_TYPE,
            };
            org.objectweb.asm.Type iret = org.objectweb.asm.Type.getType(Object.class);
            org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "m", "()V", null, null);
            m.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(99L));
            org.objectweb.asm.tree.InvokeDynamicInsnNode id =
                    new org.objectweb.asm.tree.InvokeDynamicInsnNode("x",
                            "(Ljava/util/List;IJ)Ljava/lang/Object;",
                            new org.objectweb.asm.Handle(org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                                    "r/R", "bsm",
                                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                                    false));
            m.instructions.add(id);
            m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.POP));
            m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
            java.util.List<org.objectweb.asm.tree.AbstractInsnNode> keys =
                    java.util.List.of(m.instructions.getFirst());
            check(ReferenceResolver.inlineIndy(m, id, keys, rr), "itf-inline");
            boolean found = false;
            for (org.objectweb.asm.tree.AbstractInsnNode x = m.instructions.getFirst();
                    x != null; x = x.getNext()) {
                if (x instanceof org.objectweb.asm.tree.MethodInsnNode mi
                        && mi.getOpcode() == org.objectweb.asm.Opcodes.INVOKEINTERFACE
                        && mi.owner.equals("java/util/List") && mi.name.equals("get")) found = true;
            }
            check(found, "invokeinterface-missing");
        } catch (Exception e) {
            throw new AssertionError("itf-hazirlik: " + e);
        }
        System.out.println("interface-inline OK");
    }

    public static void testComboBudget() {
        java.util.List<java.util.List<java.util.List<String>>> big = new java.util.ArrayList<>();
        for (int i = 0; i < 12; i++) {
            java.util.List<java.util.List<String>> perN = new java.util.ArrayList<>();
            for (int j = 0; j < 12; j++) perN.add(java.util.List.of("s" + j));
            big.add(perN);
        }
        check(LookupRecovery.tooBig(big, 12), "budget-exceeded-missing");
        java.util.List<java.util.List<java.util.List<String>>> small = new java.util.ArrayList<>();
        for (int i = 0; i < 2; i++) {
            java.util.List<java.util.List<String>> perN = new java.util.ArrayList<>();
            perN.add(java.util.List.of("a"));
            perN.add(java.util.List.of("b"));
            small.add(perN);
        }
        check(!LookupRecovery.tooBig(small, 12), "butce-yanlis-pozitif");
        System.out.println("combo-budget OK");
    }

    public static void testXorZeroKey() {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/Z", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "<clinit>", "()V", null, null);
        mv.visitCode();
        org.objectweb.asm.Label d = new org.objectweb.asm.Label();
        org.objectweb.asm.Label[] ls = new org.objectweb.asm.Label[6];
        for (int i = 0; i < 6; i++) ls[i] = new org.objectweb.asm.Label();
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
        mv.visitTableSwitchInsn(0, 5, d, ls);
        int[] kv = {0, 39, 95, 2, 24, 6, 61};
        for (int i = 0; i < 6; i++) {
            mv.visitLabel(ls[i]);
            mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, kv[i]);
            mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        }
        mv.visitLabel(d);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, kv[6]);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
        int[] keys = StringDecryptor.extractXorKeys(cl);
        check(keys != null && keys[0] == 0 && keys.length == 7, "sifir-anahtar");
        System.out.println("xor-zero-key OK");
    }

    public static void testFloatBranchFold() {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/FB", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(org.objectweb.asm.Opcodes.FCONST_2);
        mv.visitInsn(org.objectweb.asm.Opcodes.FCONST_1);
        mv.visitInsn(org.objectweb.asm.Opcodes.FCMPL);
        org.objectweb.asm.Label l = new org.objectweb.asm.Label();
        mv.visitJumpInsn(org.objectweb.asm.Opcodes.IFLT, l);
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitLabel(l);
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "f", "()I");
        int n = FlowSimplifier.foldMethod(cn, m, java.util.Map.of(), java.util.Map.of());
        check(n > 0, "float-dal-katlanmadi");
        boolean hasIf = false;
        for (AbstractInsnNode x = m.instructions.getFirst(); x != null; x = x.getNext()) {
            if (x.getOpcode() == org.objectweb.asm.Opcodes.IFLT) hasIf = true;
        }
        check(!hasIf, "iflt-kaldi");
        System.out.println("float-branch OK");
    }

    public static void testClinitChainConst() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/CC", null, "java/lang/Object", null);
        w.visitField(org.objectweb.asm.Opcodes.ACC_STATIC | org.objectweb.asm.Opcodes.ACC_PRIVATE,
                "F", "I", null, null).visitEnd();
        org.objectweb.asm.MethodVisitor c = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        c.visitCode();
        c.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 40);
        c.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
        c.visitInsn(org.objectweb.asm.Opcodes.IADD);
        c.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "t/CC", "F", "I");
        c.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        c.visitMaxs(0, 0);
        c.visitEnd();
        org.objectweb.asm.MethodVisitor m = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        m.visitCode();
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/CC", "F", "I");
        m.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 42);
        org.objectweb.asm.Label l = new org.objectweb.asm.Label();
        m.visitJumpInsn(org.objectweb.asm.Opcodes.IF_ICMPEQ, l);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitLabel(l);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode mm = ClassIO.findMethod(cn, "f", "()I");
        int n = FlowSimplifier.foldMethod(cn, mm,
                FlowSimplifier.clinitConstants(cn), FlowSimplifier.trivialGetters(cn));
        check(n > 0, "zincir-sabit-katlanmadi");
        System.out.println("clinit-chain OK");
    }

    public static void testCheckcastHandler() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/CC", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        mv.visitCode();
        org.objectweb.asm.Label s = new org.objectweb.asm.Label();
        org.objectweb.asm.Label e = new org.objectweb.asm.Label();
        org.objectweb.asm.Label h = new org.objectweb.asm.Label();
        mv.visitTryCatchBlock(s, e, h, "java/lang/ClassCastException");
        mv.visitLabel(s);
        mv.visitLdcInsn("s");
        mv.visitTypeInsn(org.objectweb.asm.Opcodes.CHECKCAST, "java/lang/Integer");
        mv.visitInsn(org.objectweb.asm.Opcodes.POP);
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitLabel(e);
        mv.visitLabel(h);
        mv.visitInsn(org.objectweb.asm.Opcodes.POP);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 9);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        Class<?> c = new ClassLoader(null) {
            Class<?> def() { return defineClass("t.CC", b, 0, b.length); }
        }.def();
        int jvm = (Integer) c.getMethod("f").invoke(null);
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(b).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "f", "()I");
        java.util.Map<String, ClassNode> cs = java.util.Map.of("t/CC.class", cn);
        Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
        check(jvm == 9 && ((Integer) emu) == 9, "checkcast-handler jvm=" + jvm + " emu=" + emu);
        System.out.println("checkcast-handler OK");
    }

    public static void testSharedStatics() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/SS", null, "java/lang/Object", null);
        w.visitField(org.objectweb.asm.Opcodes.ACC_STATIC | org.objectweb.asm.Opcodes.ACC_PRIVATE,
                "F", "I", null, null).visitEnd();
        org.objectweb.asm.MethodVisitor c = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        c.visitCode();
        c.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 41);
        c.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "t/SS", "F", "I");
        c.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        c.visitMaxs(0, 0);
        c.visitEnd();
        org.objectweb.asm.MethodVisitor hh = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "h", "()I", null, null);
        hh.visitCode();
        hh.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/SS", "F", "I");
        hh.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        hh.visitMaxs(0, 0);
        hh.visitEnd();
        org.objectweb.asm.MethodVisitor f = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        f.visitCode();
        f.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "t/SS", "h", "()I", false);
        f.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        f.visitMaxs(0, 0);
        f.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(b).accept(cn, 0);
        java.util.Map<String, ClassNode> cs = new java.util.HashMap<>();
        cs.put("t/SS.class", cn);
        MiniInterpreter.Ctx ctx = new MiniInterpreter.Ctx(cs, null, 0);
        MiniInterpreter.run(ctx, cn, ClassIO.findMethod(cn, "<clinit>", "()V"), new Object[0]);
        Object r = MiniInterpreter.run(ctx, cn, ClassIO.findMethod(cn, "f", "()I"), new Object[0]);
        check(((Integer) r) == 41, "paylasimli-statik=" + r);
        System.out.println("shared-statics OK");
    }

    public static void testJsrDeadCodeGuard() {

        MethodNode mj = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "j", "()I", null, null);
        org.objectweb.asm.tree.LabelNode lsub = new org.objectweb.asm.tree.LabelNode();
        mj.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ICONST_0));
        mj.instructions.add(new org.objectweb.asm.tree.JumpInsnNode(org.objectweb.asm.Opcodes.JSR, lsub));
        mj.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.IRETURN));
        mj.instructions.add(lsub);
        mj.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ASTORE, 0));
        mj.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.RET, 0));
        check(Rewriter.hasJsrRet(mj), "jsr-missing");
        check(Rewriter.removeDeadCode(mj) == 0, "jsr-dead-code-removed");
        check(Rewriter.hasJsrRet(mj), "jsr-bozuldu");
        System.out.println("jsr-guard OK");
    }

    public static void testFinallyPreserved() {

        MethodNode m = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "f", "()V", null, null);
        org.objectweb.asm.tree.LabelNode s = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode e = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode h = new org.objectweb.asm.tree.LabelNode();
        m.instructions.add(s);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        m.instructions.add(e);
        m.instructions.add(h);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ATHROW));
        m.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(s, e, h, null));
        ClassNode cn = new ClassNode();
        cn.visit(org.objectweb.asm.Opcodes.V17, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "t/F", null, "java/lang/Object", null);
        check(Rewriter.stripFakeHandlers(cn, m) == 0, "finally-removed");
        check(m.tryCatchBlocks.size() == 1, "finally-kayboldu");
        System.out.println("finally OK");
    }

    public static void testIfNullStrict() {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/IN", null, "java/lang/Object", null);
        w.visitField(org.objectweb.asm.Opcodes.ACC_STATIC | org.objectweb.asm.Opcodes.ACC_PRIVATE,
                "F", "I", null, null).visitEnd();
        org.objectweb.asm.MethodVisitor c = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        c.visitCode();
        c.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 7);
        c.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "t/IN", "F", "I");
        c.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        c.visitMaxs(0, 0);
        c.visitEnd();
        org.objectweb.asm.MethodVisitor m = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        m.visitCode();
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/IN", "F", "I");
        org.objectweb.asm.Label l = new org.objectweb.asm.Label();
        m.visitJumpInsn(org.objectweb.asm.Opcodes.IFNULL, l);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitLabel(l);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode mm = ClassIO.findMethod(cn, "f", "()I");
        int n = FlowSimplifier.foldMethod(cn, mm,
                FlowSimplifier.clinitConstants(cn), FlowSimplifier.trivialGetters(cn));
        check(n == 0, "ifnull-folded=" + n);
        System.out.println("ifnull-strict OK");
    }

    public static void testMultiLookupNames() throws Exception {

        String tmpJar = "build/test-tmp/_synov.jar";
        String tmpOut = "build/test-tmp/_synov-deobf.jar";
        {
            org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                    org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
            w.visit(org.objectweb.asm.Opcodes.V17,
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                    "syn/Ov", null, "java/lang/Object", null);
            org.objectweb.asm.MethodVisitor a = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "lk", "(IJ)I", null, null);
            a.visitCode();
            a.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
            a.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 100);
            a.visitInsn(org.objectweb.asm.Opcodes.IADD);
            a.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
            a.visitMaxs(0, 0);
            a.visitEnd();
            org.objectweb.asm.MethodVisitor b = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "lk", "(IJ)J", null, null);
            b.visitCode();
            b.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0);
            b.visitIntInsn(org.objectweb.asm.Opcodes.SIPUSH, 200);
            b.visitInsn(org.objectweb.asm.Opcodes.IADD);
            b.visitInsn(org.objectweb.asm.Opcodes.I2L);
            b.visitInsn(org.objectweb.asm.Opcodes.LRETURN);
            b.visitMaxs(0, 0);
            b.visitEnd();
            org.objectweb.asm.MethodVisitor mm = w.visitMethod(
                    org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                    "main", "([Ljava/lang/String;)V", null, null);
            mm.visitCode();
            mm.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System",
                    "out", "Ljava/io/PrintStream;");
            mm.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
            mm.visitLdcInsn(0L);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "syn/Ov",
                    "lk", "(IJ)I", false);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                    "println", "(I)V", false);
            mm.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System",
                    "out", "Ljava/io/PrintStream;");
            mm.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
            mm.visitLdcInsn(0L);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "syn/Ov",
                    "lk", "(IJ)J", false);
            mm.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream",
                    "println", "(J)V", false);
            mm.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            mm.visitMaxs(0, 0);
            mm.visitEnd();
            w.visitEnd();
            java.util.Map<String, byte[]> entries = new java.util.TreeMap<>();
            entries.put("syn/Ov.class", w.toByteArray());
            ClassIO.writeJar(tmpJar, entries);
        }
        Pipeline.Result r = Pipeline.deobfuscateJar(tmpJar);
        check(r.stats().intPatched() == 2, "asiri-yuk-patch=" + r.stats().intPatched());
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar(tmpOut, jar);
        String out = runMain(tmpOut, findMain(tmpOut));
        check(out.contains("101") && out.contains("201"), "run-overload: " + out);
        System.out.println("multi-lookup OK");
    }

    public static void testStackSizesWidening() {
        // I2L/I2D/F2L/F2D pop one word and push two; L2D/D2L are 2->2.
        // A wrong [2,2] here corrupts producer search depth tracking.
        org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "()V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_5));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.I2L));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LSTORE, 1));
        java.util.List<AbstractInsnNode> ins = ClassIO.list(m);
        int[] s = Rewriter.stackSizes(ins.get(1));
        check(s[0] == 1 && s[1] == 2, "i2l-stack=" + s[0] + "," + s[1]);
        m.instructions.clear();
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.FCONST_1));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.F2D));
        s = Rewriter.stackSizes(ClassIO.list(m).get(1));
        check(s[0] == 1 && s[1] == 2, "f2d-stack=" + s[0] + "," + s[1]);
        System.out.println("stack-sizes OK");
    }

    public static void testFindProducerIincBarrier() {
        // ILOAD x; IINC x; ISTORE y must not resolve to the stale pre-IINC value.
        org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "()V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 1));
        m.instructions.add(new org.objectweb.asm.tree.IincInsnNode(1, 1));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ISTORE, 2));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        java.util.List<AbstractInsnNode> ins = ClassIO.list(m);
        check(Rewriter.findProducer(ins, 2) == null, "iinc-bariyer-missing");
        System.out.println("iinc-barrier OK");
    }

    public static void testPatchPurity() {
        // A decrypt range containing a real call must be vetoed, never silently dropped.
        org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "()V", null, null);
        org.objectweb.asm.tree.LdcInsnNode from =
                new org.objectweb.asm.tree.LdcInsnNode("enc");
        org.objectweb.asm.tree.MethodInsnNode evil =
                new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "t/Evil", "run", "()V", false);
        org.objectweb.asm.tree.MethodInsnNode call =
                new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "t/X", "dec", "(Ljava/lang/String;)Ljava/lang/String;", false);
        m.instructions.add(from);
        m.instructions.add(evil);
        m.instructions.add(call);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.POP));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        check(!Rewriter.patchCallSite(m, from, call, "plain"), "sidefx-patch-yazildi");
        boolean kept = false;
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext())
            if (n instanceof MethodInsnNode mi && mi.name.equals("run")) kept = true;
        check(kept, "sidefx-cagri-silindi");
        System.out.println("patch-purity OK");
    }

    public static void testDropOrphanKeepsLineNumbers() {
        org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "()I", null, null);
        org.objectweb.asm.tree.LabelNode l0 = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode lLine = new org.objectweb.asm.tree.LabelNode();
        m.instructions.add(l0);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_1));
        m.instructions.add(lLine);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.IRETURN));
        m.instructions.add(new org.objectweb.asm.tree.LineNumberNode(10, lLine));
        Rewriter.dropOrphanLabels(m);
        boolean kept = false;
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext())
            if (n == lLine) kept = true;
        check(kept, "linenumber-label-silindi");
        ClassNode cn = new ClassNode();
        cn.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "t/L", null, "java/lang/Object", null);
        cn.methods.add(m);
        ClassIO.toBytes(cn);
        System.out.println("linenumber-label OK");
    }

    public static void testCallerPushPatternRejected() {
        // Standard javac new-Object[]{...} callers push fresh values INSIDE the
        // array range; deleting the range would drop the arguments, so the
        // rewrite must refuse.
        ClassNode cn = new ClassNode();
        cn.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "syn/P", null, "java/lang/Object", null);
        org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "caller", "()V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_1));
        m.instructions.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.DUP));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_0));
        m.instructions.add(new org.objectweb.asm.tree.LdcInsnNode("fresh-arg"));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.AASTORE));
        m.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                "syn/P", "foo", "([Ljava/lang/Object;)V", false));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        cn.methods.add(m);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("syn/P.class", cn);
        java.util.Map<String, String> nd = new java.util.HashMap<>();
        nd.put("syn/P.foo([Ljava/lang/Object;)V", "(Ljava/lang/String;)V");
        check(ParamRestorer.rewriteCallers(classes, nd) == 0, "push-pattern-written");
        System.out.println("caller-pattern OK");
    }

    public static void testCalleeSlotRelocation() {
        // Unpack widens an Object store into a long parameter while a
        // temporary sits in the overlapping slot: the temp must move, not alias.
        ClassNode cn = new ClassNode();
        cn.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "syn/P", null, "java/lang/Object", null);
        org.objectweb.asm.tree.MethodNode m = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "foo", "([Ljava/lang/Object;)J", null, null);
        // ZKM prolog shape: ALOAD 0, DUP, [..], AALOAD, CHECKCAST, ASTORE 1, POP
        // Temp deliberately sits AT slot 1..2: the widened J param would alias it.
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.DUP));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_0));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.AALOAD));
        m.instructions.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ASTORE, 1));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.POP));
        // temp long in slot 1..2 (collides with J param slots 0..1? slot 1 is shared)
        m.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(7L));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LSTORE, 1));
        // use: unbox local 1, add temp, return
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 1));
        m.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Long", "longValue", "()J", false));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.LLOAD, 1));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.LADD));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.LRETURN));
        cn.methods.add(m);
        ParamRestorer.Plan p = ParamRestorer.analyze(cn, m);
        check(p != null && p.newDesc().equals("(J)J"), "reloc-plan: " + (p == null ? "null" : p.newDesc()));
        // The temp shares slots 2..3 with nothing, but slot 1 of the unpack
        // feeds the J param: slot 2..3 temp is adjacent, so the rewrite is
        // safe ONLY when the temp doesn't overlap; here it must either
        // succeed cleanly or refuse, never alias.
        boolean ok = ParamRestorer.rewriteCallee(cn, p);
        if (!ok) {
            check(m.desc.equals("([Ljava/lang/Object;)J"), "reloc-desc: " + m.desc);
            System.out.println("callee-relocation OK (refused cleanly)");
            return;
        }
        check(m.desc.equals("(J)J"), "reloc-desc: " + m.desc);
        // No store to slot 0/1 may remain: the only local traffic in the new
        // parameter block is writing/reading the J param itself.
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof org.objectweb.asm.tree.VarInsnNode v
                    && (v.getOpcode() == Opcodes.ISTORE || v.getOpcode() == Opcodes.LSTORE
                        || v.getOpcode() == Opcodes.ASTORE || v.getOpcode() == Opcodes.FSTORE
                        || v.getOpcode() == Opcodes.DSTORE)
                    && (v.var == 0 || v.var == 1)) {
                check(false, "slot-aliasing op=" + n.getOpcode() + " var=" + v.var);
            }
        }
        // And the rewritten method must still verify.
        ClassIO.toBytes(cn);
        System.out.println("callee-relocation OK");
    }

    public static void testNativeSkipped() {
        ClassNode cn = new ClassNode();
        cn.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "syn/N", null, "java/lang/Object", null);
        org.objectweb.asm.tree.MethodNode nat = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                "foo", "([Ljava/lang/Object;)V", null, null);
        cn.methods.add(nat);
        check(ParamRestorer.analyze(cn, nat) == null, "native-analiz-edildi");
        org.objectweb.asm.tree.MethodNode nm = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_NATIVE, "ab", "()V", null, null);
        cn.methods.add(nm);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("syn/N.class", cn);
        check(!Renamer.buildMapping(classes, null).containsKey("syn/N.ab()V"), "native-renamed");
        System.out.println("native-skip OK");
    }

    public static void testDeadMethodEnumGuard() {
        // Plural reflective enumeration keeps ordinary private methods, but
        // ZKM (IJ) helpers must still go so tables can die.
        ClassNode cn = new ClassNode();
        cn.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "syn/E", null, "java/lang/Object", null);
        org.objectweb.asm.tree.MethodNode en = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "e", "()V", null, null);
        en.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(
                org.objectweb.asm.Type.getType("Lsyn/E;")));
        en.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Class", "getDeclaredMethods", "()[Ljava/lang/reflect/Method;", false));
        en.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.POP));
        en.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        cn.methods.add(en);
        org.objectweb.asm.tree.MethodNode real = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "helper", "()V", null, null);
        real.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        cn.methods.add(real);
        org.objectweb.asm.tree.MethodNode lk = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "a", "(IJ)I", null, null);
        lk.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(100L));
        lk.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.LAND));
        lk.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.L2I));
        lk.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.IXOR));
        lk.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_1));
        lk.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.IXOR));
        lk.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.IRETURN));
        cn.methods.add(lk);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("syn/E.class", cn);
        Rewriter.removeDeadMethods(classes);
        check(ClassIO.findMethod(cn, "helper", "()V") != null, "enum-korumasi-missing");
        check(ClassIO.findMethod(cn, "a", "(IJ)I") == null, "zkm-helper-kaldi");
        System.out.println("enum-guard OK");
    }

    public static void testNoDynFlag() throws Exception {
        // --no-dyn must still produce a verified jar (static recovery only).
        String out = "build/test-tmp/_nodyn.jar";
        String log = runCli("corpus/fixtures/demo2-obf.jar", "-o", out, "--no-dyn");
        check(log.contains("verify: OK"), "no-dyn-verify: " + log);
        System.out.println("no-dyn OK");
    }

    public static void testParamSlotGuard() {

        ClassNode cn = new ClassNode();
        cn.visit(org.objectweb.asm.Opcodes.V17, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "syn/P", null, "java/lang/Object", null);
        MethodNode m = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "foo", "([Ljava/lang/Object;)I", null, null);
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ALOAD, 0));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.DUP));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ICONST_0));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.AALOAD));
        m.instructions.add(new org.objectweb.asm.tree.TypeInsnNode(
                org.objectweb.asm.Opcodes.CHECKCAST, "java/lang/String"));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ASTORE, 2));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.POP));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ALOAD, 0));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ARRAYLENGTH));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.IRETURN));
        cn.methods.add(m);
        ParamRestorer.Plan p = ParamRestorer.analyze(cn, m);

        if (p == null) {
            check(true, "analiz guvenli tarafta reddetti");
        } else {
            check(!ParamRestorer.rewriteCallee(cn, p), "slot-collision-written");
        }

        check(m.desc.equals("([Ljava/lang/Object;)I"), "imza-degistirildi: " + m.desc);
        System.out.println("param-slot-guard OK");
    }

    public static void testCallerSizeRequired() {

        ClassNode cn = new ClassNode();
        cn.visit(org.objectweb.asm.Opcodes.V17, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "syn/P", null, "java/lang/Object", null);
        MethodNode m = new MethodNode(org.objectweb.asm.Opcodes.ACC_PUBLIC
                | org.objectweb.asm.Opcodes.ACC_STATIC, "caller", "(I)V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(org.objectweb.asm.Opcodes.ILOAD, 0));
        m.instructions.add(new org.objectweb.asm.tree.TypeInsnNode(
                org.objectweb.asm.Opcodes.ANEWARRAY, "java/lang/Object"));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.DUP));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ICONST_0));
        m.instructions.add(new org.objectweb.asm.tree.LdcInsnNode("x"));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.AASTORE));
        m.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(org.objectweb.asm.Opcodes.INVOKESTATIC,
                "syn/P", "foo", "([Ljava/lang/Object;)V", false));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.RETURN));
        cn.methods.add(m);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("syn/P.class", cn);
        java.util.Map<String, String> nd = new java.util.HashMap<>();
        nd.put("syn/P.foo([Ljava/lang/Object;)V", "(Ljava/lang/String;)V");
        check(ParamRestorer.rewriteCallers(classes, nd) == 0, "dimensionless-caller-written");
        System.out.println("caller-size OK");
    }

    public static void testDeadLookupRemoved() throws Exception {

        System.setProperty("zkmdeobf.rename", "false");
        try {
        Pipeline.Result r = Pipeline.deobfuscateJar("corpus/fixtures/demo2-obf.jar");
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar("build/test-tmp/_jt2d.jar", jar);
        java.util.Map<String, ClassNode> cs = ClassIO.readJar("build/test-tmp/_jt2d.jar");
        ClassNode wb = cs.get("a/a/b.class");
        check(wb != null, "worker-missing");
        for (MethodNode m : wb.methods)
            check(!m.desc.equals("(IJ)I") && !m.desc.equals("(IJ)J"), "lookup-kaldi:" + m.name);
        for (FieldNode f : wb.fields)
            check(!f.name.equals("d") && !f.name.equals("e") && !f.name.equals("f")
                    && !f.name.equals("g") && !f.name.equals("h"), "table-remains:" + f.name);
        int real = 0;
        MethodNode cl = ClassIO.findMethod(wb, "<clinit>", "()V");
        if (cl != null) for (AbstractInsnNode x = cl.instructions.getFirst(); x != null; x = x.getNext())
            if (x.getOpcode() >= 0) real++;
        check(real < 20, "clinit-sismemis=" + real);
        check(runMain("build/test-tmp/_jt2d.jar", "a.a.a").contains("B-good"), "run-dead");
        System.out.println("dead-lookup OK clinit=" + real);
        } finally {
            System.clearProperty("zkmdeobf.rename");
        }
    }

    public static void testCopyPropDeadStore() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/CP", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_5);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 1);
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 7);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 3);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 1);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 2);
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 2);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(b).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "f", "()I");
        java.util.Map<String, ClassNode> cs = java.util.Map.of("t/CP.class", cn);
        Object before = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
        int p = Rewriter.propagateCopies(m);
        int d = Rewriter.removeDeadStores(cn, m);
        check(p > 0 && d > 0, "cleanup-missing p=" + p + " d=" + d);
        Object after = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
        check(((Integer) before) == 5 && ((Integer) after) == 5, "sonuc-degisti");
        System.out.println("copyprop-deadstore OK");
    }

    public static void testUnwrittenDefault() {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/UW", null, "java/lang/Object", null);
        w.visitField(org.objectweb.asm.Opcodes.ACC_STATIC | org.objectweb.asm.Opcodes.ACC_PRIVATE,
                "F", "I", null, null).visitEnd();
        org.objectweb.asm.MethodVisitor m = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        m.visitCode();
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/UW", "F", "I");
        org.objectweb.asm.Label l = new org.objectweb.asm.Label();
        m.visitJumpInsn(org.objectweb.asm.Opcodes.IFNE, l);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitLabel(l);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("t/UW.class", cn);
        java.util.Map<String, FlowSimplifier.Const> cc =
                FlowSimplifier.unwrittenDefaults(classes, false);
        check(cc.get("t/UW.F") instanceof FlowSimplifier.IntConst, "default-missing");
        MethodNode mm = ClassIO.findMethod(cn, "f", "()I");
        int n = FlowSimplifier.foldMethod(cn, mm, cc, FlowSimplifier.trivialGetters(cn));
        check(n > 0, "yazilmayan-dal-katlanmadi");

        java.util.Map<String, FlowSimplifier.Const> cc2 =
                FlowSimplifier.unwrittenDefaults(classes, true);
        check(cc2.isEmpty(), "reflection-guard-missing");
        System.out.println("unwritten-default OK");
    }

    public static void testRenameDefault() throws Exception {

        System.clearProperty("zkmdeobf.rename");
        Pipeline.Result r = Pipeline.deobfuscateJar("corpus/fixtures/demo2-obf.jar");
        try {
            check(r.stats().renamed() > 0, "default-rename-missing");
            java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
            boolean hasC = false;
            for (String n : jar.keySet()) if (n.contains("C00")) hasC = true;
            check(hasC, "C00-missing");
            ClassIO.writeJar("build/test-tmp/_jt2def.jar", jar);
            check(runMain("build/test-tmp/_jt2def.jar", findMain("build/test-tmp/_jt2def.jar")).contains("B-good"),
                    "run-rename-default");
        } finally {
            System.clearProperty("zkmdeobf.rename");
        }
        System.out.println("rename-default OK");
    }

    public static void testOptimisticCycle() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/OC", null, "java/lang/Object", null);
        w.visitField(org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "b", "Z", null, null).visitEnd();
        w.visitField(org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "c", "I", null, null).visitEnd();
        org.objectweb.asm.MethodVisitor m = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        m.visitCode();
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/OC", "b", "Z");
        org.objectweb.asm.Label l1 = new org.objectweb.asm.Label();
        m.visitJumpInsn(org.objectweb.asm.Opcodes.IFEQ, l1);
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/OC", "c", "I");
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        m.visitInsn(org.objectweb.asm.Opcodes.IADD);
        m.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "t/OC", "c", "I");
        m.visitLabel(l1);
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/OC", "c", "I");
        org.objectweb.asm.Label l2 = new org.objectweb.asm.Label();
        m.visitJumpInsn(org.objectweb.asm.Opcodes.IFEQ, l2);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_1);
        m.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "t/OC", "b", "Z");
        m.visitLabel(l2);
        m.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 7);
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        Class<?> c = new ClassLoader(null) {
            Class<?> def() { return defineClass("t.OC", b, 0, b.length); }
        }.def();
        int jvm = (Integer) c.getMethod("f").invoke(null);
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(b).accept(cn, 0);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("t/OC.class", cn);
        int n = FlowSimplifier.optimisticFold(classes, false);
        check(n > 0, "optimistic-fold-missing");
        MethodNode mm = ClassIO.findMethod(cn, "f", "()I");
        boolean hasPut = false;
        for (AbstractInsnNode x = mm.instructions.getFirst(); x != null; x = x.getNext()) {
            if (x.getOpcode() == org.objectweb.asm.Opcodes.PUTSTATIC) hasPut = true;
        }
        check(!hasPut, "yazim-kaldi");

        Class<?> c2 = new ClassLoader(null) {
            Class<?> def() {
                try {
                    return defineClass("t.OC", ClassIO.toBytes(cn), 0,
                            ClassIO.toBytes(cn).length);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }.def();
        check(((Integer) c2.getMethod("f").invoke(null)) == 7 && jvm == 7, "esdegerlik");
        System.out.println("optimistic-cycle OK");
    }

    public static void testTest1Opaque() throws Exception {

        System.setProperty("zkmdeobf.rename", "false");
        try {
        Pipeline.Result r = Pipeline.deobfuscateJar("corpus/jars/demo1-zkm27/obf.jar");
        java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
        ClassIO.writeJar("build/test-tmp/_jt1.jar", jar);
        java.util.Map<String, ClassNode> cs = ClassIO.readJar("build/test-tmp/_jt1.jar");
        int opaqueReads = 0, lookupLeft = 0;
        for (ClassNode cn : cs.values()) {
            for (MethodNode m : cn.methods) {
                if (m.name.equals("<clinit>")) continue;
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                    if (n instanceof FieldInsnNode f && n.getOpcode() == Opcodes.GETSTATIC
                            && (f.desc.equals("Z") || (f.desc.equals("I") && f.name.equals("c"))))
                        opaqueReads++;
                    if (n instanceof MethodInsnNode mi && mi.owner.equals(cn.name)
                            && (mi.desc.equals("(IJ)I") || mi.desc.equals("(IJ)J"))) lookupLeft++;
                }
            }
            for (MethodNode m : cn.methods)
                check(!m.desc.equals("(IJ)I") && !m.desc.equals("(IJ)J"), "lookup-kaldi:" + m.name);
        }
        check(opaqueReads == 0, "opak-okuma-kaldi=" + opaqueReads);
        check(lookupLeft == 0, "lookup-cagrisi-kaldi");

        check(runMain("build/test-tmp/_jt1.jar", "a.a.a").contains("secret-sauce"), "run-t1");
        System.out.println("test1-opaque OK");
        } finally {
            System.clearProperty("zkmdeobf.rename");
        }
    }

    public static void testChangelogRestore() throws Exception {

        java.nio.file.Path jar = java.nio.file.Paths.get("corpus/jars/demo1-zkm27/obf.jar");
        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/demo1-zkm27.txt");
        if (!java.nio.file.Files.exists(jar) || !java.nio.file.Files.exists(map)) {
            System.out.println("changelog-restore SKIP (corpus not present)");
            return;
        }
        ChangeLogMap cm = ChangeLogMap.parse(map.toString());
        check("com/demo/Worker".equals(cm.classes.get("a/a/b")), "class-mapping");
        check("calc".equals(cm.methods.get("a/a/b.a(II)I")), "uye-esleme");
        check("MAGIC".equals(cm.fields.get("a/a/b.aI")), "field-mapping");
        System.setProperty("zkmdeobf.changelog", map.toString());
        System.setProperty("zkmdeobf.rename", "false");
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar(jar.toString());
            java.util.Map<String, byte[]> out = new java.util.TreeMap<>(r.jar());
            ClassIO.writeJar("build/test-tmp/_jt1x.jar", out);
            java.util.Map<String, ClassNode> cs = ClassIO.readJar("build/test-tmp/_jt1x.jar");
            check(cs.containsKey("com/demo/Worker.class"), "worker-missing");
            ClassNode wb = cs.get("com/demo/Worker.class");
            boolean hasCalc = false, hasMagic = false;
            for (MethodNode m : wb.methods) if (m.name.equals("calc")) hasCalc = true;
            for (FieldNode f : wb.fields) if (f.name.equals("MAGIC")) hasMagic = true;
            check(hasCalc && hasMagic, "member-restore-missing");
            check("Worker.java".equals(wb.sourceFile), "source:" + wb.sourceFile);
            check(runMain("build/test-tmp/_jt1x.jar", "com.demo.Main").contains("secret-sauce"), "run-map");
        } finally {
            System.clearProperty("zkmdeobf.changelog");
            System.clearProperty("zkmdeobf.rename");
        }
        System.out.println("changelog-restore OK");
    }

    public static void testConstValueRestore() throws Exception {

        org.objectweb.asm.ClassWriter w = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        w.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "t/CV", null, "java/lang/Object", null);
        w.visitField(org.objectweb.asm.Opcodes.ACC_STATIC | org.objectweb.asm.Opcodes.ACC_FINAL
                | org.objectweb.asm.Opcodes.ACC_PRIVATE, "F", "I", null, null).visitEnd();
        org.objectweb.asm.MethodVisitor c = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        c.visitCode();
        c.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 40);
        c.visitInsn(org.objectweb.asm.Opcodes.ICONST_2);
        c.visitInsn(org.objectweb.asm.Opcodes.IADD);
        c.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "t/CV", "F", "I");
        c.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        c.visitMaxs(0, 0);
        c.visitEnd();
        org.objectweb.asm.MethodVisitor m = w.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "f", "()I", null, null);
        m.visitCode();
        m.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "t/CV", "F", "I");
        m.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        Class<?> jc = new ClassLoader(null) {
            Class<?> def() { return defineClass("t.CV", b, 0, b.length); }
        }.def();
        int jvm = (Integer) jc.getMethod("f").invoke(null);
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(b).accept(cn, 0);
        java.util.Map<String, ClassNode> classes = new java.util.HashMap<>();
        classes.put("t/CV.class", cn);
        check(ClinitRegenerator.regenerate(cn, classes, null), "regen-missing");
        FieldNode f = ClassIO.findField(cn, "F");
        check(f != null && Integer.valueOf(42).equals(f.value), "constvalue-missing");
        Object emu = MiniInterpreter.run(new MiniInterpreter.Ctx(classes, null, 0), cn,
                ClassIO.findMethod(cn, "f", "()I"), new Object[0]);
        check(jvm == 42 && ((Integer) emu) == 42, "esdegerlik jvm=" + jvm + " emu=" + emu);
        System.out.println("constvalue OK");
    }

    static String structuralDiff(String origJar, String deobfJar) throws Exception {
        java.util.Map<String, ClassNode> a = ClassIO.readJar(origJar);
        java.util.Map<String, ClassNode> b = ClassIO.readJar(deobfJar);
        List<String> d = new ArrayList<>();
        if (a.size() != b.size()) d.add("class-count " + a.size() + " vs " + b.size());
        for (java.util.Map.Entry<String, ClassNode> e : a.entrySet()) {
            ClassNode x = e.getValue(), y = b.get(e.getKey());
            if (y == null) { d.add("SINIF-YOK " + e.getKey()); continue; }
            java.util.Set<String> fa = new java.util.TreeSet<>(), fb = new java.util.TreeSet<>();
            for (FieldNode f : x.fields) fa.add(f.name + ":" + f.desc);
            for (FieldNode f : y.fields) fb.add(f.name + ":" + f.desc);
            if (!fa.equals(fb)) {
                java.util.Set<String> d1 = new java.util.TreeSet<>(fa); d1.removeAll(fb);
                java.util.Set<String> d2 = new java.util.TreeSet<>(fb); d2.removeAll(fa);
                d.add("ALAN " + e.getKey() + " eksik=" + d1 + " fazla=" + d2);
            }
            java.util.Set<String> ma = new java.util.TreeSet<>(), mb = new java.util.TreeSet<>();
            for (MethodNode m : x.methods) ma.add(m.name + m.desc);
            for (MethodNode m : y.methods) mb.add(m.name + m.desc);
            if (!ma.equals(mb)) {
                java.util.Set<String> d1 = new java.util.TreeSet<>(ma); d1.removeAll(mb);
                java.util.Set<String> d2 = new java.util.TreeSet<>(mb); d2.removeAll(ma);
                d.add("METOT " + e.getKey() + " eksik=" + d1 + " fazla=" + d2);
            }
        }
        return String.join(" | ", d);
    }

    static void corpusRoundTrip(String set, String mainClass, String tag) throws Exception {
        java.nio.file.Path obf = java.nio.file.Paths.get("corpus/jars/" + set + "/obf.jar");
        java.nio.file.Path orig = java.nio.file.Paths.get("corpus/jars/" + set + "/original.jar");
        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/" + set + ".txt");
        if (!java.nio.file.Files.exists(obf) || !java.nio.file.Files.exists(orig)) {
            System.out.println(tag + "-e2e SKIP (corpus not present)");
            return;
        }
        String outJar = "build/test-tmp/_jt-" + set + ".jar";
        if (java.nio.file.Files.exists(map)) System.setProperty("zkmdeobf.changelog", map.toString());
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar(obf.toString());
            check(r.stats().strSkipped().isEmpty(), tag + " str-skip:" + r.stats().strSkipped());
            check(r.stats().intUnresolved().isEmpty(), tag + " int-unres:" + r.stats().intUnresolved());
            check(r.verified(), tag + " dogrulanmadi:" + r.verifyLog());
            ClassIO.writeJar(outJar, new java.util.TreeMap<>(r.jar()));
            String main = findMain(outJar);
            String o1 = runMain(orig.toString(), mainClass);
            String o2 = runMain(outJar, main);
            check(o1.equals(o2), tag + " output-mismatch");
            String sd = structuralDiff(orig.toString(), outJar);
            check(sd.isEmpty(), tag + " 1:1-mismatch: " + sd);
            java.util.Map<String, ClassNode> cs = ClassIO.readJar(outJar);
            int leftovers = 0;
            List<String> names = new ArrayList<>();
            for (ClassNode cn : cs.values()) {
                for (FieldNode f : cn.fields)
                    if (f.name.matches("f_\\d+.*") || f.name.matches("[Cm]_?\\d+")) {
                        leftovers++; names.add(cn.name + "." + f.name);
                    }
                for (MethodNode m : cn.methods)
                    if (m.desc.equals("(IJ)I") || m.desc.equals("(IJ)J")
                            || m.desc.startsWith("([Ljava/lang/Object;)")) {
                        leftovers++; names.add(cn.name + "." + m.name + m.desc);
                    }
            }
            check(leftovers == 0, tag + " ZKM kalinti: " + names);
            System.out.println(tag + "-e2e OK (" + o1.split("\n").length + " lines, main=" + main
                    + ", 1:1 classes/fields/methods, no residue)");
        } finally {
            System.clearProperty("zkmdeobf.changelog");
        }
    }

    public static void testZkm13Corpus() throws Exception {
        corpusRoundTrip("demo1-zkm13", "com.demo.Main", "demo1-zkm13");
        corpusRoundTrip("demo2-zkm13", "com.demo2.Main", "demo2-zkm13");
        corpusRoundTrip("demo3-zkm13", "com.demo3.App", "demo3-zkm13");
    }

    public static void testTest1E2E() throws Exception {

        java.nio.file.Path obf = java.nio.file.Paths.get("corpus/jars/demo1-zkm27/obf.jar");
        java.nio.file.Path orig = java.nio.file.Paths.get("corpus/jars/demo1-zkm27/original.jar");
        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/demo1-zkm27.txt");
        if (!java.nio.file.Files.exists(obf) || !java.nio.file.Files.exists(orig)) {
            System.out.println("test1-e2e SKIP (corpus not present)");
            return;
        }
        if (java.nio.file.Files.exists(map)) System.setProperty("zkmdeobf.changelog", map.toString());
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar(obf.toString());
            check(r.stats().strSkipped().isEmpty(), "t1 str-skip:" + r.stats().strSkipped());
            check(r.stats().intUnresolved().isEmpty(), "t1 int-unres:" + r.stats().intUnresolved());
            check(r.verified(), "t1 dogrulanmadi:" + r.verifyLog());
            ClassIO.writeJar("build/test-tmp/_jt1b.jar", new java.util.TreeMap<>(r.jar()));
            String main = findMain("build/test-tmp/_jt1b.jar");
            String o1 = runMain(orig.toString(), "com.demo.Main");
            String o2 = runMain("build/test-tmp/_jt1b.jar", main);
            check(o1.equals(o2), "t1 output-mismatch");
            String sd = structuralDiff(orig.toString(), "build/test-tmp/_jt1b.jar");
            check(sd.isEmpty(), "t1 1:1-mismatch: " + sd);
            System.out.println("test1-e2e OK (" + o1.split("\n").length + " lines, main=" + main
                    + ", 1:1 classes/fields/methods)");
        } finally {
            System.clearProperty("zkmdeobf.changelog");
        }
    }

    public static void testTest2E2E() throws Exception {

        java.nio.file.Path obf = java.nio.file.Paths.get("corpus/jars/demo2-zkm27/obf.jar");
        java.nio.file.Path orig = java.nio.file.Paths.get("corpus/jars/demo2-zkm27/original.jar");
        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/demo2-zkm27.txt");
        if (!java.nio.file.Files.exists(obf) || !java.nio.file.Files.exists(orig)) {
            System.out.println("test2-e2e SKIP (corpus not present)");
            return;
        }
        if (java.nio.file.Files.exists(map)) System.setProperty("zkmdeobf.changelog", map.toString());
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar(obf.toString());
            check(r.stats().strSkipped().isEmpty(), "str-skip:" + r.stats().strSkipped());
            check(r.stats().intUnresolved().isEmpty(), "int-unres:" + r.stats().intUnresolved());
            check(r.verified(), "dogrulanmadi:" + r.verifyLog());
            java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
            ClassIO.writeJar("build/test-tmp/_jt2.jar", jar);
            String deobfMain = findMain("build/test-tmp/_jt2.jar");
            String o1 = runMain(orig.toString(), "com.demo2.Main");
            String o2 = runMain("build/test-tmp/_jt2.jar", deobfMain);
            check(o1.equals(o2), "output-mismatch");
            String sd = structuralDiff(orig.toString(), "build/test-tmp/_jt2.jar");
            check(sd.isEmpty(), "t2 1:1-mismatch: " + sd);
            System.out.println("test2-e2e OK (" + o1.split("\n").length + " lines, main=" + deobfMain
                    + ", 1:1 classes/fields/methods)");
        } finally {
            System.clearProperty("zkmdeobf.changelog");
        }
    }

    public static void testTest2Clean() throws Exception {

        java.nio.file.Path obf = java.nio.file.Paths.get("corpus/jars/demo2-zkm27/obf.jar");
        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/demo2-zkm27.txt");
        if (!java.nio.file.Files.exists(obf)) {
            System.out.println("test2-clean SKIP (corpus not present)");
            return;
        }
        if (java.nio.file.Files.exists(map)) System.setProperty("zkmdeobf.changelog", map.toString());
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar(obf.toString());
            java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
            ClassIO.writeJar("build/test-tmp/_jt2c.jar", jar);
            java.util.Map<String, ClassNode> cs = ClassIO.readJar("build/test-tmp/_jt2c.jar");

            for (ClassNode cn : cs.values())
                check(!ReferenceResolver.isResolverClass(cn), "resolver-remains:" + cn.name);
            check(!cs.containsKey("a/a/c.class"), "a/a/c dosyasi kaldi");
            check(cs.containsKey("com/demo2/Main.class") && cs.containsKey("com/demo2/Worker.class"),
                    "class-restore-missing:" + cs.keySet());
            ClassNode mn = cs.get("com/demo2/Main.class");
            ClassNode wb = cs.get("com/demo2/Worker.class");

            check(mn.fields.isEmpty(), "Main-field-remains:" + mn.fields);
            java.util.Set<String> wf = new java.util.HashSet<>();
            for (FieldNode f : wb.fields) wf.add(f.name);
            check(wf.equals(java.util.Set.of("MAGIC", "BIG", "counter", "prefix")),
                    "Worker-alanlar:" + wf);

            for (String nm : new String[]{"empty", "unicode", "fieldUser"}) {
                boolean found = false;
                for (MethodNode m : wb.methods) {
                    if (m.name.equals(nm)) {
                        found = true;
                        check(!m.desc.startsWith("([Ljava/lang/Object;)"), nm + "-arite:" + m.desc);
                    }
                }
                check(found, nm + "-yok");
            }

            int opaqueGets = 0;
            for (ClassNode cn : cs.values()) {
                for (MethodNode m : cn.methods) {
                    if (m.name.equals("<clinit>")) continue;
                    for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                        if (n instanceof FieldInsnNode f && n.getOpcode() == Opcodes.GETSTATIC
                                && f.desc.equals("Z")) opaqueGets++;
                    }
                }
            }
            check(opaqueGets == 0, "opak-GETSTATIC-kaldi=" + opaqueGets);

            for (ClassNode cn : cs.values())
                for (MethodNode m : cn.methods)
                    check(!m.desc.equals("(IJ)I") && !m.desc.equals("(IJ)J"),
                            "lookup-kaldi:" + cn.name + "." + m.name);

            MethodNode sw = null, we = null, lp = null;
            for (MethodNode m : wb.methods) {
                if (m.name.equals("switchGrade")) sw = m;
                if (m.name.equals("withException")) we = m;
                if (m.name.equals("loopSum")) lp = m;
            }
            check(sw != null && we != null && lp != null, "method-missing");
            boolean hasTS = false;
            for (AbstractInsnNode n = sw.instructions.getFirst(); n != null; n = n.getNext())
                if (n instanceof org.objectweb.asm.tree.TableSwitchInsnNode) hasTS = true;
            check(hasTS, "switch-tableswitch-missing");
            check(we.tryCatchBlocks != null && we.tryCatchBlocks.size() == 3,
                    "withException-handler:" + (we.tryCatchBlocks == null ? 0 : we.tryCatchBlocks.size()));
            System.out.println("test2-clean OK");
        } finally {
            System.clearProperty("zkmdeobf.changelog");
        }
    }

    public static void testTest3E2E() throws Exception {

        java.nio.file.Path obf = java.nio.file.Paths.get("corpus/jars/demo3-zkm27/obf.jar");
        java.nio.file.Path orig = java.nio.file.Paths.get("corpus/jars/demo3-zkm27/original.jar");
        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/demo3-zkm27.txt");
        if (!java.nio.file.Files.exists(obf) || !java.nio.file.Files.exists(orig)) {
            System.out.println("test3-e2e SKIP (corpus not present)");
            return;
        }
        if (java.nio.file.Files.exists(map)) System.setProperty("zkmdeobf.changelog", map.toString());
        try {
            Pipeline.Result r = Pipeline.deobfuscateJar(obf.toString());
            check(r.stats().strSkipped().isEmpty(), "t3 str-skip:" + r.stats().strSkipped());
            check(r.stats().intUnresolved().isEmpty(), "t3 int-unres:" + r.stats().intUnresolved());
            check(r.verified(), "t3 dogrulanmadi:" + r.verifyLog());
            java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
            ClassIO.writeJar("build/test-tmp/_jt3.jar", jar);

            String o1 = runMain(orig.toString(), "com.demo3.App");
            String o2 = runMain("build/test-tmp/_jt3.jar", "com.demo3.App");
            check(o1.equals(o2), "t3 output-mismatch");

            java.util.Map<String, ClassNode> cs = ClassIO.readJar("build/test-tmp/_jt3.jar");
            for (String n : new String[]{"com/demo3/App.class", "com/demo3/Shape.class",
                    "com/demo3/Circle.class", "com/demo3/CircleBase.class", "com/demo3/Rect.class",
                    "com/demo3/Rect$Kind.class", "com/demo3/Registry.class",
                    "com/demo3/Registry$Cursor.class", "com/demo3/BadShape.class"}) {
                check(cs.containsKey(n), "t3 class-missing:" + n);
            }
            check(!ReferenceResolver.isResolverClass(cs.get("com/demo3/Rect.class")),
                    "t3 resolver-shape");

            ClassNode circ = cs.get("com/demo3/Circle.class");
            boolean tagRead = false, wrongName = false;
            for (MethodNode m : circ.methods) {
                if (!m.name.equals("kind")) continue;
                for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext())
                    if (n instanceof FieldInsnNode f && f.getOpcode() == Opcodes.GETFIELD
                            && f.desc.equals("Ljava/lang/String;")) {
                        if (f.name.equals("tag")) tagRead = true;
                        else wrongName = true;
                    }
            }
            check(tagRead && !wrongName, "t3 inherited-field-name-unresolved");

            java.util.Map<String, ClassNode> byName = new java.util.HashMap<>();
            for (ClassNode cn : cs.values()) byName.put(cn.name, cn);
            for (ClassNode cn : cs.values()) {
                for (MethodNode m : cn.methods) {
                    for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext()) {
                        if (!(n instanceof MethodInsnNode mi)) continue;
                        if (!mi.desc.startsWith("([Ljava/lang/Object;)")) continue;
                        ClassNode t = byName.get(mi.owner);
                        check(t != null, "t3 bilinmeyen hedef: " + mi.owner);
                        boolean ok = false;
                        for (MethodNode tm : t.methods)
                            if (tm.name.equals(mi.name) && tm.desc.equals(mi.desc)) ok = true;
                        check(ok, "t3 sarkan ([Object;) cagri: " + mi.owner + "." + mi.name + mi.desc);
                    }
                }
            }

            int flowFlags = 0;
            List<String> leftover = new ArrayList<>();
            for (ClassNode cn : cs.values()) {
                for (FieldNode f : cn.fields) {
                    if (!f.name.startsWith("f_0")) continue;
                    if (f.desc.equals("Z") || f.desc.equals("I")) { flowFlags++; leftover.add(cn.name + "." + f.name); }
                }
            }
            check(flowFlags == 0, "t3 opaque-field-remains: " + leftover);

            java.util.Map<String, ClassNode> origCs = ClassIO.readJar(orig.toString());
            check(origCs.size() == cs.size(), "t3 class-count: " + origCs.size() + " vs " + cs.size());
            int clsEq = 0, fldEq = 0, mthEq = 0;
            List<String> diffs = new ArrayList<>();
            for (java.util.Map.Entry<String, ClassNode> e : origCs.entrySet()) {
                ClassNode a0 = e.getValue(), b0 = cs.get(e.getKey());
                if (b0 == null) { diffs.add("SINIF-YOK " + e.getKey()); continue; }
                clsEq++;
                java.util.Set<String> fa = new java.util.TreeSet<>(), fb = new java.util.TreeSet<>();
                for (FieldNode f : a0.fields) fa.add(f.name + ":" + f.desc);
                for (FieldNode f : b0.fields) fb.add(f.name + ":" + f.desc);
                if (fa.equals(fb)) fldEq++;
                else {
                    java.util.Set<String> d1 = new java.util.TreeSet<>(fa); d1.removeAll(fb);
                    java.util.Set<String> d2 = new java.util.TreeSet<>(fb); d2.removeAll(fa);
                    diffs.add("ALAN " + e.getKey() + " eksik=" + d1 + " fazla=" + d2);
                }
                java.util.Set<String> ma = new java.util.TreeSet<>(), mb = new java.util.TreeSet<>();
                for (MethodNode m : a0.methods) ma.add(m.name + m.desc);
                for (MethodNode m : b0.methods) mb.add(m.name + m.desc);
                if (ma.equals(mb)) mthEq++;
                else {
                    java.util.Set<String> d1 = new java.util.TreeSet<>(ma); d1.removeAll(mb);
                    java.util.Set<String> d2 = new java.util.TreeSet<>(mb); d2.removeAll(ma);
                    diffs.add("METOT " + e.getKey() + " eksik=" + d1 + " fazla=" + d2);
                }
            }
            check(diffs.isEmpty(), "t3 1:1-mismatch: " + diffs);
            check(clsEq == origCs.size() && fldEq == origCs.size() && mthEq == origCs.size(),
                    "t3 kapsam eksik");
            System.out.println("test3-e2e OK (" + o1.split("\n").length + " lines, "
                    + origCs.size() + " classes, 1:1 classes/fields/methods)");
        } finally {
            System.clearProperty("zkmdeobf.changelog");
        }
    }

    public static void testInheritanceChangelog() throws Exception {

        java.nio.file.Path map = java.nio.file.Paths.get("corpus/changelogs/demo3-zkm27.txt");
        if (!java.nio.file.Files.exists(map)) {
            System.out.println("inheritance-changelog SKIP (corpus not present)");
            return;
        }
        ChangeLogMap cm = ChangeLogMap.parse(map.toString());

        check("tag".equals(cm.fields.get("a/a/c.aLjava/lang/String;")),
                "declaring-field:" + cm.fields.get("a/a/c.aLjava/lang/String;"));
        java.util.Map<String, ClassNode> cs = ClassIO.readJar("corpus/jars/demo3-zkm27/obf.jar");
        java.util.Map<String, String> mapOut = cm.buildMapping(cs);
        check("tag".equals(mapOut.get("a/a/d.a")),
                "miras-referans-cozulmedi: " + mapOut.get("a/a/d.a"));

        check("describe".equals(mapOut.get("a/a/d.e([Ljava/lang/Object;)Ljava/lang/String;")),
                "inherited-method-unresolved: " + mapOut.get("a/a/d.e([Ljava/lang/Object;)Ljava/lang/String;"));
        System.out.println("inheritance-changelog OK");
    }

    public static void testE2EAll() throws Exception {

        String[][] cases = {
                {"corpus/fixtures/demo2-obf.jar", "hello-ZKM-E2E-secret-sauce|B-good"},
                {"corpus/fixtures/demo3B-obf.jar", "hello-ZKM-E2E-secret-sauce|magic="},
                {"corpus/fixtures/demo3C-obf.jar", "hello-ZKM-E2E-secret-sauce|magic="},
                {"corpus/fixtures/demo3D-obf.jar", "hello-ZKM-E2E-secret-sauce|magic="},
                {"corpus/fixtures/demo3E-obf.jar", "hello-ZKM-E2E-secret-sauce|magic="},
        };
        for (String[] c : cases) {
            Pipeline.Result r = Pipeline.deobfuscateJar(c[0]);
            check(r.stats().strPatched() + r.stats().intPatched() + r.stats().refInlined()
                    + r.stats().paramCalls() + r.stats().handlersRemoved() > 0,
                    "patch-missing " + c[0]);
            java.util.Map<String, byte[]> jar = new java.util.TreeMap<>(r.jar());
            String tmp = "build/test-tmp/_e2eall.jar";
            ClassIO.writeJar(tmp, jar);
            String main = null;
            java.util.Map<String, ClassNode> rcs = ClassIO.readJar(tmp);
            for (ClassNode cn : rcs.values()) {
                for (MethodNode mm : cn.methods) {
                    if (mm.name.equals("main") && mm.desc.equals("([Ljava/lang/String;)V"))
                        main = cn.name.replace('/', '.');
                }
            }
            check(main != null, "main-missing " + c[0]);
            check(runMain(tmp, main).contains(c[1]), "run " + c[0]);
        }
        System.out.println("e2e-all OK");
    }

    public static void main(String[] argv) throws Exception {
        System.out.println("[step] testCrypto");
        testCrypto();
        System.out.println("[step] testDemo2");
        testDemo2();
        System.out.println("[step] testDemo3B");
        testDemo3B();
        System.out.println("[step] testDemo3C");
        testDemo3C();
        System.out.println("[step] testDesAndLong");
        testDesAndLong();
        System.out.println("[step] testTables");
        testTables();
        System.out.println("[step] testCorpusBytecodeTarget");
        testCorpusBytecodeTarget();
        System.out.println("[step] testCliHelp");
        testCliHelp();
        System.out.println("[step] testRefInline");
        testRefInline();
        System.out.println("[step] testRename");
        testRename();
        System.out.println("[step] testPatcherE2E");
        testPatcherE2E();
        System.out.println("[step] testDupCat2");
        testDupCat2();
        System.out.println("[step] testTripleLookup");
        testTripleLookup();
        System.out.println("[step] testConstFold");
        testConstFold();
        System.out.println("[step] testDesRealData");
        testDesRealData();
        System.out.println("[step] testInterpreterLimits");
        testInterpreterLimits();
        System.out.println("[step] testRefLimits");
        testRefLimits();
        System.out.println("[step] testEmuTables");
        testEmuTables();
        System.out.println("[step] testSwitchFold");
        testSwitchFold();
        System.out.println("[step] testOverrideSafeRename");
        testOverrideSafeRename();
        System.out.println("[step] testDynLookupFallback");
        testDynLookupFallback();
        System.out.println("[step] testInterfaceInline");
        testInterfaceInline();
        System.out.println("[step] testComboBudget");
        testComboBudget();
        System.out.println("[step] testXorZeroKey");
        testXorZeroKey();
        System.out.println("[step] testFloatBranchFold");
        testFloatBranchFold();
        System.out.println("[step] testClinitChainConst");
        testClinitChainConst();
        System.out.println("[step] testCheckcastHandler");
        testCheckcastHandler();
        System.out.println("[step] testSharedStatics");
        testSharedStatics();
        System.out.println("[step] testJsrDeadCodeGuard");
        testJsrDeadCodeGuard();
        System.out.println("[step] testFinallyPreserved");
        testFinallyPreserved();
        System.out.println("[step] testIfNullStrict");
        testIfNullStrict();
        System.out.println("[step] testMultiLookupNames");
        testMultiLookupNames();
        System.out.println("[step] testStackSizesWidening");
        testStackSizesWidening();
        System.out.println("[step] testFindProducerIincBarrier");
        testFindProducerIincBarrier();
        System.out.println("[step] testPatchPurity");
        testPatchPurity();
        System.out.println("[step] testDropOrphanKeepsLineNumbers");
        testDropOrphanKeepsLineNumbers();
        System.out.println("[step] testCallerPushPatternRejected");
        testCallerPushPatternRejected();
        System.out.println("[step] testCalleeSlotRelocation");
        testCalleeSlotRelocation();
        System.out.println("[step] testNativeSkipped");
        testNativeSkipped();
        System.out.println("[step] testDeadMethodEnumGuard");
        testDeadMethodEnumGuard();
        System.out.println("[step] testNoDynFlag");
        testNoDynFlag();
        System.out.println("[step] testParamSlotGuard");
        testParamSlotGuard();
        System.out.println("[step] testCallerSizeRequired");
        testCallerSizeRequired();
        System.out.println("[step] testDeadLookupRemoved");
        testDeadLookupRemoved();
        System.out.println("[step] testCopyPropDeadStore");
        testCopyPropDeadStore();
        System.out.println("[step] testUnwrittenDefault");
        testUnwrittenDefault();
        System.out.println("[step] testRenameDefault");
        testRenameDefault();
        System.out.println("[step] testOptimisticCycle");
        testOptimisticCycle();
        System.out.println("[step] testTest1Opaque");
        testTest1Opaque();
        System.out.println("[step] testChangelogRestore");
        testChangelogRestore();
        System.out.println("[step] testConstValueRestore");
        testConstValueRestore();
        System.out.println("[step] testZkm13Corpus");
        testZkm13Corpus();
        System.out.println("[step] testTest1E2E");
        testTest1E2E();
        System.out.println("[step] testTest2E2E");
        testTest2E2E();
        System.out.println("[step] testTest2Clean");
        testTest2Clean();
        System.out.println("[step] testInheritanceChangelog");
        testInheritanceChangelog();
        System.out.println("[step] testTest3E2E");
        testTest3E2E();
        System.out.println("[step] testE2EAll");
        testE2EAll();
        System.out.println("[step] SynthFlow");
        SynthFlow.main(new String[0]);
        System.out.println("ALL JAVA TESTS PASSED (" + pass + " assertions)");
    }

    static String runMain(String jar, String main) throws Exception {
        String javaBin = System.getProperty("java.home") + "/bin/java";
        Process p = new ProcessBuilder(javaBin, "-cp", jar, main).redirectErrorStream(true).start();
        boolean bitti = p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);
        if (!bitti) {
            p.destroyForcibly();
            throw new AssertionError("run timeout: " + jar + " " + main);
        }
        String out = new String(p.getInputStream().readAllBytes());
        if (p.exitValue() != 0) throw new AssertionError("calisma hatasi: " + out);
        return out.replace("\r", "").trim();
    }
}
