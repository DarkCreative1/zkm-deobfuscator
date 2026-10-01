package com.zkmdeobf;

import java.util.Map;

public final class Main {
    private Main() {}

    private static final String VERSION = version();

    private static String version() {
        String v = Main.class.getPackage().getImplementationVersion();
        if (v != null && !v.isBlank()) return v;
        v = Main.class.getPackage().getSpecificationVersion();
        if (v != null && !v.isBlank()) return v;
        return "dev";
    }

    private static int badOption(String opt, String why) {
        System.out.println("error: " + opt + " " + why);
        System.out.println("Run with --help for usage.");
        return 2;
    }

    private static void usage() {
        String nl = System.lineSeparator();
        System.out.print(
            "zkm-deobfuscator " + VERSION + " - static deobfuscator for Zelix KlassMaster jars" + nl
            + nl
            + "USAGE" + nl
            + "  java -jar zkm-deobfuscator.jar <input.jar> [options]" + nl
            + nl
            + "OPTIONS" + nl
            + "  -o, --output <file>   Write the deobfuscated jar to this path." + nl
            + "                        Without it the jar is analysed but not written." + nl
            + "      --map <file>      ZKM changelog used to restore the exact original" + nl
            + "                        member names. Without it names are heuristics." + nl
            + "      --rename          Enable heuristic renaming. This is the default." + nl
            + "      --no-rename       Keep the obfuscated member names as they are." + nl
            + "      --run <main>      Run a class from the produced jar after writing" + nl
            + "                        it, and report whether it exited cleanly." + nl
            + "                        Requires --output." + nl
            + "  -h, --help            Show this help and exit." + nl
            + "  -V, --version         Show the version and exit." + nl
            + nl
            + "EXAMPLES" + nl
            + "  Deobfuscate and write the result:" + nl
            + "    java -jar zkm-deobfuscator.jar input.jar -o output.jar" + nl
            + nl
            + "  Restore exact original names using the ZKM changelog:" + nl
            + "    java -jar zkm-deobfuscator.jar input.jar -o output.jar \\" + nl
            + "        --map changelog.txt" + nl
            + nl
            + "  Deobfuscate, then run the entry point to confirm it works:" + nl
            + "    java -jar zkm-deobfuscator.jar input.jar -o output.jar \\" + nl
            + "        --map changelog.txt --run com.example.Main" + nl
            + nl
            + "REPORTING" + nl
            + "  After each run the tool prints what it changed. Every counter counts" + nl
            + "  sites that were repaired. Nothing is guessed:" + nl
            + nl
            + "    str_patched      encrypted string literals restored" + nl
            + "    str_skipped      sites left untouched because the pattern was not" + nl
            + "                     recognised. Non-zero means the jar is not fully" + nl
            + "                     clean." + nl
            + "    int_patched      recovered integer constants" + nl
            + "    int_unresolved   integer sites that stayed opaque" + nl
            + "    handlers_removed fake exception handlers and their try blocks" + nl
            + "    flow_folded      opaque predicates and constant branches folded" + nl
            + "    dead_removed     dead stores and unreachable code" + nl
            + "    ref_inlined      ZKM reference indirection call sites resolved" + nl
            + "    param_calls      obfuscated call arguments unpacked at the caller" + nl
            + "    param_callees    obfuscated parameters unpacked in the callee" + nl
            + "    renamed          members renamed" + nl
            + nl
            + "  A verify line follows. OK means every class in the output parses and its" + nl
            + "  stack frames recompute cleanly." + nl
            + nl
            + "EXIT STATUS" + nl
            + "  0  the run completed. Read str_skipped and int_unresolved to judge how" + nl
            + "     much was left unresolved" + nl
            + "  2  bad command line" + nl
            + "  1  the run failed with an exception" + nl
            + nl
            + "REQUIREMENTS" + nl
            + "  Java 17 or newer. ASM is bundled in this jar." + nl
            + nl
            + "ZKM only targets Zelix KlassMaster protected jars. Other obfuscators are" + nl
            + "out of scope. Not affiliated with Zelix KlassMaster." + nl
        );
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        String input = null, output = null, runMain = null;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            boolean hasValue = i + 1 < args.length;
            if (a.equals("-h") || a.equals("--help")) {
                usage();
                return;
            }
            if (a.equals("-V") || a.equals("--version")) {
                System.out.println("zkm-deobfuscator " + VERSION);
                return;
            }
            if ((a.equals("-o") || a.equals("--output"))) {
                if (!hasValue) { System.exit(badOption(a, "needs a file path")); return; }
                output = args[++i];
            } else if (a.equals("--rename")) {
                System.setProperty("zkmdeobf.rename", "true");
            } else if (a.equals("--no-rename")) {
                System.setProperty("zkmdeobf.rename", "false");
            } else if (a.equals("--map")) {
                if (!hasValue) { System.exit(badOption(a, "needs a file path")); return; }
                System.setProperty("zkmdeobf.changelog", args[++i]);
            } else if (a.equals("--run")) {
                if (!hasValue) { System.exit(badOption(a, "needs a main class name")); return; }
                runMain = args[++i];
            } else if (a.startsWith("-")) {
                System.exit(badOption(a, "is not a known option"));
                return;
            } else if (input == null) {
                input = a;
            } else {
                System.exit(badOption(a, "is an unexpected extra argument"));
                return;
            }
        }
        if (input == null) {
            usage();
            return;
        }
        if (runMain != null && output == null) {
            System.out.println("error: --run needs --output, there is no jar to run from");
            System.exit(2);
            return;
        }
        Pipeline.Result r;
        try {
            r = Pipeline.deobfuscateJar(input);
        } catch (Exception e) {
            System.out.println("FAILED: " + e);
            System.exit(1);
            return;
        }
        Pipeline.Stats s = r.stats();
        System.out.println("class: " + s.classes());
        System.out.println("  str_patched=" + s.strPatched() + " int_patched=" + s.intPatched()
                + " handlers_removed=" + s.handlersRemoved() + " flow_folded=" + s.flowFolded()
                + " dead_removed=" + s.deadRemoved() + " ref_inlined=" + s.refInlined()
                + " param_calls=" + s.paramCalls() + " param_callees=" + s.paramCallees()
                + " renamed=" + s.renamed());
        if (!s.strSkipped().isEmpty()) System.out.println("  str_skipped=" + s.strSkipped().size());
        if (!s.intUnresolved().isEmpty()) System.out.println("  int_unresolved=" + s.intUnresolved().size());
        if (output != null) {
            Map<String, byte[]> jar = r.jar();
            java.util.Map<String, byte[]> sorted = new java.util.TreeMap<>(jar);
            ClassIO.writeJar(output, sorted);
            System.out.println("output: " + output);

            System.out.println("verify: " + (r.verified() ? "OK" : "FAIL") + " " + r.verifyLog());
            boolean readable = true;
            try {
                Map<String, org.objectweb.asm.tree.ClassNode> check = ClassIO.readJar(output);
                System.out.println("classes: " + check.size() + " read");
            } catch (Exception e) {
                System.out.println("VERIFICATION FAILED: " + e);
                readable = false;
            }
            if (!r.verified() || !readable) System.exit(1);
        } else {
            System.out.println("verify: " + (r.verified() ? "OK" : "FAIL") + " " + r.verifyLog());
        }
        if (runMain != null && output != null) {
            try {
                String javaBin = System.getProperty("java.home") + "/bin/java";
                Process p = new ProcessBuilder(javaBin, "-cp", output, runMain)
                        .redirectErrorStream(true).start();
                boolean bitti = p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);
                if (!bitti) {
                    p.destroyForcibly();
                    System.out.println("run FAILED: timeout (120s)");
                } else {
                    String out = new String(p.getInputStream().readAllBytes());
                    boolean ok = p.exitValue() == 0;
                    String head = out.replace("\r", "").strip();
                    if (head.length() > 300) head = head.substring(0, 300) + "...";
                    System.out.println("run: " + (ok ? "OK" : "FAIL") + " " + head);
                    if (!ok) System.out.println(out);
                    if (!ok) System.exit(1);
                }
            } catch (Exception e) {
                System.out.println("run FAILED: " + e);
                System.exit(1);
            }
        }
    }
}
