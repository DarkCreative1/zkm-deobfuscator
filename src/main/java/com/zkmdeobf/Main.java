package com.zkmdeobf;

import java.util.Map;

public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        String input = null, output = null, runMain = null;
        for (int i = 0; i < args.length; i++) {
            if ((args[i].equals("-o") || args[i].equals("--output")) && i + 1 < args.length) output = args[++i];
            else if (args[i].equals("--rename")) System.setProperty("zkmdeobf.rename", "true");
            else if (args[i].equals("--no-rename")) System.setProperty("zkmdeobf.rename", "false");
            else if (args[i].equals("--map") && i + 1 < args.length)
                System.setProperty("zkmdeobf.changelog", args[++i]);
            else if (args[i].equals("--run") && i + 1 < args.length) runMain = args[++i];
            else if (!args[i].startsWith("-")) input = args[i];
        }
        if (input == null) {
            System.out.println("usage: Main <input.jar> [-o output.jar] [--rename|--no-rename] [--map changelog.txt] [--run ana.Sinif]");
            return;
        }
        Pipeline.Result r = Pipeline.deobfuscateJar(input);
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
            try {
                Map<String, org.objectweb.asm.tree.ClassNode> check = ClassIO.readJar(output);
                System.out.println("classes: " + check.size() + " read");
            } catch (Exception e) {
                System.out.println("VERIFICATION FAILED: " + e);
            }
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
                }
            } catch (Exception e) {
                System.out.println("run FAILED: " + e);
            }
        }
    }
}
