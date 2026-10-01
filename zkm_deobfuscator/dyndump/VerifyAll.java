import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class VerifyAll {
    static class L extends ClassLoader {
        private final JarFile jar;
        L(JarFile j) { super(null); jar = j; }
        Class<?> def(String name, byte[] b) { return defineClass(name, b, 0, b.length); }
    }

    public static void main(String[] args) throws Exception {
        JarFile jar = new JarFile(args[0]);
        L loader = new L(jar);
        int ok = 0, fail = 0;
        Enumeration<JarEntry> en = jar.entries();
        while (en.hasMoreElements()) {
            JarEntry e = en.nextElement();
            String n = e.getName();
            if (!n.endsWith(".class") || n.contains("module-info")) continue;
            String cls = n.substring(0, n.length() - 6).replace('/', '.');
            try (InputStream in = jar.getInputStream(e)) {
                byte[] b = in.readAllBytes();
                Class<?> c = loader.def(cls, b);
                c.getDeclaredMethods();
                c.getDeclaredFields();
                ok++;
            } catch (Throwable t) {
                fail++;
                System.err.println("FAIL " + cls + " : " + t);
            }
        }
        System.out.println("verified=" + ok + " failed=" + fail);
        if (fail > 0) System.exit(1);
    }
}
