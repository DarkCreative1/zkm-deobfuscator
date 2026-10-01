import java.lang.reflect.Method;

public class ProbeRef {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName("a.a.c");
        Method d = null;
        for (Method m : c.getDeclaredMethods()) {
            if (m.getParameterCount() == 1 && m.getParameterTypes()[0] == long.class
                    && m.getReturnType() == java.lang.reflect.Method.class
                    && java.lang.reflect.Modifier.isStatic(m.getModifiers())) d = m;
        }
        d.setAccessible(true);
        long[] keys = {475970309145254L, 295197519278103L, 381053198843420L, 498242390595009L};
        for (long k : keys) {
            try {
                java.lang.reflect.Method m = (java.lang.reflect.Method) d.invoke(null, k);
                System.out.println(k + " -> " + m.getDeclaringClass().getName() + "."
                    + m.getName() + org.objectweb.asm.Type.getMethodDescriptor(m));
            } catch (Exception e) {
                System.out.println(k + " FAIL " + e.getCause());
            }
        }
    }
}
