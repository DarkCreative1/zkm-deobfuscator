import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

public class DynDump {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: DynDump <class> [I:arg:key]* [J:arg:key]*");
            return;
        }
        Class<?> c = null;
        try {
            c = Class.forName(args[0]);
        } catch (ClassNotFoundException e) {

        }
        List<Method> intL = new ArrayList<>();
        List<Method> lngL = new ArrayList<>();
        if (c != null) {
            for (Method m : c.getDeclaredMethods()) {
                if (!Modifier.isStatic(m.getModifiers()) || m.getParameterCount() != 2) continue;
                Class<?>[] p = m.getParameterTypes();
                if (p[0] == int.class && p[1] == long.class && m.getReturnType() == int.class) intL.add(m);
                if (p[0] == int.class && p[1] == long.class && m.getReturnType() == long.class) lngL.add(m);
            }
        }
        for (Method m : intL) m.setAccessible(true);
        for (Method m : lngL) m.setAccessible(true);
        for (int i = 1; i < args.length; i++) {
            String[] t = args[i].split(":", 3);
            if (t[0].equals("T") && t.length == 3) {
                try {
                    Class<?> cc = Class.forName(t[1]);
                    java.lang.reflect.Field f = null;
                    for (java.lang.reflect.Field ff : cc.getDeclaredFields()) {
                        if (ff.getName().equals(t[2])
                                && (ff.getType() == String[].class || ff.getType() == String.class)) f = ff;
                    }
                    if (f == null) { System.out.println("FAIL " + i + " no-field"); continue; }
                    f.setAccessible(true);
                    if (f.getType() == String[].class) {
                        String[] arr = (String[]) f.get(null);
                        if (arr == null) { System.out.println("FAIL " + i + " null-table"); continue; }
                        StringBuilder sb = new StringBuilder();
                        sb.append("TOK ").append(i).append(" ").append(arr.length);
                        for (String s : arr) {
                            if (s == null) { sb.append(" |NULL"); continue; }
                            sb.append(" |").append(s.length()).append(":");
                            for (int j = 0; j < s.length(); j++) sb.append(s.charAt(j) & 0xFFFF).append(",");
                        }
                        System.out.println(sb);
                    } else if (f.getType() == String.class) {
                        String s = (String) f.get(null);
                        if (s == null) { System.out.println("FAIL " + i + " null-string"); continue; }
                        StringBuilder sb = new StringBuilder();
                        sb.append("TX ").append(i).append(" ").append(s.length()).append(":");
                        for (int j = 0; j < s.length(); j++) sb.append(s.charAt(j) & 0xFFFF).append(",");
                        System.out.println(sb);
                    } else {
                        System.out.println("FAIL " + i + " bad-type");
                    }
                } catch (Exception e) {
                    System.out.println("FAIL " + i + " " + e);
                }
                continue;
            }
            try {
                int arg = Integer.parseInt(t[1]);
                long key = Long.parseLong(t[2]);
                if (t[0].equals("I") && !intL.isEmpty()) {
                    Object last = null;
                    for (Method m : intL) last = m.invoke(null, arg, key);
                    System.out.println("OK " + i + " " + last);
                } else if (t[0].equals("J") && !lngL.isEmpty()) {
                    Object last = null;
                    for (Method m : lngL) last = m.invoke(null, arg, key);
                    System.out.println("OK " + i + " " + last);
                } else {
                    System.out.println("FAIL " + i + " no-lookup");
                }
            } catch (Exception e) {
                System.out.println("FAIL " + i + " " + e);
            }
        }
    }
}
