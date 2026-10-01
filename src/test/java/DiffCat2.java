import com.zkmdeobf.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;

public class DiffCat2 {
    static int failures = 0;
    static void check(String name, Object expect, Object got) {
        boolean ok = Objects.equals(expect, got);
        System.out.println((ok ? "OK  " : "FAIL") + " " + name + " expect=" + expect + " got=" + got);
        if (!ok) failures++;
    }
    static Object[] runBoth(String name, java.util.function.Consumer<MethodVisitor> gen, String desc) {
        ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        w.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "diff/" + name, null,
                "java/lang/Object", null);
        MethodVisitor mv = w.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", desc, null, null);
        mv.visitCode();
        gen.accept(mv);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        Object jr, er;
        try {
            Class<?> c = new ClassLoader(null) {
                Class<?> def() { return defineClass("diff." + name, b, 0, b.length); }
            }.def();
            jr = c.getMethod("f").invoke(null);
        } catch (Exception e) {
            Throwable t = e.getCause() == null ? e : e.getCause();
            jr = "JVM-EX:" + t.getClass().getSimpleName();
        }
        try {
            ClassNode cn = new ClassNode();
            new org.objectweb.asm.ClassReader(b).accept(cn, 0);
            MethodNode m = ClassIO.findMethod(cn, "f", desc);
            Map<String, ClassNode> cs = Map.of("diff/" + name + ".class", cn);
            er = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
            if (er instanceof Long) er = "J" + er;
            if (er instanceof Integer) er = "I" + er;
        } catch (Throwable e) {
            er = "EMU-EX:" + e.getClass().getSimpleName() + ":" + e.getMessage();
        }
        if (jr instanceof Long) jr = "J" + jr;
        if (jr instanceof Integer) jr = "I" + jr;
        return new Object[]{jr, er};
    }
    public static void main(String[] a) {

        Object[] r1 = runBoth("C1", mv -> {
            mv.visitIntInsn(Opcodes.BIPUSH, 7);
            mv.visitLdcInsn(100L);
            mv.visitInsn(Opcodes.ICONST_3);
            mv.visitInsn(Opcodes.DUP_X2);
            mv.visitInsn(Opcodes.POP);

            mv.visitVarInsn(Opcodes.LSTORE, 1);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            mv.visitVarInsn(Opcodes.ISTORE, 3);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitVarInsn(Opcodes.LLOAD, 1);
            mv.visitInsn(Opcodes.L2I);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 3);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
        }, "()I");
        check("dup_x2_cat2", r1[0], r1[1]);

        Object[] r2 = runBoth("C2", mv -> {
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitInsn(Opcodes.ICONST_2);
            mv.visitInsn(Opcodes.ICONST_3);
            mv.visitInsn(Opcodes.DUP_X1);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            mv.visitVarInsn(Opcodes.ISTORE, 1);
            mv.visitVarInsn(Opcodes.ISTORE, 2);
            mv.visitVarInsn(Opcodes.ISTORE, 3);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitIntInsn(Opcodes.SIPUSH, 1000);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitIntInsn(Opcodes.BIPUSH, 100);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 2);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 3);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
        }, "()I");

        check("dup_x1_order", r2[0], r2[1]);
        System.out.println("  (dup_x1: JVM value on top; emulator must agree)");

        Object[] r3 = runBoth("C3", mv -> {
            mv.visitIntInsn(Opcodes.BIPUSH, 9);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitIntInsn(Opcodes.BIPUSH, 11);
            mv.visitInsn(Opcodes.DUP2_X1);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            mv.visitVarInsn(Opcodes.ISTORE, 1);
            mv.visitVarInsn(Opcodes.ISTORE, 2);
            mv.visitVarInsn(Opcodes.ISTORE, 3);
            mv.visitVarInsn(Opcodes.ISTORE, 4);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitIntInsn(Opcodes.SIPUSH, 10000);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitIntInsn(Opcodes.SIPUSH, 1000);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 2);
            mv.visitIntInsn(Opcodes.BIPUSH, 100);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 3);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 4);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
        }, "()I");
        check("dup2_x1_5", r3[0], r3[1]);

        Object[] r4 = runBoth("C4", mv -> {
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitInsn(Opcodes.ICONST_2);
            mv.visitInsn(Opcodes.ICONST_3);
            mv.visitIntInsn(Opcodes.BIPUSH, 4);
            mv.visitInsn(Opcodes.DUP2_X2);
            for (int i = 0; i < 6; i++) mv.visitVarInsn(Opcodes.ISTORE, i);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitIntInsn(Opcodes.SIPUSH, 100000);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitIntInsn(Opcodes.SIPUSH, 10000);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 2);
            mv.visitIntInsn(Opcodes.SIPUSH, 1000);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 3);
            mv.visitIntInsn(Opcodes.BIPUSH, 100);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 4);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 5);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
        }, "()I");
        check("dup2_x2_6", r4[0], r4[1]);

        if (failures > 0) throw new AssertionError(failures + " fark");
        System.out.println("DIFFCAT2 OK");
    }
}
