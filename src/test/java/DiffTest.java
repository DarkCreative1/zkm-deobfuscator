import com.zkmdeobf.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;

public class DiffTest {
    static int failures = 0;

    static void check(String name, Object expect, Object got) {
        boolean ok = Objects.equals(expect, got);
        System.out.println((ok ? "OK  " : "FAIL") + " " + name + " expect=" + expect + " got=" + got);
        if (!ok) failures++;
    }

    static int runJvm(String name, java.util.function.Consumer<MethodVisitor> gen) throws Exception {
        ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        w.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "diff/" + name, null,
                "java/lang/Object", null);
        MethodVisitor mv = w.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "()I", null, null);
        mv.visitCode();
        gen.accept(mv);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        byte[] b = w.toByteArray();
        Class<?> c = new ClassLoader(null) {
            Class<?> def() { return defineClass("diff." + name, b, 0, b.length); }
        }.def();
        return (Integer) c.getMethod("f").invoke(null);
    }

    static int runEmu(String name, java.util.function.Consumer<MethodVisitor> gen) {
        ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        w.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "diff/" + name, null,
                "java/lang/Object", null);
        MethodVisitor mv = w.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "f", "()I", null, null);
        mv.visitCode();
        gen.accept(mv);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        w.visitEnd();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(w.toByteArray()).accept(cn, 0);
        MethodNode m = ClassIO.findMethod(cn, "f", "()I");
        Map<String, ClassNode> cs = Map.of("diff/" + name + ".class", cn);
        Object r = MiniInterpreter.run(new MiniInterpreter.Ctx(cs, null, 0), cn, m, new Object[0]);
        return (Integer) r;
    }

    public static void main(String[] a) throws Exception {

        java.util.function.Consumer<MethodVisitor> dupx1 = mv -> {
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitInsn(Opcodes.ICONST_2);
            mv.visitInsn(Opcodes.ICONST_3);
            mv.visitInsn(Opcodes.DUP_X1);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            mv.visitVarInsn(Opcodes.ISTORE, 1);
            mv.visitVarInsn(Opcodes.ISTORE, 2);
            mv.visitVarInsn(Opcodes.ISTORE, 3);

            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitIntInsn(Opcodes.BIPUSH, 100);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 2);
            mv.visitInsn(Opcodes.IADD);
            mv.visitVarInsn(Opcodes.ILOAD, 3);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
        };
        check("dup_x1", runJvm("T1", dupx1), runEmu("T1", dupx1));

        java.util.function.Consumer<MethodVisitor> swap = mv -> {
            mv.visitIntInsn(Opcodes.BIPUSH, 4);
            mv.visitIntInsn(Opcodes.BIPUSH, 5);
            mv.visitInsn(Opcodes.SWAP);
            mv.visitVarInsn(Opcodes.ISTORE, 0);
            mv.visitVarInsn(Opcodes.ISTORE, 1);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitInsn(Opcodes.IMUL);
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
        };
        check("swap", runJvm("T2", swap), runEmu("T2", swap));

        java.util.function.Consumer<MethodVisitor> dupx2 = mv -> {
            mv.visitIntInsn(Opcodes.BIPUSH, 6);
            mv.visitIntInsn(Opcodes.BIPUSH, 7);
            mv.visitIntInsn(Opcodes.BIPUSH, 8);
            mv.visitInsn(Opcodes.DUP_X2);
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
        };
        check("dup_x2", runJvm("T3", dupx2), runEmu("T3", dupx2));

        java.util.function.Consumer<MethodVisitor> dup2x1 = mv -> {
            mv.visitIntInsn(Opcodes.BIPUSH, 9);
            mv.visitIntInsn(Opcodes.BIPUSH, 10);
            mv.visitIntInsn(Opcodes.BIPUSH, 11);
            mv.visitInsn(Opcodes.DUP2_X1);
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
        };
        check("dup2_x1", runJvm("T4", dup2x1), runEmu("T4", dup2x1));

        if (failures > 0) throw new AssertionError(failures + " fark");
        System.out.println("DIFF OK");
    }
}
