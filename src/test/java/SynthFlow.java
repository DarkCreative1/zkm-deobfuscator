package com.zkmdeobf;

import com.zkmdeobf.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;

public class SynthFlow {
    public static byte[] build() {
        ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        w.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "synth/Opaque", null,
                "java/lang/Object", null);

        w.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "op", "I", null, null).visitEnd();
        MethodVisitor cl = w.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        cl.visitCode();
        cl.visitInsn(Opcodes.ICONST_1);
        cl.visitFieldInsn(Opcodes.PUTSTATIC, "synth/Opaque", "op", "I");
        cl.visitInsn(Opcodes.RETURN);
        cl.visitMaxs(1, 0);
        cl.visitEnd();

        MethodVisitor mv = w.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "(I)I", null, null);
        mv.visitCode();
        Label L1 = new Label(), L2 = new Label(), L3 = new Label(), L4 = new Label(), H = new Label();
        mv.visitFieldInsn(Opcodes.GETSTATIC, "synth/Opaque", "op", "I");
        mv.visitJumpInsn(Opcodes.IFNE, L1);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitJumpInsn(Opcodes.GOTO, L2);
        mv.visitLabel(L1);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitLabel(L2);
        mv.visitJumpInsn(Opcodes.GOTO, L3);
        mv.visitLabel(L3);
        mv.visitJumpInsn(Opcodes.GOTO, L4);
        mv.visitLabel(L4);
        mv.visitInsn(Opcodes.NOP);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(H);
        mv.visitInsn(Opcodes.ATHROW);
        mv.visitTryCatchBlock(L1, L2, H, "java/lang/Exception");
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        w.visitEnd();
        return w.toByteArray();
    }

    public static void main(String[] a) throws Exception {
        byte[] raw = build();
        Map<String, ClassNode> cs = new java.util.HashMap<>();
        ClassNode cn = new ClassNode();
        new org.objectweb.asm.ClassReader(raw).accept(cn, 0);
        cs.put("synth/Opaque.class", cn);

        int before = runRaw(raw, 41);

        MethodNode m = ClassIO.findMethod(cn, "run", "(I)I");
        Map<String, FlowSimplifier.Const> cc = FlowSimplifier.clinitConstants(cn);
        Map<String, String> gg = FlowSimplifier.trivialGetters(cn);
        int f = FlowSimplifier.foldMethod(cn, m, cc, gg);
        int g = Rewriter.collapseGotos(m);
        int h = Rewriter.stripFakeHandlers(cn, m);
        int d = Rewriter.removeDeadCode(m);
        System.out.println("fold=" + f + " goto=" + g + " handlers=" + h + " dead=" + d);
        byte[] out = ClassIO.toBytes(cn);
        int after = runRaw(out, 41);
        if (before != after) throw new AssertionError(before + " != " + after);
        if (f < 1 || h < 1) throw new AssertionError("sadelestirme uygulanmadi");

        ClassNode cn2 = new ClassNode();
        new org.objectweb.asm.ClassReader(out).accept(cn2, 0);
        MethodNode m2 = ClassIO.findMethod(cn2, "run", "(I)I");
        int jumps = 0;
        for (AbstractInsnNode n = m2.instructions.getFirst(); n != null; n = n.getNext())
            if (n instanceof org.objectweb.asm.tree.JumpInsnNode) jumps++;
        System.out.println("kalan jump: " + jumps + " sonuc: " + after);
        if (jumps > 1) throw new AssertionError("olu dallar duruyor");
        System.out.println("SYNTH FLOW OK");
    }

    static int runRaw(byte[] cls, int x) throws Exception {
        final byte[] b = cls;
        ClassLoader l = new ClassLoader(null) {};
        Class<?> c = new ClassLoader(null) {
            Class<?> def() { return defineClass("synth.Opaque", b, 0, b.length); }
        }.def();
        return (Integer) c.getMethod("run", int.class).invoke(null, x);
    }
}
