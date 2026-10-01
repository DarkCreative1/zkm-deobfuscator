package com.zkmdeobf;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

public final class MiniInterpreter {
    private MiniInterpreter() {}

    public static final int TRIP_CAP = 20000;
    public static final int STEP_CAP = 4000000;

    public static final class Arr {
        public final Object data;
        public Arr(Object d) { data = d; }
        public int len() {
            if (data instanceof byte[] b) return b.length;
            if (data instanceof char[] c) return c.length;
            if (data instanceof Object[] o) return o.length;
            if (data instanceof int[] i) return i.length;
            if (data instanceof long[] l) return l.length;
            throw new IllegalStateException();
        }
    }

    public static final class Bail extends RuntimeException {
        boolean traced;
        Bail(String m) { super(m); }
    }

    public static final List<String> lastTrace = new ArrayList<>();
    public static List<String> debugStores = null;
    public static boolean debugStack = false;
    public static List<String> debugTrace = null;
    public static int debugTraceCap = 0;

    private static String snap(Deque<Object> st) {
        StringBuilder sb = new StringBuilder("[");
        int n = 0;
        for (Object o : st) {
            if (n++ > 7) { sb.append("..."); break; }
            sb.append(o == null ? "null" : o instanceof String s
                    ? "\"" + s.substring(0, Math.min(10, s.length())) + "\""
                    : o instanceof Integer i ? "I" + i
                    : o instanceof Long ? "J" : o instanceof Arr a ? "A" + a.len()
                    : o instanceof Uninit u ? "U" + u.id : o.getClass().getSimpleName());
            sb.append(',');
        }
        return sb.append("]").toString();
    }

    public static final class Ctx {
        public final Map<String, ClassNode> classes;
        public final Map<String, Object> statics;
        public final ClassLoader loader;
        public final int depth;
        public final Set<String> clinitRunning;
        public Ctx(Map<String, ClassNode> c, ClassLoader l, int d) {
            this(c, l, d, new HashSet<>(), new HashMap<>());
        }
        public Ctx(Map<String, ClassNode> c, ClassLoader l, int d, Set<String> running) {
            this(c, l, d, running, new HashMap<>());
        }
        public Ctx(Map<String, ClassNode> c, ClassLoader l, int d,
                   Set<String> running, Map<String, Object> statics) {
            classes = c; loader = l; depth = d; clinitRunning = running; this.statics = statics;
        }
    }

    public static final class Obj {
        public final String type;
        public final Map<String, Object> fields = new HashMap<>();
        public Obj(String t) { type = t; }
        @Override public String toString() { return "Obj(" + type + ")"; }
    }

    public static Object run(Ctx ctx, ClassNode cn, MethodNode m, Object[] args) {
        if (ctx.depth > 8) throw new Bail("derinlik");

        Object[] loc = new Object[Math.max(m.maxLocals, args.length + 4)];
        Type[] at = Type.getArgumentTypes(m.desc);
        boolean statik = (m.access & Opcodes.ACC_STATIC) != 0;
        int li = statik ? 0 : 1;
        if (!statik) loc[0] = new Object();
        for (int i = 0; i < at.length && li < loc.length; i++) {
            loc[li] = args[i];
            li += at[i].getSize();
        }

        List<AbstractInsnNode> ins = ClassIO.list(m);
        Map<LabelNode, Integer> labels = new HashMap<>();
        for (int i = 0; i < ins.size(); i++)
            if (ins.get(i) instanceof LabelNode l) labels.put(l, i);
        Map<Integer, SubBypass> bypassAt = new HashMap<>();
        for (SubBypass b : detectSubroutines(m)) bypassAt.put(b.gotoPc, b);
        Deque<Object> st = new ArrayDeque<>();
        Map<Integer, Integer> trips = new HashMap<>();
        int steps = 0, pc = 0;
        int[] trace = new int[64];
        int tpos = 0;
        resume: while (true) {
        try {

        while (pc < ins.size() && isPseudo(ins.get(pc))) pc++;
        while (pc < ins.size()) {
            if (++steps > STEP_CAP) throw new Bail("adim");
            trace[tpos % trace.length] = pc;
            tpos++;
            if (debugTrace != null && debugTrace.size() < debugTraceCap) {
                AbstractInsnNode dn = ins.get(pc);
                debugTrace.add(pc + ":" + dn.getOpcode() + " " + snap(st));
            }
            AbstractInsnNode n = ins.get(pc);
            int op = n.getOpcode();
            if (op < 0) { pc++; continue; }
            switch (op) {
                case Opcodes.NOP -> pc++;
                case Opcodes.ACONST_NULL -> { st.push(NULL); pc++; }
                case Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1,
                        Opcodes.ICONST_2, Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5 ->
                    { st.push(op - 3); pc++; }
                case Opcodes.LCONST_0, Opcodes.LCONST_1 -> { st.push((long) (op - 9)); pc++; }
                case Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2 ->
                    { st.push((float) (op - 11)); pc++; }
                case Opcodes.DCONST_0, Opcodes.DCONST_1 -> { st.push((double) (op - 14)); pc++; }
                case Opcodes.BIPUSH, Opcodes.SIPUSH -> { st.push(((IntInsnNode) n).operand); pc++; }
                case Opcodes.LDC -> {
                    Object c = ((LdcInsnNode) n).cst;
                    if (c instanceof Integer || c instanceof Long || c instanceof Float
                            || c instanceof Double || c instanceof String) st.push(c);
                    else if (c instanceof Type) st.push(c);
                    else if (c instanceof org.objectweb.asm.Handle) st.push(c);
                    else throw new Bail("ldc-tur");
                    pc++;
                }
                case Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD -> {
                    Object v = loc[((VarInsnNode) n).var];
                    if (v == null && op != Opcodes.ALOAD) throw new Bail("bos-local");
                    st.push(v); pc++;
                }
                case Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE -> {
                    loc[((VarInsnNode) n).var] = st.pop(); pc++;
                }
                case Opcodes.POP -> { st.pop(); pc++; }
                case Opcodes.POP2 -> {
                    Object a = st.pop();
                    if (!(a instanceof Long || a instanceof Double)) st.pop();
                    pc++;
                }
                case Opcodes.DUP -> { Object a = st.peek(); st.push(a); pc++; }
                case Opcodes.DUP_X1 -> {

                    Object a = st.pop();
                    if (a instanceof Long || a instanceof Double) throw new Bail("dup-gecersiz");
                    Object b = st.pop();
                    st.push(a); st.push(b); st.push(a); pc++;
                }
                case Opcodes.DUP_X2 -> {

                    Object a = st.pop();
                    if (a instanceof Long || a instanceof Double) throw new Bail("dup-gecersiz");
                    Object b = st.pop();
                    if (b instanceof Long || b instanceof Double) {

                        Object c = st.pop();
                        if (c instanceof Long || c instanceof Double) throw new Bail("dup-gecersiz");
                        st.push(c); st.push(a); st.push(b); st.push(a);
                    } else {
                        Object c = st.pop();
                        if (c instanceof Long || c instanceof Double) throw new Bail("dup-gecersiz");

                        st.push(a); st.push(c); st.push(b); st.push(a);
                    }
                    pc++;
                }
                case Opcodes.DUP2 -> {
                    Object a = st.pop();
                    if (a instanceof Long || a instanceof Double) { st.push(a); st.push(a); }
                    else {
                        Object b = st.pop();
                        if (b instanceof Long || b instanceof Double) throw new Bail("dup-gecersiz");
                        st.push(b); st.push(a); st.push(b); st.push(a);
                    }
                    pc++;
                }
                case Opcodes.DUP2_X1, Opcodes.DUP2_X2, Opcodes.SWAP -> {
                    if (op == Opcodes.SWAP) {
                        Object a = st.pop(), b = st.pop();
                        if (a instanceof Long || a instanceof Double
                                || b instanceof Long || b instanceof Double)
                            throw new Bail("dup-gecersiz");
                        st.push(a); st.push(b);
                        pc++;
                        break;
                    }
                    Object a = st.pop();
                    boolean a2 = a instanceof Long || a instanceof Double;
                    if (op == Opcodes.DUP2_X1) {
                        if (a2) {

                            Object b = st.pop();
                            if (b instanceof Long || b instanceof Double) throw new Bail("dup-gecersiz");
                            st.push(a); st.push(b); st.push(a);
                        } else {

                            Object b = st.pop();
                            if (b instanceof Long || b instanceof Double) throw new Bail("dup-gecersiz");
                            Object c = st.pop();
                            st.push(b); st.push(a); st.push(c); st.push(b); st.push(a);
                        }
                        pc++;
                        break;
                    } else {

                        if (a2) {
                            Object b = st.pop();
                            if (b instanceof Long || b instanceof Double) {

                                st.push(a); st.push(b); st.push(a);
                            } else {

                                Object c = st.pop();
                                if (c instanceof Long || c instanceof Double) throw new Bail("dup-gecersiz");
                                st.push(a); st.push(c); st.push(b); st.push(a);
                            }
                        } else {
                            Object b = st.pop();
                            if (b instanceof Long || b instanceof Double) throw new Bail("dup-gecersiz");
                            Object c = st.pop();
                            if (c instanceof Long || c instanceof Double) {

                                st.push(b); st.push(a); st.push(c); st.push(b); st.push(a);
                            } else {

                                Object d = st.pop();
                                if (d instanceof Long || d instanceof Double) throw new Bail("dup-gecersiz");
                                st.push(b); st.push(a); st.push(d); st.push(c); st.push(b); st.push(a);
                            }
                        }
                        pc++;
                        break;
                    }
                }
                case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
                        Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR -> {
                    int b = (Integer) st.pop(), a = (Integer) st.pop();
                    st.push(switch (op) {
                        case Opcodes.IADD -> a + b; case Opcodes.ISUB -> a - b;
                        case Opcodes.IMUL -> a * b; case Opcodes.IDIV -> a / b;
                        case Opcodes.IREM -> a % b; case Opcodes.IAND -> a & b;
                        case Opcodes.IOR -> a | b; default -> a ^ b;
                    });
                    pc++;
                }
                case Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR -> {
                    int b = (Integer) st.pop(), a = (Integer) st.pop();
                    st.push(op == Opcodes.ISHL ? a << b : op == Opcodes.ISHR ? a >> b : a >>> b);
                    pc++;
                }
                case Opcodes.INEG -> { st.push(-(Integer) st.pop()); pc++; }
                case Opcodes.IINC -> {
                    IincInsnNode x = (IincInsnNode) n;
                    loc[x.var] = (Integer) loc[x.var] + x.incr;
                    pc++;
                }
                case Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
                        Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR -> {
                    long b = (Long) st.pop(), a = (Long) st.pop();
                    st.push(switch (op) {
                        case Opcodes.LADD -> a + b; case Opcodes.LSUB -> a - b;
                        case Opcodes.LMUL -> a * b; case Opcodes.LDIV -> a / b;
                        case Opcodes.LREM -> a % b; case Opcodes.LAND -> a & b;
                        case Opcodes.LOR -> a | b; default -> a ^ b;
                    });
                    pc++;
                }
                case Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR -> {
                    int b = (Integer) st.pop();
                    long a = (Long) st.pop();
                    st.push(op == Opcodes.LSHL ? a << b : op == Opcodes.LSHR ? a >> b : a >>> b);
                    pc++;
                }
                case Opcodes.LNEG -> { st.push(-(Long) st.pop()); pc++; }
                case Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV, Opcodes.FREM -> {
                    float b = toFloat(st.pop()), a = toFloat(st.pop());
                    st.push(switch (op) {
                        case Opcodes.FADD -> a + b; case Opcodes.FSUB -> a - b;
                        case Opcodes.FMUL -> a * b; case Opcodes.FDIV -> a / b;
                        default -> a % b;
                    });
                    pc++;
                }
                case Opcodes.FNEG -> { st.push(-toFloat(st.pop())); pc++; }
                case Opcodes.FCMPL, Opcodes.FCMPG -> {
                    float b = toFloat(st.pop()), a = toFloat(st.pop());
                    int r;
                    if (Float.isNaN(a) || Float.isNaN(b)) r = (op == Opcodes.FCMPG) ? 1 : -1;
                    else r = Float.compare(a, b);
                    st.push(r); pc++;
                }
                case Opcodes.DADD, Opcodes.DSUB, Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM -> {
                    double b = toDouble(st.pop()), a = toDouble(st.pop());
                    st.push(switch (op) {
                        case Opcodes.DADD -> a + b; case Opcodes.DSUB -> a - b;
                        case Opcodes.DMUL -> a * b; case Opcodes.DDIV -> a / b;
                        default -> a % b;
                    });
                    pc++;
                }
                case Opcodes.DNEG -> { st.push(-toDouble(st.pop())); pc++; }
                case Opcodes.DCMPL, Opcodes.DCMPG -> {
                    double b = toDouble(st.pop()), a = toDouble(st.pop());
                    int r;
                    if (Double.isNaN(a) || Double.isNaN(b)) r = (op == Opcodes.DCMPG) ? 1 : -1;
                    else r = Double.compare(a, b);
                    st.push(r); pc++;
                }
                case Opcodes.LCMP -> {
                    long b = (Long) st.pop(), a = (Long) st.pop();
                    st.push(Long.compare(a, b)); pc++;
                }
                case Opcodes.I2L -> { st.push((long) (Integer) st.pop()); pc++; }
                case Opcodes.I2F -> { st.push((float) (Integer) st.pop()); pc++; }
                case Opcodes.I2D -> { st.push((double) (Integer) st.pop()); pc++; }
                case Opcodes.L2I -> { st.push((int) (long) (Long) st.pop()); pc++; }
                case Opcodes.L2F -> { st.push((float) (long) (Long) st.pop()); pc++; }
                case Opcodes.L2D -> { st.push((double) (long) (Long) st.pop()); pc++; }
                case Opcodes.F2I, Opcodes.F2L, 141, Opcodes.D2I, 143, 144, Opcodes.I2B, Opcodes.I2C, Opcodes.I2S -> {
                    Object v = st.pop();
                    double d = v instanceof Double ? (Double) v : v instanceof Float ? (Float) v
                            : v instanceof Long ? (Long) v : (Integer) v;
                    st.push(switch (op) {
                        case Opcodes.F2I, Opcodes.D2I -> (int) d;
                        case Opcodes.F2L -> (long) d;
                        case 141, 144 -> d;
                        case 143 -> (long) d;
                        case Opcodes.I2B -> (int) (byte) (int) d;
                        case Opcodes.I2C -> (int) (char) (int) d;
                        default -> (int) (short) (int) d;
                    });
                    pc++;
                }
                case Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE,
                        Opcodes.IFGT, Opcodes.IFLE -> {
                    int a = (Integer) st.pop();
                    boolean t = switch (op) {
                        case Opcodes.IFEQ -> a == 0; case Opcodes.IFNE -> a != 0;
                        case Opcodes.IFLT -> a < 0; case Opcodes.IFGE -> a >= 0;
                        case Opcodes.IFGT -> a > 0; default -> a <= 0;
                    };
                    pc = jump(ins, labels, trips, pc, ((JumpInsnNode) n).label, t);
                }
                case Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT,
                        Opcodes.IF_ICMPGE, Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE -> {
                    int b = (Integer) st.pop(), a = (Integer) st.pop();
                    boolean t = switch (op) {
                        case Opcodes.IF_ICMPEQ -> a == b; case Opcodes.IF_ICMPNE -> a != b;
                        case Opcodes.IF_ICMPLT -> a < b; case Opcodes.IF_ICMPGE -> a >= b;
                        case Opcodes.IF_ICMPGT -> a > b; default -> a <= b;
                    };
                    pc = jump(ins, labels, trips, pc, ((JumpInsnNode) n).label, t);
                }
                case Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE -> {
                    Object b = st.pop(), a = st.pop();
                    boolean eq = a == b || (a == null && b == null);
                    boolean t = op == Opcodes.IF_ACMPEQ ? eq : !eq;
                    pc = jump(ins, labels, trips, pc, ((JumpInsnNode) n).label, t);
                }
                case Opcodes.IFNULL, Opcodes.IFNONNULL -> {
                    Object a = st.pop();
                    boolean isNull = a == null || a == NULL;
                    boolean t = op == Opcodes.IFNULL ? isNull : !isNull;
                    pc = jump(ins, labels, trips, pc, ((JumpInsnNode) n).label, t);
                }
                case Opcodes.GOTO -> {
                    SubBypass b = bypassAt.get(pc);
                    if (b != null) {

                        if (st.size() >= 2) {
                            Object idO = st.pop();
                            Object subO = st.pop();
                            if (idO instanceof Integer && subO instanceof String) {
                                String dec = Crypto.xorWithKeys((String) subO, b.keys);
                                st.push(dec);
                                int id = (Integer) idO;
                                int tgt = (id >= b.dispMin && id - b.dispMin < b.dispTargets.size())
                                        ? b.dispTargets.get(id - b.dispMin) : b.dispDefault;
                                pc = jump(ins, labels, trips, pc, null, true, tgt);
                                break;
                            } else {
                                st.push(subO);
                                st.push(idO);
                            }
                        }
                    }
                    pc = jump(ins, labels, trips, pc, ((JumpInsnNode) n).label, true);
                }
                case Opcodes.TABLESWITCH -> {
                    if (debugStack && debugStores != null)
                        debugStores.add("SWITCH @" + pc + " stack=" + snap(st));
                    int v = (Integer) st.pop();
                    TableSwitchInsnNode t = (TableSwitchInsnNode) n;
                    LabelNode tgt = (v >= t.min && v <= t.max) ? t.labels.get(v - t.min) : t.dflt;
                    pc = jump(ins, labels, trips, pc, tgt, true);
                }
                case Opcodes.LOOKUPSWITCH -> {
                    int v = (Integer) st.pop();
                    LookupSwitchInsnNode t = (LookupSwitchInsnNode) n;
                    LabelNode tgt = t.dflt;
                    for (int i = 0; i < t.keys.size(); i++)
                        if (t.keys.get(i) == v) { tgt = t.labels.get(i); break; }
                    pc = jump(ins, labels, trips, pc, tgt, true);
                }
                case Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN,
                        Opcodes.DRETURN, Opcodes.ARETURN -> { return st.pop(); }
                case Opcodes.RETURN -> { return null; }
                case Opcodes.ATHROW -> {
                    Object ex = st.pop();
                    Integer handler = findHandler(m, labels, pc, ex);
                    if (handler == null) throw new Bail("athrow");
                    st.clear();
                    st.push(ex);
                    pc = jumpTo(ins, trips, handler);
                }
                case Opcodes.ARRAYLENGTH -> {
                    Object a = st.pop();
                    if (a == NULL) throw new NullPointerException();
                    if (!(a instanceof Arr)) throw new Bail("arraylength-tip");
                    st.push(((Arr) a).len()); pc++;
                }
                case Opcodes.IALOAD, Opcodes.LALOAD, Opcodes.FALOAD, Opcodes.DALOAD,
                        Opcodes.AALOAD, Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD -> {
                    Object idxO = st.pop();
                    Object arrO = st.pop();
                    if (arrO == NULL) throw new NullPointerException();
                    if (!(idxO instanceof Integer) || !(arrO instanceof Arr))
                        throw new Bail("aload-tip");
                    int i = (Integer) idxO;
                    Arr a = (Arr) arrO;
                    if (i < 0 || i >= a.len()) throw new Bail("aload-aralik");
                    Object element = switch (op) {
                        case Opcodes.IALOAD -> ((int[]) a.data)[i];
                        case Opcodes.LALOAD -> ((long[]) a.data)[i];
                        case Opcodes.FALOAD -> ((float[]) a.data)[i];
                        case Opcodes.DALOAD -> ((double[]) a.data)[i];
                        case Opcodes.BALOAD -> (int) ((byte[]) a.data)[i];
                        case Opcodes.CALOAD -> (int) ((char[]) a.data)[i];
                        case Opcodes.SALOAD -> (int) ((short[]) a.data)[i];
                        default -> ((Object[]) a.data)[i];
                    };

                    st.push(element == null ? NULL : element);
                    pc++;
                }
                case Opcodes.IASTORE, Opcodes.LASTORE, Opcodes.FASTORE, Opcodes.DASTORE,
                        Opcodes.AASTORE, Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE -> {
                    if (debugStores != null && op == Opcodes.AASTORE) {
                        Object[] sn = st.toArray();

                        int ii = (Integer) sn[1];
                        int ll = ((Arr) sn[2]).len();
                        Object vv = sn[0];
                        String vs = vv instanceof String s
                                ? (s.length() + ":" + s.substring(0, Math.min(12, s.length()))) : "?";
                        debugStores.add("AASTORE idx=" + ii + " len=" + ll + " val=" + vs
                                + " loc8=" + loc[8] + " loc9=" + loc[9] + " loc11=" + loc[11] + " loc12=" + loc[12]
                                + " loc10=" + (loc[10] instanceof String s10
                                    ? ("len" + s10.length() + ":" + s10.substring(0, Math.min(8, s10.length()))) : "?")
                                + " loc13same=" + (loc[13] == ((Arr) sn[2])));
                    }
                    Object v = st.pop();
                    Object iO = st.pop();
                    Object aO = st.pop();
                    if (aO == NULL) throw new NullPointerException();
                    if (!(iO instanceof Integer) || !(aO instanceof Arr))
                        throw new Bail("astore-tip");
                    int i = (Integer) iO;
                    Arr a = (Arr) aO;
                    if (i < 0 || i >= a.len())
                        throw new Bail("aralik-disi:" + op + " idx=" + i + " len=" + a.len());
                    Object vv = (v == NULL) ? null : v;
                    switch (op) {
                        case Opcodes.IASTORE -> ((int[]) a.data)[i] = (Integer) vv;
                        case Opcodes.LASTORE -> ((long[]) a.data)[i] = (Long) vv;
                        case Opcodes.FASTORE -> ((float[]) a.data)[i] = (Float) vv;
                        case Opcodes.DASTORE -> ((double[]) a.data)[i] = (Double) vv;
                        case Opcodes.AASTORE -> ((Object[]) a.data)[i] = vv;
                        case Opcodes.BASTORE -> ((byte[]) a.data)[i] = ((Integer) vv).byteValue();
                        case Opcodes.CASTORE -> ((char[]) a.data)[i] = (char) (int) (Integer) vv;
                        default -> ((short[]) a.data)[i] = ((Integer) vv).shortValue();
                    }
                    pc++;
                }
                case Opcodes.GETSTATIC -> {
                    FieldInsnNode f = (FieldInsnNode) n;
                    String key = f.owner + "." + f.name;
                    if (ctx.statics.containsKey(key)) {
                        st.push(ctx.statics.get(key));
                    } else if (f.owner.equals(cn.name)) {

                        Object cv = ownConstant(cn, f.name, f.desc);
                        st.push(cv != null ? cv : defaultValue(f.desc));
                    } else {
                        Object v = staticFinalConst(ctx, f.owner, f.name);
                        if (v != null) { st.push(v); pc++; break; }
                        Object cross = ensureClinit(ctx, f.owner);
                        if (cross != null && ctx.statics.containsKey(key)) {
                            st.push(ctx.statics.get(key));
                        } else if (ctx.loader != null) {
                            Object dyn = readStaticViaLoader(ctx, f.owner, f.name, f.desc);
                            if (dyn != null) st.push(dyn);
                            else throw new Bail("static-bilinmiyor:" + f.name);
                        } else {
                            throw new Bail("static-bilinmiyor:" + f.name);
                        }
                    }
                    pc++;
                }
                case Opcodes.PUTSTATIC -> {
                    FieldInsnNode f = (FieldInsnNode) n;
                    ctx.statics.put(f.owner + "." + f.name, st.pop()); pc++;
                }
                case Opcodes.GETFIELD, Opcodes.PUTFIELD -> {
                    FieldInsnNode f = (FieldInsnNode) n;
                    if (op == Opcodes.GETFIELD) {
                        Object recv = st.pop();
                        if (recv == NULL) throw new NullPointerException();
                        if (recv instanceof Obj o) {
                            Object v = o.fields.get(f.owner + "." + f.name);
                            st.push(v == null ? defaultValue(f.desc) : v);
                        } else {
                            throw new Bail("instance-field");
                        }
                    } else {
                        Object v = st.pop();
                        Object recv = st.pop();
                        if (recv == NULL) throw new NullPointerException();
                        if (recv instanceof Obj o) o.fields.put(f.owner + "." + f.name, v);
                        else throw new Bail("instance-field");
                    }
                    pc++;
                }
                case Opcodes.NEW -> {
                    TypeInsnNode t = (TypeInsnNode) n;
                    if (t.desc.equals("java/lang/StringBuilder")) st.push(new StringBuilder());
                    else if (t.desc.equals("java/lang/StringBuffer")) st.push(new StringBuffer());
                    else if (t.desc.equals("java/lang/String")) st.push(new Uninit());
                    else if (t.desc.equals("java/util/ArrayList")) st.push(new ArrayList<>());
                    else if (t.desc.equals("java/util/HashMap") || t.desc.equals("java/util/LinkedHashMap"))
                        st.push(new HashMap<>());
                    else if (t.desc.equals("java/util/HashSet") || t.desc.equals("java/util/LinkedHashSet"))
                        st.push(new HashSet<>());
                    else if (t.desc.equals("java/lang/Throwable") || t.desc.equals("java/lang/Exception")
                            || t.desc.equals("java/lang/RuntimeException")
                            || t.desc.endsWith("Exception") || t.desc.endsWith("Error"))
                        st.push(new Obj(t.desc));
                    else st.push(new Obj(t.desc));
                    pc++;
                }
                case Opcodes.NEWARRAY -> {
                    int c = (Integer) st.pop();
                    int atyp = ((IntInsnNode) n).operand;
                    st.push(new Arr(switch (atyp) {
                        case 4 -> new boolean[c]; case 5 -> new char[c];
                        case 6 -> new float[c]; case 7 -> new double[c];
                        case 8 -> new byte[c]; case 9 -> new short[c];
                        case 10 -> new int[c]; default -> new long[c];
                    }));
                    pc++;
                }
                case Opcodes.ANEWARRAY -> {
                    int c = (Integer) st.pop();
                    TypeInsnNode t = (TypeInsnNode) n;
                    if (t.desc.equals("java/lang/String")) st.push(new Arr(new String[c]));
                    else if (t.desc.equals("java/lang/Object")) st.push(new Arr(new Object[c]));
                    else if (t.desc.equals("java/lang/Integer")) st.push(new Arr(new Integer[c]));
                    else if (t.desc.equals("java/lang/Long")) st.push(new Arr(new Long[c]));
                    else if (t.desc.equals("[B") || t.desc.equals("[C") || t.desc.equals("[I")
                            || t.desc.equals("[J") || t.desc.equals("[Ljava/lang/String;"))
                        st.push(new Arr(new Object[c]));
                    else throw new Bail("anewarray:" + t.desc);
                    pc++;
                }
                case Opcodes.MULTIANEWARRAY -> {
                    MultiANewArrayInsnNode t = (MultiANewArrayInsnNode) n;
                    int dims = t.dims;
                    int[] counts = new int[dims];
                    for (int i = dims - 1; i >= 0; i--) counts[i] = (Integer) st.pop();
                    st.push(new Arr(multiArray(t.desc, counts, 0)));
                    pc++;
                }
                case Opcodes.CHECKCAST -> {
                    TypeInsnNode t = (TypeInsnNode) n;
                    Object v = st.peek();

                    if (v != NULL && !instanceofCheck(v, t.desc)) {
                        Object syn = new Obj("java/lang/ClassCastException");
                        Integer h = findHandler(m, labels, pc, syn);
                        if (h == null) throw new Bail("checkcast:" + t.desc);
                        st.clear();
                        st.push(syn);
                        pc = jumpTo(ins, trips, h);
                    } else pc++;
                }
                case Opcodes.INSTANCEOF -> {
                    Object v = st.pop();
                    TypeInsnNode t = (TypeInsnNode) n;
                    st.push(instanceofCheck(v, t.desc) ? 1 : 0);
                    pc++;
                }
                case Opcodes.MONITORENTER, Opcodes.MONITOREXIT -> {
                    Object mo = st.pop();
                    if (mo == NULL) throw new NullPointerException();
                    pc++;
                }
                case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL,
                        Opcodes.INVOKESTATIC, Opcodes.INVOKEINTERFACE -> {
                    MethodInsnNode mi2 = (MethodInsnNode) n;

                    if (op == Opcodes.INVOKESPECIAL && mi2.owner.equals("java/lang/String")
                            && mi2.name.equals("<init>")) {
                        Type[] aa = Type.getArgumentTypes(mi2.desc);
                        Object[] ag = new Object[aa.length];
                        for (int i = aa.length - 1; i >= 0; i--) ag[i] = st.pop();
                        Object rc = st.pop();
                        if (!(rc instanceof Uninit)) throw new Bail("String-init-alici");
                        {
                            Uninit u = (Uninit) rc;
                            String built = buildString(mi2.desc, ag);
                            for (int j = 0; j < loc.length; j++)
                                if (loc[j] == u) loc[j] = built;
                            Object[] fix = st.toArray();
                            st.clear();
                            for (int j = fix.length - 1; j >= 0; j--)
                                st.push(fix[j] == u ? built : fix[j]);
                        }
                        pc++;
                        break;
                    }
                    Object r = invoke(ctx, cn, mi2, st, op);
                    Type rt = Type.getReturnType(((MethodInsnNode) n).desc);
                    if (rt.getSort() != Type.VOID) st.push(r);
                    pc++;
                }
                case Opcodes.INVOKEDYNAMIC -> {
                    InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) n;
                    if (isStringConcat(id)) {
                        st.push(evalStringConcat(id, st));
                        pc++;
                        break;
                    }
                    throw new Bail("indy");
                }
                case Opcodes.JSR -> {
                    st.push(pc + 1);
                    pc = jump(ins, labels, trips, pc, ((JumpInsnNode) n).label, true);
                }
                case Opcodes.RET -> {
                    Object a = loc[((VarInsnNode) n).var];
                    if (!(a instanceof Integer)) throw new Bail("ret-tip");
                    pc = jumpTo(ins, trips, (Integer) a);
                }
                default -> throw new Bail("opcode:" + op);
            }
        }
        throw new Bail("akis-sonu");
        } catch (Bail b) {
            if (b.traced) throw b;
            b.traced = true;
            StringBuilder sb = new StringBuilder();
            sb.append(cn.name).append('.').append(m.name).append(" iz[");
            int n = Math.min(tpos, trace.length);
            for (int i = 0; i < n; i++) {
                int p2 = trace[(tpos - n + i) % trace.length];
                AbstractInsnNode nn = ins.get(p2);
                sb.append(p2).append(':').append(nn.getOpcode()).append(' ');
            }
            sb.append("] ");
            throw new Bail(sb.toString() + b.getMessage());
        } catch (RuntimeException b) {

            Object syn = syntheticException(b);
            if (syn != null) {
                Integer h = findHandler(m, labels, pc, syn);
                if (h != null) {
                    st.clear();
                    st.push(syn);
                    pc = jumpTo(ins, trips, h);
                    continue resume;
                }
            }
            StringBuilder sb = new StringBuilder();
            sb.append(cn.name).append('.').append(m.name).append(" iz[");
            int n = Math.min(tpos, trace.length);
            for (int i = 0; i < n; i++) {
                int p2 = trace[(tpos - n + i) % trace.length];
                AbstractInsnNode nn = ins.get(p2);
                sb.append(p2).append(':').append(nn.getOpcode()).append(' ');
            }
            sb.append("] ");
            if (Boolean.getBoolean("zkmdeobf.debugEmu")) {
                System.err.println("[emu-istisna] " + cn.name + "." + m.name + " : " + b);
                for (StackTraceElement e : b.getStackTrace()) System.err.println("      at " + e);
            }
            throw new Bail(sb.toString() + b);
        }
        }
    }

    private static boolean instanceofCheck(Object v, String desc) {
        if (v == null || v == NULL) return false;
        if (v instanceof Arr a) {
            if (!desc.startsWith("[")) {
                return desc.equals("java/lang/Object") || desc.equals("java/lang/Cloneable")
                        || desc.equals("java/io/Serializable");
            }
            Object d = a.data;
            return switch (desc) {
                case "[Z" -> d instanceof boolean[];
                case "[C" -> d instanceof char[];
                case "[F" -> d instanceof float[];
                case "[D" -> d instanceof double[];
                case "[B" -> d instanceof byte[];
                case "[S" -> d instanceof short[];
                case "[I" -> d instanceof int[];
                case "[J" -> d instanceof long[];
                default -> d instanceof Object[];
            };
        }
        if (v instanceof Uninit) return false;
        if (v instanceof Obj o) {
            if (desc.equals("java/lang/Object")) return true;
            return desc.equals(o.type);
        }
        return switch (desc) {
            case "java/lang/String" -> v instanceof String;
            case "java/lang/Integer" -> v instanceof Integer;
            case "java/lang/Long" -> v instanceof Long;
            case "java/lang/Float" -> v instanceof Float;
            case "java/lang/Double" -> v instanceof Double;
            case "java/lang/Number" ->
                    v instanceof Integer || v instanceof Long || v instanceof Float || v instanceof Double;
            case "java/lang/CharSequence" ->
                    v instanceof String || v instanceof StringBuilder || v instanceof StringBuffer;
            case "java/util/List", "java/util/Collection", "java/util/ArrayList" ->
                v instanceof ArrayList;
            case "java/util/Map", "java/util/HashMap" -> v instanceof HashMap;
            case "java/util/Set", "java/util/HashSet" -> v instanceof HashSet;
            case "java/lang/Object" -> true;
            case "java/io/Serializable" ->
                    v instanceof String || v instanceof Integer || v instanceof Long
                            || v instanceof Float || v instanceof Double
                            || v instanceof ArrayList || v instanceof HashMap || v instanceof HashSet;
            case "java/lang/Comparable" ->
                    v instanceof String || v instanceof Integer || v instanceof Long;
            case "java/lang/Cloneable" -> v instanceof Arr;
            case "java/lang/Class" -> v instanceof Class;
            case "java/lang/Throwable", "java/lang/Exception", "java/lang/RuntimeException" ->
                    v instanceof Throwable;
            default -> false;
        };
    }

    private static boolean isPseudo(AbstractInsnNode n) {
        return n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode;
    }

    private static boolean isNullable(String desc) {
        return desc.equals("Ljava/lang/String;") || desc.startsWith("[")
                || desc.equals("Ljava/util/Map;") || desc.equals("Ljava/lang/Object;");
    }

    public static final Object NULL = new Object();

    private static Object defaultValue(String desc) {
        return switch (desc.charAt(0)) {
            case 'J' -> 0L;
            case 'F' -> 0.0f;
            case 'D' -> 0.0;
            case 'Z', 'B', 'C', 'S', 'I' -> 0;
            default -> NULL;
        };
    }

    private static Object ownConstant(ClassNode cn, String name, String desc) {
        for (var f : cn.fields) {
            if (!f.name.equals(name)) continue;
            if (f.value instanceof Integer i
                    && (desc.equals("I") || desc.equals("Z") || desc.equals("B")
                        || desc.equals("C") || desc.equals("S"))) return i;
            if (f.value instanceof Long l && desc.equals("J")) return l;
            if (f.value instanceof Float ff && desc.equals("F")) return ff;
            if (f.value instanceof Double d && desc.equals("D")) return d;
            if (f.value instanceof String s && desc.equals("Ljava/lang/String;")) return s;
            return null;
        }
        return null;
    }

    private static Object staticFinalConst(Ctx ctx, String owner, String name) {
        ClassNode cn = ctx.classes.get(owner + ".class");
        if (cn == null) return null;
        for (var f : cn.fields) {
            if (f.name.equals(name) && (f.access & Opcodes.ACC_STATIC) != 0
                    && (f.access & Opcodes.ACC_FINAL) != 0 && f.value != null) {
                return f.value;
            }
        }
        return null;
    }

    private static Object ensureClinit(Ctx ctx, String owner) {
        ClassNode ocn = ctx.classes.get(owner + ".class");
        if (ocn == null) return null;
        if (ctx.depth > 8) throw new Bail("derinlik");
        if (ctx.clinitRunning.contains(owner)) return null;
        MethodNode cl = ClassIO.findMethod(ocn, "<clinit>", "()V");
        if (cl == null) return null;
        ctx.clinitRunning.add(owner);
        try {
            run(new Ctx(ctx.classes, ctx.loader, ctx.depth + 1, ctx.clinitRunning, ctx.statics),
                    ocn, cl, new Object[0]);
        } catch (Bail b) {
            return null;
        } finally {
            ctx.clinitRunning.remove(owner);
        }
        return Boolean.TRUE;
    }

    private static Object readStaticViaLoader(Ctx ctx, String owner, String name, String desc) {
        if (ctx.loader == null) return null;
        try {
            Class<?> c = Class.forName(owner.replace('/', '.'), false, ctx.loader);
            java.lang.reflect.Field f = null;
            for (java.lang.reflect.Field ff : c.getDeclaredFields()) {
                if (ff.getName().equals(name)) { f = ff; break; }
            }
            if (f == null) return null;
            if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) return null;
            f.setAccessible(true);
            if (java.lang.reflect.Modifier.isFinal(f.getModifiers())) return wrap(f.get(null));

            try {
                Object v = f.get(null);
                return wrap(v);
            } catch (ExceptionInInitializerError | IllegalAccessException e) {
                return null;
            }
        } catch (Throwable t) {
            return null;
        }
    }

    private static int jump(List<AbstractInsnNode> ins, Map<LabelNode, Integer> labels,
                            Map<Integer, Integer> trips, int pc, LabelNode t, boolean taken) {
        if (!taken) return pc + 1;
        Integer tgt = labels.get(t);
        if (tgt == null) throw new Bail("hedef");
        int c = trips.merge(tgt, 1, Integer::sum);
        if (c > TRIP_CAP) throw new Bail("dongu");
        return tgt;
    }

    private static int jump(List<AbstractInsnNode> ins, Map<LabelNode, Integer> labels,
                            Map<Integer, Integer> trips, int pc, LabelNode t, boolean taken, int absTgt) {
        if (!taken) return pc + 1;
        int c = trips.merge(absTgt, 1, Integer::sum);
        if (c > TRIP_CAP) throw new Bail("dongu");
        return absTgt;
    }

    private static int jumpTo(List<AbstractInsnNode> ins, Map<Integer, Integer> trips, int tgt) {
        int c = trips.merge(tgt, 1, Integer::sum);
        if (c > TRIP_CAP) throw new Bail("dongu");
        return tgt;
    }

    private static Object syntheticException(RuntimeException b) {
        if (b instanceof NullPointerException) return new Obj("java/lang/NullPointerException");
        if (b instanceof ClassCastException) return new Obj("java/lang/ClassCastException");
        if (b instanceof ArithmeticException) return new Obj("java/lang/ArithmeticException");
        if (b instanceof ArrayIndexOutOfBoundsException)
            return new Obj("java/lang/ArrayIndexOutOfBoundsException");
        if (b instanceof NegativeArraySizeException)
            return new Obj("java/lang/NegativeArraySizeException");
        return null;
    }

    private static Integer findHandler(MethodNode m, Map<LabelNode, Integer> labels, int pc, Object ex) {
        if (m.tryCatchBlocks == null || m.tryCatchBlocks.isEmpty()) return null;
        for (TryCatchBlockNode t : m.tryCatchBlocks) {
            Integer s = labels.get(t.start), e = labels.get(t.end), h = labels.get(t.handler);
            if (s == null || e == null || h == null) continue;
            if (!(s <= pc && pc < e)) continue;
            if (t.type == null) return h;
            String tn = t.type;
            if (ex instanceof Obj o) {
                if (matchesType(o.type, tn)) return h;
            } else if (ex instanceof Throwable th) {
                try {
                    Class<?> cc = Class.forName(tn.replace('/', '.'), false,
                            Thread.currentThread().getContextClassLoader());
                    if (cc.isInstance(th)) return h;
                } catch (Throwable ignored) {
                    if (tn.endsWith("Throwable") || tn.endsWith("Exception")) return h;
                }
            } else {
                return null;
            }
        }
        return null;
    }

    private static boolean matchesType(String actual, String handler) {
        if (actual.equals(handler)) return true;
        if (handler.equals("java/lang/Throwable")) return true;
        Set<String> sups = new HashSet<>();
        String cur = actual;
        while (cur != null && sups.add(cur)) {
            cur = switch (cur) {
                case "java/lang/NullPointerException", "java/lang/ClassCastException",
                     "java/lang/ArithmeticException", "java/lang/ArrayIndexOutOfBoundsException",
                     "java/lang/NegativeArraySizeException", "java/lang/IllegalArgumentException",
                     "java/lang/IllegalStateException", "java/lang/IndexOutOfBoundsException" ->
                    "java/lang/RuntimeException";
                case "java/lang/RuntimeException", "java/io/IOException" -> "java/lang/Exception";
                case "java/lang/Exception" -> "java/lang/Throwable";
                default -> null;
            };
            if (handler.equals(cur)) return true;
        }
        if (handler.equals("java/lang/Exception")
                && (actual.endsWith("Exception") || sups.contains("java/lang/Exception"))) return true;
        return false;
    }

    private static boolean isStringConcat(InvokeDynamicInsnNode id) {
        if (!id.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) return false;
        String nm = id.bsm.getName();
        return nm.equals("makeConcat") || nm.equals("makeConcatWithConstants");
    }

    private static String evalStringConcat(InvokeDynamicInsnNode id, Deque<Object> st) {
        Type[] at = Type.getArgumentTypes(id.desc);
        Object[] args = new Object[at.length];
        for (int i = at.length - 1; i >= 0; i--) args[i] = unwrap(st.pop());
        if (!id.bsm.getName().equals("makeConcatWithConstants") || id.bsmArgs.length == 0)
            return concatArgs(args);
        Object recipe = id.bsmArgs[0];
        if (!(recipe instanceof String r)) return concatArgs(args);
        StringBuilder o = new StringBuilder();
        int ai = 0;
        for (int i = 0; i < r.length(); i++) {
            char c = r.charAt(i);
            if (c == '\u0001' && ai < args.length) o.append(args[ai++]);
            else o.append(c);
        }
        while (ai < args.length) o.append(args[ai++]);
        return o.toString();
    }

    private static String concatArgs(Object[] args) {
        StringBuilder o = new StringBuilder();
        for (Object a : args) o.append(a);
        return o.toString();
    }

    public static final class SubBypass {
        public final int gotoPc;
        public final int entryPc;
        public final int dispatcherPc;
        public final int[] keys;
        public final int dispMin;
        public final List<Integer> dispTargets;
        public final int dispDefault;
        SubBypass(int g, int e, int d, int[] k, int min, List<Integer> t, int df) {
            gotoPc = g; entryPc = e; dispatcherPc = d; keys = k;
            dispMin = min; dispTargets = t; dispDefault = df;
        }
    }

    public static List<SubBypass> detectSubroutines(MethodNode m) {
        List<SubBypass> o = new ArrayList<>();
        List<AbstractInsnNode> ins = ClassIO.list(m);
        Map<LabelNode, Integer> lab = new HashMap<>();
        for (int i = 0; i < ins.size(); i++)
            if (ins.get(i) instanceof LabelNode l) lab.put(l, i);

        for (int k = 0; k < ins.size(); k++) {
            AbstractInsnNode g = ins.get(k);
            if (!(g instanceof JumpInsnNode) || g.getOpcode() != Opcodes.GOTO) continue;
            AbstractInsnNode idn = prevReal(ins, k);
            Integer idv = idn == null ? null : ClassIO.constInt(idn);
            if (idv == null) continue;
            Integer entry = lab.get(((JumpInsnNode) g).label);
            if (entry == null) continue;

            Integer disp = null;
            int[] keys = null;
            boolean hasToChar = false, hasKeySwitch = false;
            for (int j = entry; j < ins.size(); j++) {
                AbstractInsnNode n = ins.get(j);
                if (n instanceof MethodInsnNode mi && mi.name.equals("toCharArray")) hasToChar = true;
                if (n.getOpcode() == Opcodes.TABLESWITCH && n instanceof TableSwitchInsnNode t) {
                    if (t.max - t.min + 1 == 7 || (t.min == 0 && t.max == 5)) {
                        hasKeySwitch = true;
                        keys = readKeySwitch(ins, t);
                        continue;
                    }
                    if (t.max == t.min) {
                        disp = j;
                        break;
                    }
                }
                if (j - entry > 400) break;
            }
            if (disp == null || !hasToChar || !hasKeySwitch || keys == null) continue;
            TableSwitchInsnNode dt = (TableSwitchInsnNode) ins.get(disp);

            AbstractInsnNode beforeEntry = prevReal(ins, entry);
            if (beforeEntry != null) {
                int bop = beforeEntry.getOpcode();
                boolean endsFlow = bop == Opcodes.GOTO || bop == Opcodes.RETURN
                        || (bop >= Opcodes.IRETURN && bop <= Opcodes.RETURN)
                        || bop == Opcodes.ATHROW || bop == Opcodes.TABLESWITCH
                        || bop == Opcodes.LOOKUPSWITCH || bop == Opcodes.JSR || bop == Opcodes.RET;
                if (!endsFlow) continue;
            }
            List<Integer> tgts = new ArrayList<>();
            for (LabelNode l : dt.labels) {
                Integer t = lab.get(l);
                if (t == null) { tgts = null; break; }
                tgts.add(t);
            }
            Integer df = lab.get(dt.dflt);
            if (tgts == null || df == null) continue;

            Set<Integer> inside = new HashSet<>();
            for (int j = entry; j <= disp; j++) inside.add(j);
            boolean ok = true;
            for (int j = 0; j < ins.size(); j++) {
                if (inside.contains(j)) continue;
                AbstractInsnNode n = ins.get(j);
                if (n instanceof JumpInsnNode jj) {
                    Integer t = lab.get(jj.label);
                    if (t != null && inside.contains(t) && t != entry) { ok = false; break; }
                } else if (n instanceof TableSwitchInsnNode t) {
                    for (LabelNode l : t.labels) {
                        Integer tt = lab.get(l);
                        if (tt != null && inside.contains(tt)) { ok = false; break; }
                    }
                    Integer dd = lab.get(t.dflt);
                    if (dd != null && inside.contains(dd)) ok = false;
                    if (!ok) break;
                } else if (n instanceof LookupSwitchInsnNode t) {
                    for (LabelNode l : t.labels) {
                        Integer tt = lab.get(l);
                        if (tt != null && inside.contains(tt)) { ok = false; break; }
                    }
                    Integer dd = lab.get(t.dflt);
                    if (dd != null && inside.contains(dd)) ok = false;
                    if (!ok) break;
                }
            }
            if (!ok) continue;
            o.add(new SubBypass(k, entry, disp, keys, dt.min, tgts, df));
        }
        return o;
    }

    private static AbstractInsnNode prevReal(List<AbstractInsnNode> ins, int k) {
        for (int j = k - 1; j >= 0; j--) {
            AbstractInsnNode n = ins.get(j);
            if (!(n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode)) return n;
        }
        return null;
    }

    private static int[] readKeySwitch(List<AbstractInsnNode> ins, TableSwitchInsnNode t) {
        Map<LabelNode, Integer> lab = new HashMap<>();
        for (int i = 0; i < ins.size(); i++)
            if (ins.get(i) instanceof LabelNode l) lab.put(l, i);
        List<LabelNode> order = new ArrayList<>(t.labels);
        order.add(t.dflt);
        List<Integer> keys = new ArrayList<>();
        for (LabelNode l : order) {
            Integer idx = lab.get(l);
            if (idx == null) return null;
            AbstractInsnNode cur = null;
            for (int j = idx; j < ins.size(); j++) {
                AbstractInsnNode n = ins.get(j);
                if (n instanceof LabelNode || n instanceof LineNumberNode || n instanceof FrameNode) continue;
                cur = n;
                break;
            }
            Integer v = cur == null ? null : ClassIO.constInt(cur);
            if (v == null || v < 0 || v > 255) return null;
            keys.add(v);
            if (keys.size() == 7) break;
        }
        if (keys.size() != 7) return null;
        int[] o = new int[7];
        for (int i = 0; i < 7; i++) o[i] = keys.get(i);
        return o;
    }

    public static final class Uninit {
        static int seq;
        final int id;
        Uninit() { id = ++seq; }
    }

    @SuppressWarnings("unchecked")
    private static Object invoke(Ctx ctx, ClassNode cn, MethodInsnNode mi,
                                 Deque<Object> st, int op) {
        String k = mi.owner + "." + mi.name + mi.desc;
        Type[] at = Type.getArgumentTypes(mi.desc);
        Object[] args = new Object[at.length];
        for (int i = at.length - 1; i >= 0; i--) args[i] = st.pop();
        Object recv = null;
        if (op != Opcodes.INVOKESTATIC) recv = st.pop();

        if (recv == NULL) throw new NullPointerException();
        if (mi.name.equals("<init>")) {
            Object initRes = handleInit(mi, args, recv);
            if (initRes != null || Type.getReturnType(mi.desc).getSort() == Type.VOID) return initRes;
        }

        if (mi.owner.equals("java/lang/String")) {
            switch (mi.name + mi.desc) {
                case "length()I" -> { return ((String) recv).length(); }
                case "charAt(I)C" -> { return (int) ((String) recv).charAt((Integer) args[0]); }
                case "substring(II)Ljava/lang/String;" ->
                    { return ((String) recv).substring((Integer) args[0], (Integer) args[1]); }
                case "substring(I)Ljava/lang/String;" ->
                    { return ((String) recv).substring((Integer) args[0]); }
                case "<init>([C)V" -> {

                    throw new Bail("String-init");
                }
                case "intern()Ljava/lang/String;" -> { return recv; }
                case "equals(Ljava/lang/Object;)Z" -> { return ((String) recv).equals(args[0]) ? 1 : 0; }
                case "indexOf(I)I" -> { return ((String) recv).indexOf((Integer) args[0]); }
                case "indexOf(Ljava/lang/String;)I" ->
                    { return ((String) recv).indexOf((String) args[0]); }
                case "concat(Ljava/lang/String;)Ljava/lang/String;" ->
                    { return ((String) recv) + ((String) args[0]); }
                case "valueOf(I)Ljava/lang/String;" -> { return String.valueOf((Integer) args[0]); }
                case "valueOf(J)Ljava/lang/String;" -> { return String.valueOf((Long) args[0]); }
                case "valueOf(Ljava/lang/Object;)Ljava/lang/String;" ->
                    { return String.valueOf(unwrap(args[0])); }
                case "isEmpty()Z" -> { return ((String) recv).isEmpty() ? 1 : 0; }
                case "isBlank()Z" -> { return ((String) recv).isBlank() ? 1 : 0; }
                case "startsWith(Ljava/lang/String;)Z" ->
                    { return ((String) recv).startsWith((String) args[0]) ? 1 : 0; }
                case "endsWith(Ljava/lang/String;)Z" ->
                    { return ((String) recv).endsWith((String) args[0]) ? 1 : 0; }
                case "contains(Ljava/lang/CharSequence;)Z" ->
                    { return ((String) recv).contains(String.valueOf(unwrap(args[0]))) ? 1 : 0; }
                case "trim()Ljava/lang/String;" -> { return ((String) recv).trim(); }
                case "strip()Ljava/lang/String;" -> { return ((String) recv).strip(); }
                case "toLowerCase()Ljava/lang/String;" -> { return ((String) recv).toLowerCase(); }
                case "toUpperCase()Ljava/lang/String;" -> { return ((String) recv).toUpperCase(); }
                case "toCharArray()[C" -> { return new Arr(((String) recv).toCharArray()); }
                case "getBytes()[B" -> {
                    return new Arr(((String) recv).getBytes(java.nio.charset.Charset.defaultCharset()));
                }
                case "getBytes(Ljava/lang/String;)[B" -> {
                    try {
                        return new Arr(((String) recv).getBytes((String) args[0]));
                    } catch (Exception e) { throw new Bail("charset"); }
                }
                case "compareTo(Ljava/lang/String;)I" ->
                    { return ((String) recv).compareTo((String) args[0]); }
                case "compareToIgnoreCase(Ljava/lang/String;)I" ->
                    { return ((String) recv).compareToIgnoreCase((String) args[0]); }
                case "repeat(I)Ljava/lang/String;" ->
                    { return ((String) recv).repeat((Integer) args[0]); }
                case "subSequence(II)Ljava/lang/CharSequence;" -> {
                    return ((String) recv).substring((Integer) args[0], (Integer) args[1]);
                }
                case "getChars(II[CI)V" -> {
                    Object dst = args[2] instanceof Arr a ? a.data : unwrap(args[2]);
                    ((String) recv).getChars((Integer) args[0], (Integer) args[1],
                            (char[]) dst, (Integer) args[3]);
                    return null;
                }
                case "hashCode()I" -> { return ((String) recv).hashCode(); }
                case "split(Ljava/lang/String;)[Ljava/lang/String;" -> {
                    return new Arr(((String) recv).split((String) args[0]));
                }
                case "replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;" -> {
                    return ((String) recv).replace(String.valueOf(unwrap(args[0])),
                            String.valueOf(unwrap(args[1])));
                }
                case "replace(CC)Ljava/lang/String;" -> {
                    return ((String) recv).replace((char)(int)(Integer) args[0],
                            (char)(int)(Integer) args[1]);
                }
                case "join(Ljava/lang/CharSequence;[Ljava/lang/Object;)Ljava/lang/String;" -> {
                    Object ao = args[1] instanceof Arr a ? a.data : unwrap(args[1]);
                    CharSequence[] parts = new CharSequence[((Object[]) ao).length];
                    for (int i = 0; i < parts.length; i++)
                        parts[i] = String.valueOf(unwrap(((Object[]) ao)[i]));
                    return String.join(String.valueOf(unwrap(args[0])), parts);
                }
            }
            throw new Bail("String:" + mi.name + mi.desc);
        }
        if (mi.owner.equals("java/lang/StringBuilder") && recv instanceof StringBuilder sb) {
            switch (mi.name + mi.desc) {
                case "<init>()V", "<init>(I)V", "<init>(Ljava/lang/String;)V" -> { return null; }
                case "append(Ljava/lang/String;)Ljava/lang/StringBuilder;" -> { sb.append((String) args[0]); return sb; }
                case "append(I)Ljava/lang/StringBuilder;" -> { sb.append((Integer) args[0]); return sb; }
                case "append(J)Ljava/lang/StringBuilder;" -> { sb.append((Long) args[0]); return sb; }
                case "append(C)Ljava/lang/StringBuilder;" -> { sb.append((char) (int) (Integer) args[0]); return sb; }
                case "append(Ljava/lang/Object;)Ljava/lang/StringBuilder;" -> { sb.append(unwrap(args[0])); return sb; }
                case "toString()Ljava/lang/String;" -> { return sb.toString(); }
                case "length()I" -> { return sb.length(); }
                case "setLength(I)V" -> { sb.setLength((Integer) args[0]); return null; }
                case "charAt(I)C" -> { return (int) sb.charAt((Integer) args[0]); }
                case "setCharAt(IC)V" -> { sb.setCharAt((Integer) args[0], (char)(int)(Integer) args[1]); return null; }
                case "delete(II)Ljava/lang/StringBuilder;" -> {
                    sb.delete((Integer) args[0], (Integer) args[1]); return sb;
                }
                case "deleteCharAt(I)Ljava/lang/StringBuilder;" -> {
                    sb.deleteCharAt((Integer) args[0]); return sb;
                }
                case "reverse()Ljava/lang/StringBuilder;" -> { sb.reverse(); return sb; }
                case "insert(ILjava/lang/String;)Ljava/lang/StringBuilder;" -> {
                    sb.insert((int)(Integer) args[0], (String) args[1]); return sb;
                }
                case "insert(IC)Ljava/lang/StringBuilder;" -> {
                    sb.insert((int)(Integer) args[0], (char)(int)(Integer) args[1]); return sb;
                }
                case "append([C)Ljava/lang/StringBuilder;" -> {
                    Object ch = args[0] instanceof Arr a ? a.data : unwrap(args[0]);
                    sb.append((char[]) ch); return sb;
                }
                case "append(Z)Ljava/lang/StringBuilder;" -> {
                    Object b0 = args[0];
                    sb.append(b0 instanceof Integer ? ((Integer) b0) != 0 : (Boolean) unwrap(b0));
                    return sb;
                }
            }
            throw new Bail("SB:" + mi.name);
        }
        if (mi.owner.equals("java/lang/StringBuffer") && recv instanceof StringBuffer sb) {
            switch (mi.name + mi.desc) {
                case "<init>()V" -> { return null; }
                case "append(Ljava/lang/String;)Ljava/lang/StringBuffer;" -> { sb.append((String) args[0]); return sb; }
                case "toString()Ljava/lang/String;" -> { return sb.toString(); }
            }
            throw new Bail("SBuf:" + mi.name);
        }
        if (mi.owner.equals("java/util/Iterator")) {
            if (recv instanceof It it) {
                if (mi.name.equals("hasNext") && mi.desc.equals("()Z"))
                    return it.i < it.l.size() ? 1 : 0;
                if (mi.name.equals("next") && mi.desc.equals("Ljava/lang/Object;")) {
                    if (it.i >= it.l.size()) throw new Bail("iterator-bos");
                    return wrap(it.l.get(it.i++));
                }
                if (mi.name.equals("remove") && mi.desc.equals("()V")) { return null; }
            }
        }
        if (mi.owner.equals("java/util/List") || mi.owner.equals("java/util/Collection")
                || mi.owner.equals("java/lang/Iterable") || mi.owner.equals("java/util/Set")) {
            List<Object> asList = null;
            if (recv instanceof ArrayList al) asList = al;
            else if (recv instanceof Arr a && a.data instanceof Object[] o) asList = Arrays.asList(o);
            if (asList != null) {
                if (mi.name.equals("iterator") && mi.desc.equals("()Ljava/util/Iterator;"))
                    return new It(asList, 0);
                if (mi.name.equals("size") && mi.desc.equals("()I")) return asList.size();
                if (mi.name.equals("isEmpty") && mi.desc.equals("()Z")) return asList.isEmpty() ? 1 : 0;
                if (mi.name.equals("get") && mi.desc.equals("(I)Ljava/lang/Object;"))
                    return wrap(asList.get((Integer) args[0]));
                if (mi.name.equals("toArray") && mi.desc.equals("()[Ljava/lang/Object;"))
                    return new Arr(asList.toArray());
            }
        }
        if (mi.owner.equals("java/util/ArrayList")) {
            if (mi.name.equals("<init>")) return new ArrayList<>();
            if (recv instanceof ArrayList l) {
                switch (mi.name + mi.desc) {
                    case "add(Ljava/lang/Object;)Z" -> { return l.add(unwrap(args[0])) ? 1 : 0; }
                    case "get(I)Ljava/lang/Object;" -> { return wrap(l.get((Integer) args[0])); }
                    case "size()I" -> { return l.size(); }
                    case "toArray()[Ljava/lang/Object;" -> { return new Arr(l.toArray()); }
                    case "isEmpty()Z" -> { return l.isEmpty() ? 1 : 0; }
                }
            }
            throw new Bail("ArrayList:" + mi.name + mi.desc);
        }
        if (mi.owner.equals("java/util/HashMap")) {
            if (mi.name.equals("<init>")) return new HashMap<>();
            if (recv instanceof HashMap m) {
                switch (mi.name + mi.desc) {
                    case "put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" ->
                        { return wrap(m.put(unwrap(args[0]), unwrap(args[1]))); }
                    case "get(Ljava/lang/Object;)Ljava/lang/Object;" ->
                        { return wrap(m.get(unwrap(args[0]))); }
                    case "size()I" -> { return m.size(); }
                    case "containsKey(Ljava/lang/Object;)Z" ->
                        { return m.containsKey(unwrap(args[0])) ? 1 : 0; }
                }
            }
            throw new Bail("HashMap:" + mi.name + mi.desc);
        }
        if (mi.owner.equals("java/util/HashSet")) {
            if (mi.name.equals("<init>")) return new HashSet<>();
            throw new Bail("HashSet:" + mi.name);
        }
        if (mi.owner.equals("java/util/Arrays")) {
            if (mi.name.equals("asList") && mi.desc.equals("([Ljava/lang/Object;)Ljava/util/List;")) {
                Object ao = args[0];
                Object[] arr = ao instanceof Arr a ? (Object[]) a.data : (Object[]) ao;
                return new ArrayList<>(Arrays.asList(arr));
            }
            if ((mi.name.equals("copyOf") || mi.name.equals("copyOfRange")) && op == Opcodes.INVOKESTATIC)
                return arraysCopy(mi, args);
            if (mi.name.equals("fill") && op == Opcodes.INVOKESTATIC && arraysFill(mi, args)) return null;
            if (mi.name.equals("equals") && args.length == 2 && arraysEquals(args)) return 1;
            if (mi.name.equals("equals") && args.length == 2) return 0;
            if (mi.name.equals("toString") && args.length == 1) {
                Object ao = arrayData(args[0]);
                if (ao instanceof int[] x) return Arrays.toString(x);
                if (ao instanceof long[] x) return Arrays.toString(x);
                if (ao instanceof byte[] x) return Arrays.toString(x);
                if (ao instanceof char[] x) return Arrays.toString(x);
                if (ao instanceof Object[] x) return Arrays.toString(x);
            }
            if (mi.name.equals("copyOf") || mi.name.equals("copyOfRange")) throw new Bail("Arrays:" + mi.name);
            throw new Bail("Arrays:" + mi.name);
        }
        if (mi.owner.equals("java/lang/System")
                && mi.name.equals("arraycopy")
                && mi.desc.equals("(Ljava/lang/Object;ILjava/lang/Object;II)V")) {
            Object src = arrayData(args[0]);
            int sp = (Integer) args[1];
            Object dst = arrayData(args[2]);
            int dp = (Integer) args[3], ln = (Integer) args[4];
            try {
                System.arraycopy(src, sp, dst, dp, ln);
            } catch (Exception e) { throw new Bail("arraycopy"); }
            return null;
        }
        if (mi.owner.equals("java/lang/Integer")) {
            if (mi.name.equals("valueOf") && mi.desc.equals("(I)Ljava/lang/Integer;")) return args[0];
            if (mi.name.equals("intValue") && mi.desc.equals("()I")) return recv;
            if (mi.name.equals("parseInt") ) return Integer.parseInt((String) args[0]);
            if (mi.name.equals("compare") && mi.desc.equals("(II)I"))
                return Integer.compare((Integer) args[0], (Integer) args[1]);
            if (mi.name.equals("toString") && mi.desc.equals("(I)Ljava/lang/String;"))
                return Integer.toString((Integer) args[0]);
            if (mi.name.equals("toString") && mi.desc.equals("(II)Ljava/lang/String;"))
                return Integer.toString((Integer) args[0], (Integer) args[1]);
            if (mi.name.equals("toHexString") && mi.desc.equals("(I)Ljava/lang/String;"))
                return Integer.toHexString((Integer) args[0]);
            if (mi.name.equals("hashCode") && mi.desc.equals("()I")) return recv.hashCode();
            throw new Bail("Integer:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Long")) {
            if (mi.name.equals("valueOf") && mi.desc.equals("(J)Ljava/lang/Long;")) return args[0];
            if (mi.name.equals("longValue") && mi.desc.equals("()J")) return recv;
            if (mi.name.equals("parseLong") && mi.desc.startsWith("(Ljava/lang/String;"))
                return args.length == 2 ? Long.parseLong((String) args[0], (Integer) args[1])
                        : Long.parseLong((String) args[0]);
            if (mi.name.equals("toString") && mi.desc.equals("(J)Ljava/lang/String;"))
                return Long.toString((Long) args[0]);
            if (mi.name.equals("toString") && mi.desc.equals("()Ljava/lang/String;"))
                return recv.toString();
            if (mi.name.equals("compare") && mi.desc.equals("(JJ)I"))
                return Long.compare((Long) args[0], (Long) args[1]);
            if (mi.name.equals("toHexString") && mi.desc.equals("(J)Ljava/lang/String;"))
                return Long.toHexString((Long) args[0]);
            if (mi.name.equals("hashCode") && mi.desc.equals("()I")) return recv.hashCode();
            throw new Bail("Long:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Float")) {
            if (mi.name.equals("valueOf") && mi.desc.equals("(F)Ljava/lang/Float;")) return args[0];
            if (mi.name.equals("floatValue") && mi.desc.equals("()F")) return recv;
            if (mi.name.equals("intValue") && mi.desc.equals("()I")) return (int) (float)(Float) recv;
            if (mi.name.equals("isNaN") && mi.desc.equals("(F)Z"))
                return Float.isNaN(toFloat(args[0])) ? 1 : 0;
            if (mi.name.equals("compare") && mi.desc.equals("(FF)I"))
                return Float.compare(toFloat(args[0]), toFloat(args[1]));
            throw new Bail("Float:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Double")) {
            if (mi.name.equals("valueOf") && mi.desc.equals("(D)Ljava/lang/Double;")) return args[0];
            if (mi.name.equals("doubleValue") && mi.desc.equals("()D")) return recv;
            if (mi.name.equals("intValue") && mi.desc.equals("()I")) return (int) (double)(Double) recv;
            if (mi.name.equals("longValue") && mi.desc.equals("()J")) return (long) (double)(Double) recv;
            if (mi.name.equals("isNaN") && mi.desc.equals("(D)Z"))
                return Double.isNaN(toDouble(args[0])) ? 1 : 0;
            if (mi.name.equals("compare") && mi.desc.equals("(DD)I"))
                return Double.compare(toDouble(args[0]), toDouble(args[1]));
            throw new Bail("Double:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Character")) {
            if (mi.name.equals("valueOf") && mi.desc.equals("(C)Ljava/lang/Character;") && args[0] instanceof Integer)
                return (char)(int)(Integer) args[0];
            if (mi.name.equals("charValue") && mi.desc.equals("()C")) {
                if (recv instanceof Integer) return recv;
                if (recv instanceof Character) return (int)(Character) recv;
                return recv;
            }
            throw new Bail("Character:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Boolean")) {
            if (mi.name.equals("valueOf") && mi.desc.equals("(Z)Ljava/lang/Boolean;"))
                return args[0] instanceof Integer ? ((Integer) args[0]) != 0 : args[0];
            if (mi.name.equals("booleanValue") && mi.desc.equals("()Z"))
                return recv instanceof Boolean ? ((Boolean) recv ? 1 : 0) : recv;
            throw new Bail("Boolean:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Math")) {
            try {
                return switch (mi.name + mi.desc) {
                    case "abs(I)I" -> Math.abs((Integer) args[0]);
                    case "abs(J)J" -> Math.abs((Long) args[0]);
                    case "abs(F)F" -> Math.abs(toFloat(args[0]));
                    case "abs(D)D" -> Math.abs(toDouble(args[0]));
                    case "min(II)I" -> Math.min((Integer) args[0], (Integer) args[1]);
                    case "max(II)I" -> Math.max((Integer) args[0], (Integer) args[1]);
                    case "min(JJ)J" -> Math.min((Long) args[0], (Long) args[1]);
                    case "max(JJ)J" -> Math.max((Long) args[0], (Long) args[1]);
                    default -> throw new Bail("Math:" + mi.name + mi.desc);
                };
            } catch (Bail b) { throw b; }
            catch (RuntimeException e) { throw new Bail("Math:" + mi.name); }
        }
        if (mi.owner.equals("java/util/Objects")) {
            if (mi.name.equals("requireNonNull") && at.length == 1) {
                if (unwrap(args[0]) == null) throw new Bail("npe-requireNonNull");
                return args[0];
            }
            if (mi.name.equals("equals") && mi.desc.equals("(Ljava/lang/Object;Ljava/lang/Object;)Z")) {
                Object a = unwrap(args[0]), b = unwrap(args[1]);
                return java.util.Objects.equals(a, b) ? 1 : 0;
            }
            throw new Bail("Objects:" + mi.name);
        }
        if (mi.owner.equals("javax/crypto/Cipher")) {
            return invokeCipher(mi, args, recv);
        }
        if (mi.owner.equals("javax/crypto/SecretKeyFactory")) {
            if (mi.name.equals("getInstance") && mi.desc.equals("(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;"))
                return new Obj("javax/crypto/SecretKeyFactory|" + args[0]);
            if (recv instanceof Obj o && mi.name.equals("generateSecret")) return args[0];
            throw new Bail("SecretKeyFactory:" + mi.name);
        }
        if (mi.owner.equals("javax/crypto/spec/DESKeySpec")) {
            if (mi.name.equals("<init>")) return args[0];
            throw new Bail("DESKeySpec:" + mi.name);
        }
        if (mi.owner.equals("javax/crypto/spec/IvParameterSpec")) {
            if (mi.name.equals("<init>")) return args[0];
            throw new Bail("IvParameterSpec:" + mi.name);
        }
        if (mi.owner.equals("java/lang/Thread")) {
            if (mi.name.equals("currentThread")) return Thread.currentThread();
            throw new Bail("Thread:" + mi.name);
        }
        if (k.equals("java/lang/Object.<init>()V")) return null;
        if (mi.owner.equals("java/lang/System")) {
            if (mi.name.equals("getProperty") && mi.desc.equals("(Ljava/lang/String;)Ljava/lang/String;")) {
                String v = System.getProperty((String) args[0]);
                return v == null ? NULL : v;
            }
            if (mi.name.equals("lineSeparator") && mi.desc.equals("()Ljava/lang/String;"))
                return System.lineSeparator();
            if (mi.name.equals("identityHashCode")) return System.identityHashCode(unwrap(args[0]));
            if (mi.name.equals("arraycopy")) {
                Object src = arrayData(args[0]);
                int sp = (Integer) args[1];
                Object dst = arrayData(args[2]);
                int dp = (Integer) args[3], ln = (Integer) args[4];
                try {
                    System.arraycopy(src, sp, dst, dp, ln);
                } catch (Exception e) { throw new Bail("arraycopy"); }
                return null;
            }
            throw new Bail("System:" + mi.name);
        }

        if (mi.owner.equals("java/lang/Class")) {
            if (mi.name.equals("forName") && ctx.loader != null) {
                try {
                    return Class.forName((String) args[0], false, ctx.loader);
                } catch (Exception e) { throw new Bail("forName"); }
            }
            if (mi.name.equals("getName")) return ((Class<?>) recv).getName();
            if (mi.name.equals("getSuperclass")) {
                Class<?> sc = ((Class<?>) recv).getSuperclass();
                return sc == null ? NULL : sc;
            }
            if (mi.name.equals("getSimpleName")) return ((Class<?>) recv).getSimpleName();
            if (mi.name.equals("getCanonicalName")) {
                String cns = ((Class<?>) recv).getCanonicalName();
                return cns == null ? NULL : cns;
            }
            if (mi.name.equals("isArray")) return ((Class<?>) recv).isArray() ? 1 : 0;
            if (mi.name.equals("isPrimitive")) return ((Class<?>) recv).isPrimitive() ? 1 : 0;
            if (mi.name.equals("getComponentType")) {
                Class<?> cc = ((Class<?>) recv).getComponentType();
                return cc == null ? NULL : cc;
            }
            if (mi.name.equals("getClassLoader")) return wrap(ctx.loader);
            if (mi.name.equals("desiredAssertionStatus")) return 0;
            if (mi.name.equals("getDeclaredFields")) return new Arr(((Class<?>) recv).getDeclaredFields());
            if (mi.name.equals("getDeclaredMethods")) return new Arr(((Class<?>) recv).getDeclaredMethods());
            if (mi.name.equals("getInterfaces")) return new Arr(((Class<?>) recv).getInterfaces());
            throw new Bail("Class:" + mi.name);
        }
        if (mi.owner.equals("java/lang/reflect/Field")) {
            java.lang.reflect.Field f = (java.lang.reflect.Field) recv;
            switch (mi.name + mi.desc) {
                case "getName()Ljava/lang/String;" -> { return f.getName(); }
                case "getType()Ljava/lang/Class;" -> { return f.getType(); }
                case "getModifiers()I" -> { return f.getModifiers(); }
                case "setAccessible(Z)V" -> { f.setAccessible(toBool(args[0])); return null; }
                case "get(Ljava/lang/Object;)Ljava/lang/Object;" -> {
                    try { return wrap(f.get(unwrap(args[0]))); }
                    catch (Exception e) { throw new Bail("Field-get"); }
                }
                case "getInt(Ljava/lang/Object;)I" -> {
                    try { return f.getInt(unwrap(args[0])); }
                    catch (Exception e) { throw new Bail("Field-getInt"); }
                }
                case "getLong(Ljava/lang/Object;)J" -> {
                    try { return f.getLong(unwrap(args[0])); }
                    catch (Exception e) { throw new Bail("Field-getLong"); }
                }
                case "set(Ljava/lang/Object;Ljava/lang/Object;)V" -> {
                    try { f.set(unwrap(args[0]), unwrap(args[1])); return null; }
                    catch (Exception e) { throw new Bail("Field-set"); }
                }
            }
            throw new Bail("Field:" + mi.name);
        }
        if (mi.owner.equals("java/lang/reflect/Method")) {
            java.lang.reflect.Method mm = (java.lang.reflect.Method) recv;
            switch (mi.name + mi.desc) {
                case "getName()Ljava/lang/String;" -> { return mm.getName(); }
                case "getModifiers()I" -> { return mm.getModifiers(); }
                case "getParameterCount()I" -> { return mm.getParameterCount(); }
                case "setAccessible(Z)V" -> { mm.setAccessible(toBool(args[0])); return null; }
                case "getParameterTypes()[Ljava/lang/Class;" -> {
                    return new Arr(((java.lang.reflect.Method) recv).getParameterTypes());
                }
                case "getReturnType()Ljava/lang/Class;" -> { return mm.getReturnType(); }
                case "getDeclaringClass()Ljava/lang/Class;" -> { return mm.getDeclaringClass(); }
            }
            throw new Bail("Method:" + mi.name);
        }

        if (op == Opcodes.INVOKESTATIC && mi.owner.equals(cn.name)) {
            MethodNode tgt = ClassIO.findMethod(cn, mi.name, mi.desc);
            if (tgt != null) {
                Object[] unwrapped = new Object[args.length];
                for (int i = 0; i < args.length; i++) unwrapped[i] = unwrap(args[i]);
                Object r = run(new Ctx(ctx.classes, ctx.loader, ctx.depth + 1,
                        ctx.clinitRunning, ctx.statics), cn, tgt, unwrapped);
                return wrap(r);
            }
            throw new Bail("helper-missing:" + mi.name);
        }
        throw new Bail("cagri:" + k);
    }

    static Object unwrap(Object o) { return o == NULL ? null : o; }
    static Object wrap(Object o) { return o == null ? NULL : o; }

    static final class It {
        final List<Object> l;
        int i;
        It(List<Object> l, int i) { this.l = l; this.i = i; }
    }

    private static String lastBail = "";
    public static String lastBail() { return lastBail; }

    public static Map<String, Object> emulateClinit(Map<String, ClassNode> classes,
                                                   ClassLoader loader, ClassNode cn) {
        try {
            Ctx ctx = new Ctx(classes, loader, 0);
            MethodNode cl = ClassIO.findMethod(cn, "<clinit>", "()V");
            if (cl == null) return null;
            run(ctx, cn, cl, new Object[0]);
            lastBail = "";
            return ctx.statics;
        } catch (Bail b) {
            lastBail = b.getMessage();
            return null;
        }
    }

    private static boolean toBool(Object o) {
        Object u = unwrap(o);
        if (u instanceof Boolean b) return b;
        if (u instanceof Integer i) return i != 0;
        throw new Bail("bool-tip");
    }

    private static float toFloat(Object o) {
        if (o instanceof Float f) return f;
        if (o instanceof Integer i) return i;
        if (o instanceof Long l) return l;
        if (o instanceof Double d) return d.floatValue();
        throw new Bail("float-tip");
    }

    private static double toDouble(Object o) {
        if (o instanceof Double d) return d;
        if (o instanceof Float f) return f;
        if (o instanceof Integer i) return i;
        if (o instanceof Long l) return l;
        throw new Bail("double-tip");
    }

    private static Object arrayData(Object o) {
        if (o instanceof Arr a) return a.data;
        return o;
    }

    private static Object arraysCopy(MethodInsnNode mi, Object[] args) {
        if (mi.name.equals("copyOf")) {
            int n = (Integer) args[1];
            Object src = arrayData(args[0]);
            if (src instanceof int[] x) return new Arr(Arrays.copyOf(x, n));
            if (src instanceof long[] x) return new Arr(Arrays.copyOf(x, n));
            if (src instanceof byte[] x) return new Arr(Arrays.copyOf(x, n));
            if (src instanceof char[] x) return new Arr(Arrays.copyOf(x, n));
            if (src instanceof Object[] x) return new Arr(Arrays.copyOf(x, n));
        } else {
            int f = (Integer) args[1], t = (Integer) args[2];
            Object src = arrayData(args[0]);
            if (src instanceof int[] x) return new Arr(Arrays.copyOfRange(x, f, t));
            if (src instanceof long[] x) return new Arr(Arrays.copyOfRange(x, f, t));
            if (src instanceof byte[] x) return new Arr(Arrays.copyOfRange(x, f, t));
            if (src instanceof char[] x) return new Arr(Arrays.copyOfRange(x, f, t));
            if (src instanceof Object[] x) return new Arr(Arrays.copyOfRange(x, f, t));
        }
        throw new Bail("Arrays-kopya");
    }

    private static boolean arraysFill(MethodInsnNode mi, Object[] args) {
        Object arr = arrayData(args[0]);
        if (arr instanceof int[] x && args[1] instanceof Integer v) { Arrays.fill(x, v); return true; }
        if (arr instanceof long[] x && args[1] instanceof Long v) { Arrays.fill(x, v); return true; }
        if (arr instanceof byte[] x && args[1] instanceof Integer v) {
            Arrays.fill(x, v.byteValue()); return true;
        }
        if (arr instanceof char[] x && args[1] instanceof Integer v) {
            Arrays.fill(x, (char)(int) v); return true;
        }
        if (arr instanceof Object[] x) { Arrays.fill(x, unwrap(args[1])); return true; }
        return false;
    }

    private static boolean arraysEquals(Object[] args) {
        Object a = arrayData(args[0]), b = arrayData(args[1]);
        if (a instanceof int[] x && b instanceof int[] y) return Arrays.equals(x, y);
        if (a instanceof long[] x && b instanceof long[] y) return Arrays.equals(x, y);
        if (a instanceof byte[] x && b instanceof byte[] y) return Arrays.equals(x, y);
        if (a instanceof char[] x && b instanceof char[] y) return Arrays.equals(x, y);
        if (a instanceof Object[] x && b instanceof Object[] y) return Arrays.equals(x, y);
        return false;
    }

    private static String buildString(String desc, Object[] ag) {
        try {
            return switch (desc) {
                case "()V" -> "";
                case "([C)V" -> {
                    Object ch = ag[0] instanceof Arr a ? a.data : unwrap(ag[0]);
                    yield new String((char[]) ch);
                }
                case "([CII)V" -> {
                    Object ch = ag[0] instanceof Arr a ? a.data : unwrap(ag[0]);
                    yield new String((char[]) ch, (Integer) ag[1], (Integer) ag[2]);
                }
                case "(Ljava/lang/String;)V" -> String.valueOf(unwrap(ag[0]));
                case "([B)V" -> {
                    Object b = ag[0] instanceof Arr a ? a.data : unwrap(ag[0]);
                    yield new String((byte[]) b, java.nio.charset.StandardCharsets.ISO_8859_1);
                }
                case "([BLjava/lang/String;)V" -> {
                    Object b = ag[0] instanceof Arr a ? a.data : unwrap(ag[0]);
                    yield new String((byte[]) b, (String) ag[1]);
                }
                case "([BIILjava/lang/String;)V" -> {
                    Object b = ag[0] instanceof Arr a ? a.data : unwrap(ag[0]);
                    yield new String((byte[]) b, (Integer) ag[1], (Integer) ag[2], (String) ag[3]);
                }
                default -> throw new Bail("String-init-desc:" + desc);
            };
        } catch (Bail b) { throw b; }
        catch (RuntimeException e) { throw new Bail("String-init-deger"); }
        catch (Exception e) { throw new Bail("String-init-charset"); }
    }

    private static Object handleInit(MethodInsnNode mi, Object[] args, Object recv) {
        if (mi.owner.equals("java/lang/Object")) return null;
        if (mi.owner.equals("java/lang/StringBuilder") || mi.owner.equals("java/lang/StringBuffer")
                || mi.owner.equals("java/util/ArrayList") || mi.owner.equals("java/util/HashMap")
                || mi.owner.equals("java/util/HashSet")) return null;
        if (recv instanceof Obj) return null;
        if (recv instanceof StringBuilder || recv instanceof StringBuffer
                || recv instanceof ArrayList || recv instanceof HashMap || recv instanceof HashSet)
            return null;
        if (mi.owner.equals("java/lang/Throwable") || mi.owner.endsWith("Exception")
                || mi.owner.endsWith("Error")) return null;
        return null;
    }

    private static final class CipherState {
        String xform = "DES/CBC/PKCS5Padding";
        int mode = -1;
        byte[] key;
        byte[] iv = new byte[8];
    }

    private static Object invokeCipher(MethodInsnNode mi, Object[] args, Object recv) {
        if (mi.name.equals("getInstance")) {
            CipherState cs = new CipherState();
            if (args.length >= 1 && args[0] instanceof String s) cs.xform = s;
            return cs;
        }
        if (!(recv instanceof CipherState cs)) throw new Bail("Cipher-alici");
        switch (mi.name + mi.desc) {
            case "init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
                 "init(ILjava/security/Key;)V" -> {
                cs.mode = (Integer) args[0];
                cs.key = keyBytes(args[1]);
                if (args.length >= 3) cs.iv = ivBytes(args[2]);
                else cs.iv = new byte[8];
                return null;
            }
            case "doFinal([B)[B" -> {
                try {
                    byte[] data = (byte[]) arrayData(args[0]);
                    javax.crypto.Cipher ch = javax.crypto.Cipher.getInstance(cs.xform);
                    javax.crypto.SecretKeyFactory f = javax.crypto.SecretKeyFactory.getInstance("DES");
                    ch.init(cs.mode == javax.crypto.Cipher.DECRYPT_MODE
                                    ? javax.crypto.Cipher.DECRYPT_MODE : javax.crypto.Cipher.ENCRYPT_MODE,
                            f.generateSecret(new javax.crypto.spec.DESKeySpec(cs.key)),
                            new javax.crypto.spec.IvParameterSpec(cs.iv));
                    return new Arr(ch.doFinal(data));
                } catch (Bail b) { throw b; }
                catch (Exception e) { throw new Bail("Cipher-doFinal"); }
            }
            default -> throw new Bail("Cipher:" + mi.name + mi.desc);
        }
    }

    private static byte[] keyBytes(Object k) {
        if (k instanceof byte[] b) return b;
        if (k instanceof Arr a && a.data instanceof byte[] b) return b;
        if (k instanceof javax.crypto.spec.SecretKeySpec sk) return sk.getEncoded();
        Object u = unwrap(k);
        if (u instanceof byte[] b) return b;
        throw new Bail("Cipher-key");
    }

    private static byte[] ivBytes(Object v) {
        if (v instanceof byte[] b) return b;
        if (v instanceof Arr a && a.data instanceof byte[] b) return b;
        Object u = unwrap(v);
        if (u instanceof byte[] b) return b;
        if (u instanceof Obj) return new byte[8];
        throw new Bail("Cipher-iv");
    }

    private static Object multiArray(String desc, int[] counts, int dim) {
        int n = counts[dim];
        if (n < 0) throw new Bail("multianewarray-negatif");
        char e = desc.charAt(dim + 1);
        if (dim == counts.length - 1) {
            return switch (e) {
                case 'Z' -> new boolean[n];
                case 'C' -> new char[n];
                case 'F' -> new float[n];
                case 'D' -> new double[n];
                case 'B' -> new byte[n];
                case 'S' -> new short[n];
                case 'I' -> new int[n];
                case 'J' -> new long[n];
                default -> new Object[n];
            };
        }
        Object[] outer = new Object[n];
        for (int i = 0; i < n; i++) outer[i] = multiArray(desc, counts, dim + 1);
        return outer;
    }
}
