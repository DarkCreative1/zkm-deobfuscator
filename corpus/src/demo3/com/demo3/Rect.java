package com.demo3;

/** Ikinci somut sinif: cok parametre, enum switch, bit islemleri, varargs. */
public class Rect implements Shape {
    public enum Kind {
        SMALL, MEDIUM, LARGE;

        public int weight() {
            return ordinal() * 10 + 5;
        }
    }

    private final double w;
    private final double h;
    private final Kind kind;

    public Rect(double w, double h) {
        this(w, h, w * h > 100 ? Kind.LARGE : Kind.SMALL);
    }

    public Rect(double w, double h, Kind kind) {
        if (w <= 0 || h <= 0) throw new BadShape("kenar:" + w + "x" + h);
        this.w = w;
        this.h = h;
        this.kind = kind;
    }

    @Override
    public double area() {
        return w * h;
    }

    @Override
    public String kind() {
        switch (kind) {
            case SMALL:
                return "rect-s";
            case MEDIUM:
                return "rect-m";
            case LARGE:
            default:
                return "rect-l";
        }
    }

    public double perimeter() {
        return 2 * (w + h);
    }

    /** varargs + toplam */
    public static double total(double... values) {
        double s = 0;
        for (double v : values) s += v;
        return s;
    }

    /** bit islemleri + shift + unsigned */
    public static long mix(long v) {
        long r = (v << 13) | (v >>> 51);
        r ^= 0x5DEECE66DL;
        r = (r & 0xFFFFL) | ((r >>> 16) << 32);
        return r ^ kindWeight(Kind.MEDIUM);
    }

    static long kindWeight(Kind k) {
        return (long) k.weight() * 0x10001L;
    }
}
