package com.demo3;

/** Somut sinif: super nesne cagrisi, alan final, override + toString. */
public class Circle extends CircleBase implements Shape {
    private final double r;
    static int created = 0;

    public Circle(double r) {
        super("circle-base");
        if (r < 0) throw new BadShape("negatif-yaricap:" + r);
        this.r = r;
        created++;
    }

    @Override
    public double area() {
        return Math.PI * r * r;
    }

    @Override
    public String kind() {
        return tag;
    }

    @Override
    public String toString() {
        return "Circle(" + Shape.fmt(r) + ")";
    }

    public double radius() {
        return r;
    }
}
