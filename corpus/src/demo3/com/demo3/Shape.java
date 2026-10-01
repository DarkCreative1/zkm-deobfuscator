package com.demo3;

/** Arayuz: default metod + static fabrika + string switch (JDK indy SwitchBootstraps). */
public interface Shape {
    double area();

    String kind();

    default String label() {
        return "shape:" + kind() + ":" + fmt(area());
    }

    static String fmt(double d) {
        long x = Math.round(d * 100.0);
        return (x / 100) + "." + String.format("%02d", Math.abs(x % 100));
    }

    static Shape of(String kind, double a, double b) {
        switch (kind) {
            case "circle":
                return new Circle(a);
            case "rect":
                return new Rect(a, b);
            case "square":
                return new Rect(a, a);
            default:
                return null;
        }
    }
}
