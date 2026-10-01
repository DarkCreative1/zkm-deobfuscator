package com.demo3;

import java.util.List;

/** Ana sinif: tum yollari tek ekranda gezdirir (deterministik cikti). */
public class App {
    private static final String TAG = "ZKM-T3";

    public static void main(String[] args) {
        Registry reg = new Registry();
        reg.load(2.0, 3.0, 4.0);

        System.out.println(TAG);
        System.out.println("describe=" + reg.describeAll());
        System.out.println("area=" + Shape.fmt(reg.totalArea()));
        System.out.println("perim=" + Shape.fmt(new Rect(3, 4).perimeter()));
        System.out.println("inst=" + Registry.instances());
        System.out.println("created=" + Circle.created);
        System.out.println("toStr=" + new Circle(1.5));
        System.out.println("base=" + new Circle(1.0).describe());
        System.out.println("total=" + Shape.fmt(Rect.total(1, 2, 3.5, 4.25)));
        System.out.println("mix=" + Rect.mix(123456789L));
        System.out.println("spiral=" + Registry.spiral(8));
        System.out.println("fib=" + Registry.fib(20));
        System.out.println("grid=" + Registry.grid());
        System.out.println("fmt=" + Shape.fmt(3.14159) + "," + Shape.fmt(0.5));

        List<String> log = reg.log();
        for (String s : log) {
            System.out.println("log:" + s);
        }

        // negatif yaricap -> ozel istisna
        try {
            new Circle(-1);
            System.out.println("neg=yakalandi");
        } catch (BadShape e) {
            System.out.println("neg=" + e.explain());
        }

        // coklu catch + yeniden atma
        try {
            try {
                new Rect(0, 5);
            } catch (BadShape inner) {
                throw new IllegalStateException("sarmal:" + inner.getMessage());
            }
        } catch (IllegalStateException e) {
            System.out.println("sar=" + e.getMessage());
        } catch (RuntimeException e) {
            System.out.println("sar-diger");
        }

        // boxing / unboxing / karşılaştırma zinciri
        Integer boxed = 5;
        int unboxed = boxed;
        Long lng = 9000000000L;
        System.out.println("box=" + (boxed + unboxed) + ":" + (lng > 8_000_000_000L));

        // polimorfik dispatch dizi uzerinden
        Shape[] all = {Shape.of("circle", 1, 0), Shape.of("rect", 2, 5), Shape.of("square", 4, 0)};
        for (Shape s : all) {
            System.out.println("poly=" + s.kind() + ":" + Shape.fmt(s.area()));
        }

        // ternary zinciri + toString override
        Object o = (unboxed > 3) ? new Circle(2) : new Rect(1, 1);
        System.out.println("tern=" + o);

        // null yolu
        System.out.println("null=" + (Shape.of("yok", 1, 1) == null));

        reg.close();
        System.out.println("closed=" + reg.closed());
    }
}
