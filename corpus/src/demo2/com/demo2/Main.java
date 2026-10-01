package com.demo2;

public class Main {
    public static void main(String[] args) {
        System.out.println(Worker.run("ZKM-E2E"));
        System.out.println("calc=" + Worker.calc(6, 7));
        System.out.println("cat=" + Worker.cat("foo", "bar"));
        System.out.println("switch=" + Worker.switchGrade(85));
        System.out.println("loop=" + Worker.loopSum(10));
        System.out.println("mix=" + Worker.mixLong(123456789L));
        System.out.println("multi=" + Worker.multiParam(3, 10000000000L, "k", 2.5));
        System.out.println("empty=[" + Worker.empty() + "]");
        System.out.println("uni=" + Worker.unicode());
        System.out.println("over1=" + Worker.overloaded(7));
        System.out.println("over2=" + Worker.overloaded("s"));
        Worker w = new Worker();
        System.out.println("inst=" + w.instMethod("hi"));
        System.out.println("field=" + Worker.fieldUser());
    }
}
