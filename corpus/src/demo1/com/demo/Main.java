package com.demo;

public class Main {
    public static void main(String[] args) {
        System.out.println(Worker.run("ZKM-E2E"));
        System.out.println("calc=" + Worker.calc(6, 7));
        System.out.println("cat=" + Worker.cat("foo", "bar"));
    }
}
