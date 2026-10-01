package com.demo;

public class Worker {
    static final int MAGIC = 0x12345678;
    static final long BIG = 0x1122334455667788L;

    public static String run(String tag) {
        StringBuilder sb = new StringBuilder();
        sb.append(greet(tag)).append('|');
        sb.append("magic=").append(MAGIC).append('|');
        sb.append("big=").append(BIG).append('|');
        sb.append("grade=").append(grade(87)).append('|');
        sb.append("ex=").append(withException(5));
        return sb.toString();
    }

    public static int calc(int a, int b) {
        int r = a * b + 1000;
        if (r > 1000) r -= 7;
        return r;
    }

    public static String cat(String x, String y) {
        return x + "-mid-" + y;
    }

    static String greet(String tag) {
        if (tag == null || tag.length() == 0) {
            return "empty-tag";
        }
        return "hello-" + tag + "-secret-sauce";
    }

    static String grade(int score) {
        if (score >= 90) return "A-excellent";
        else if (score >= 80) return "B-good";
        else if (score >= 70) return "C-average";
        else if (score >= 60) return "D-poor";
        return "F-fail";
    }

    static String withException(int x) {
        try {
            if (x < 0) throw new IllegalArgumentException("negative-input");
            return "ok-" + (100 / (x - x + 1));
        } catch (RuntimeException e) {
            return "caught-" + e.getMessage();
        }
    }
}
