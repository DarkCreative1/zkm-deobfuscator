package com.demo2;

public class Worker {
    static final int MAGIC = 0x12345678;
    static final long BIG = 0x1122334455667788L;
    static int counter = 0;
    private String prefix = "pre-";

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

    static String switchGrade(int score) {
        int band = score / 10;
        switch (band) {
            case 10:
            case 9: return "S-super";
            case 8: return "B-good";
            case 7: return "C-average";
            default:
                if (score >= 60) return "D-poor";
                return "F-fail";
        }
    }

    static String withException(int x) {
        try {
            if (x < 0) throw new IllegalArgumentException("negative-input");
            try {
                return "ok-" + (100 / (x - x + 1));
            } finally {
                counter++;
            }
        } catch (RuntimeException e) {
            return "caught-" + e.getMessage();
        }
    }

    public static long mixLong(long v) {
        long r = v ^ 0x5A5A5A5A5A5A5A5AL;
        r += 9876543210987L;
        r -= 1234567890123L;
        return r;
    }

    public static int loopSum(int n) {
        int s = 0;
        for (int i = 1; i <= n; i++) {
            s += i;
            if (s > 1000000) break;
        }
        int j = 0;
        while (j < 3) {
            s += j;
            j++;
        }
        return s;
    }

    public static String empty() {
        return "";
    }

    public static String unicode() {
        return "merhaba-dunya-\u00e9\u00e7\u00fc\u011f";
    }

    static String overloaded(int x) {
        return "int-" + (x * 2);
    }

    static String overloaded(String s) {
        return "str-" + s + "-!";
    }

    public int instMethod(String s) {
        return (prefix + s).length() + counter;
    }

    public static int multiParam(int a, long b, String c, double d) {
        int r = (int) (a + b + d);
        if (c != null && c.length() > 0) r += 1000;
        return r;
    }

    public static int fieldUser() {
        counter += 10;
        return MAGIC + counter;
    }
}
