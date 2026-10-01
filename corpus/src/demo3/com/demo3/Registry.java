package com.demo3;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** Kapsayici: generics, lambda, method-ref, try-with-resources, ic sinif, sabit dizisi. */
public class Registry implements AutoCloseable {
    private static final String[] KINDS = {"circle", "rect", "square"};
    private static final int MAX = 12;
    private static int instances = 0;

    private final Map<String, Shape> items = new LinkedHashMap<>();
    private final List<String> log = new ArrayList<>();
    private boolean closed;

    public Registry() {
        instances++;
    }

    /** ic (nested) sinif: try-with-resources kaynagi */
    static class Cursor implements AutoCloseable {
        private final String name;
        int seen;

        Cursor(String name) {
            this.name = name;
        }

        String name() {
            return name;
        }

        @Override
        public void close() {
            seen++;
        }
    }

    public static int instances() {
        return instances;
    }

    public void load(double radius, double w, double h) {
        try (Cursor c = new Cursor("load")) {
            items.put(c.name() + "-c", new Circle(radius));
            items.put(c.name() + "-r", new Rect(w, h));
            items.put(c.name() + "-s", Shape.of("square", w, h));
            log.add("cursor-seen=" + (c.seen > 0));
        } catch (BadShape e) {
            log.add("hata:" + e.explain());
        } catch (RuntimeException e) {
            log.add("rt:" + e.getClass().getSimpleName());
        } finally {
            log.add("load-bitti:" + items.size());
        }
    }

    /** lambda + method reference + stream-benzeri zincir */
    public String describeAll() {
        Function<Shape, String> f = Shape::label;
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Shape> e : items.entrySet()) {
            String s = f.apply(e.getValue());
            sb.append(e.getKey()).append('=').append(s).append(';');
        }
        return sb.toString();
    }

    /** toplam alan + korelasyon */
    public double totalArea() {
        double t = 0;
        int i = 0;
        for (Shape s : items.values()) {
            t += s.area();
            i += i + 1;
        }
        return Math.round(t * 1000) / 1000.0 + i * 0.0;
    }

    public List<String> log() {
        return log;
    }

    /** labeled break + do-while */
    public static int spiral(int n) {
        int sum = 0;
        outer:
        for (int i = 0; i < n; i++) {
            int j = 0;
            do {
                if (j > i) continue outer;
                sum += i * j;
                j++;
                if (sum > 1000) break outer;
            } while (j < n);
        }
        return sum;
    }

    /** ozyineleme */
    public static long fib(int n) {
        return n < 2 ? n : fib(n - 1) + fib(n - 2);
    }

    /** cok boyutlu dizi + karakter aritmetigi */
    public static String grid() {
        int[][] g = new int[3][3];
        char base = 'a';
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                g[i][j] = i * 3 + j;
                sb.append((char) (base + g[i][j] % 26));
            }
        }
        return sb + ":" + g[2][2] + ":" + KINDS.length + ":" + MAX;
    }

    @Override
    public void close() {
        closed = true;
    }

    public boolean closed() {
        return closed;
    }
}
