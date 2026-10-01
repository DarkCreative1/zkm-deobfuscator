package com.demo3;

/** Ozel istisna (seri API'si yok, mesaj zinciri). */
public class BadShape extends RuntimeException {
    public BadShape(String message) {
        super(message);
    }

    public String explain() {
        return "bad-shape<" + getMessage() + ">";
    }
}
