package com.demo3;

/** Ust tip: constructor zinciri + korumali alan (constructor-chain testi). */
public class CircleBase {
    protected final String tag;
    private static final char SEP = ':';

    protected CircleBase(String tag) {
        if (tag == null || tag.isEmpty()) {
            throw new IllegalArgumentException("tag-yok");
        }
        this.tag = tag + SEP;
    }

    public String describe() {
        return "base<" + tag + ">";
    }
}
