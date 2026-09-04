package de.cyberkatze.iroot;

public final class NativeSecurity {

    private static boolean loaded = false;

    static {
        try {
            System.loadLibrary("irootsecurity");
            loaded = true;
        } catch (Throwable ignored) {
            loaded = false;
        }
    }

    private NativeSecurity() {
    }

    public static boolean isAvailable() {
        return loaded;
    }

    public static native boolean checkRuntime();
}