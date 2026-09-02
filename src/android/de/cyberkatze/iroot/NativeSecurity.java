package de.cyberkatze.iroot;

import android.util.Log;

public final class NativeSecurity {

    private static boolean loaded = false;

    static {
        try {
            Log.e("IROOT_TEST", "NativeSecurity static block EXECUTED");

            System.loadLibrary("irootsecurity");

            loaded = true;

            Log.e("IROOT_TEST", "libirootsecurity.so LOADED");
        } catch (Throwable e) {
            Log.e("IROOT_TEST", "libirootsecurity.so LOAD FAILED", e);
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