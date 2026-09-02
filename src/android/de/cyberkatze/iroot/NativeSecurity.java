package de.cyberkatze.iroot;

import android.util.Log;

public final class NativeSecurity {

    private static boolean loaded = false;

    static {
        try {
            System.err.println(
                "IROOT_TEST_SYSERR: NativeSecurity static block EXECUTED"
            );

            Log.e("IROOT_TEST", "NativeSecurity static block EXECUTED");

            System.loadLibrary("irootsecurity");

            loaded = true;

            System.err.println(
                "IROOT_TEST_SYSERR: libirootsecurity.so LOADED"
            );

            Log.e("IROOT_TEST", "libirootsecurity.so LOADED");
        } catch (Throwable e) {
            System.err.println(
                "IROOT_TEST_SYSERR: libirootsecurity.so LOAD FAILED: " + e
            );
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