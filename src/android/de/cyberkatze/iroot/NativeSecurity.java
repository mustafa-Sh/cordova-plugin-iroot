package de.cyberkatze.iroot;

import org.apache.cordova.LOG;

public final class NativeSecurity {

    private static final String TAG = "IRootNative";

    private static boolean loaded = false;

    static {
        try {
            LOG.e(TAG, "[NativeSecurity] Loading libirootsecurity.so");

            System.loadLibrary("irootsecurity");

            loaded = true;

            LOG.e(TAG, "[NativeSecurity] libirootsecurity.so loaded successfully");
        } catch (Throwable e) {
            LOG.e(TAG, "[NativeSecurity] Unable to load native security library", e);
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