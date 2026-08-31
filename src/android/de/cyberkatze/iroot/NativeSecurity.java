package de.cyberkatze.iroot;

import org.apache.cordova.LOG;

public final class NativeSecurity {

    private static final String TAG = "IRootNative";

    private static boolean loaded = false;

    static {
        try {
            System.loadLibrary("irootsecurity");
            loaded = true;
        } catch (Throwable e) {
            LOG.e(TAG, "Unable to load native security library", e);
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