package de.cyberkatze.iroot;

import org.apache.cordova.LOG;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Locale;

public final class FridaDetection {

    private static final int[] FRIDA_PORTS = new int[] { 27042, 27043 };

    private static final String[] MAPS_SUSPECT_STRINGS = new String[] {
            "frida", "gum-js-loop", "frida-gadget", "libfrida", "re.frida"
    };

    private static final String[] FRIDA_FILES = new String[] {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server"
    };

    private FridaDetection() {
    }

    public static boolean isFridaDetected() {
        boolean c1 = hasFridaInProcMaps();
        boolean c2 = isFridaPortOpen();
        boolean c3 = hasFridaFiles();

        LOG.d(Constants.LOG_TAG, String.format(Locale.US,
                "[FridaDetection] maps:%s port:%s files:%s", c1, c2, c3));

        return c1 || c2 || c3;
    }

    private static boolean hasFridaFiles() {
        for (String p : FRIDA_FILES) {
            try {
                if (new File(p).exists())
                    return true;
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static boolean hasFridaInProcMaps() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                for (String s : MAPS_SUSPECT_STRINGS) {
                    if (lower.contains(s))
                        return true;
                }
            }
        } catch (Throwable ignored) {
            // if reading is blocked, don't crash the app—just treat as "not detected" here
        } finally {
            try {
                if (br != null)
                    br.close();
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static boolean isFridaPortOpen() {
        // Parse /proc/net/tcp and look for LISTEN sockets on 27042/27043
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/net/tcp"));
            String line;
            while ((line = br.readLine()) != null) {
                // columns include local_address in hex like 0100007F:69A2
                // LISTEN state is 0A
                if (!line.contains(" 0A "))
                    continue;

                int idx = line.indexOf(':');
                if (idx < 0)
                    continue;

                // local port is after ':' and is hex up to space
                String afterColon = line.substring(idx + 1).trim();
                int space = afterColon.indexOf(' ');
                if (space < 0)
                    continue;

                String portHex = afterColon.substring(0, space);
                int port = Integer.parseInt(portHex, 16);

                for (int fridaPort : FRIDA_PORTS) {
                    if (port == fridaPort)
                        return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try {
                if (br != null)
                    br.close();
            } catch (Throwable ignored) {
            }
        }
        return false;
    }
}
