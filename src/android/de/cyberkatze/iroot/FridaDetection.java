package de.cyberkatze.iroot;

import org.apache.cordova.LOG;

import java.io.*;
import java.util.*;

import org.json.JSONObject;

public final class FridaDetection {

    private static final String[] MAPS_SUSPECT_STRINGS = new String[]{
            "frida", "gum-js-loop", "frida-gadget", "libfrida", "re.frida"
    };

    private static final String[] PROCESS_SUSPECT_STRINGS = new String[]{
            "frida-server", "re.frida", "gum-js-loop", "frida"
    };

    private static final String[] FRIDA_FILES = new String[]{
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server"
    };

    private FridaDetection() {}

    public static boolean isFridaDetected() {

        boolean c1 = hasFridaInProcMaps();
        boolean c2 = isFridaServerListeningOnAnyPort();
        boolean c3 = hasFridaFiles();
        boolean c4 = hasFridaProcessRunning();

        LOG.d(Constants.LOG_TAG, "[FridaDetection] maps=" + c1);
        LOG.d(Constants.LOG_TAG, "[FridaDetection] port(any)=" + c2);
        LOG.d(Constants.LOG_TAG, "[FridaDetection] files=" + c3);
        LOG.d(Constants.LOG_TAG, "[FridaDetection] process=" + c4);

        // Banking-grade: block if ANY signal is true
        return c1 || c2 || c3 || c4;
    }

    // -------------------------------------------------
    // 1) Check injected libraries inside app process
    // -------------------------------------------------
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
        } finally {
            closeQuietly(br);
        }
        return false;
    }

    // -------------------------------------------------
    // 2) Detect frida-server listening on ANY port
    // -------------------------------------------------
    private static boolean isFridaServerListeningOnAnyPort() {
        try {
            Map<String, String> inodeToPort = parseListeningSockets("/proc/net/tcp");
            inodeToPort.putAll(parseListeningSockets("/proc/net/tcp6"));

            if (inodeToPort.isEmpty())
                return false;

            File proc = new File("/proc");
            File[] files = proc.listFiles();
            if (files == null)
                return false;

            for (File f : files) {
                if (!f.isDirectory())
                    continue;

                String pid = f.getName();
                if (!pid.matches("\\d+"))
                    continue;

                File fdDir = new File(f, "fd");
                File[] fdFiles = fdDir.listFiles();
                if (fdFiles == null)
                    continue;

                for (File fd : fdFiles) {
                    try {
                        String link = fd.getCanonicalPath();
                        if (link.contains("socket:[")) {
                            String inode = link.substring(
                                    link.indexOf("socket:[") + 8,
                                    link.indexOf("]")
                            );
                            if (inodeToPort.containsKey(inode)) {
                                String cmdline = readCmdline(pid);
                                if (containsSuspect(cmdline))
                                    return true;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }

        } catch (Throwable ignored) {
        }

        return false;
    }

    private static Map<String, String> parseListeningSockets(String path) {
        Map<String, String> inodeMap = new HashMap<>();
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(path));
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.contains(" 0A "))
                    continue; // LISTEN state

                String[] parts = line.trim().split("\\s+");
                if (parts.length < 10)
                    continue;

                String localAddress = parts[1];
                String inode = parts[9];

                int colon = localAddress.indexOf(':');
                if (colon < 0)
                    continue;

                String portHex = localAddress.substring(colon + 1);
                int port = Integer.parseInt(portHex, 16);

                inodeMap.put(inode, String.valueOf(port));
            }
        } catch (Throwable ignored) {
        } finally {
            closeQuietly(br);
        }
        return inodeMap;
    }

    // -------------------------------------------------
    // 3) Check known frida files
    // -------------------------------------------------
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

    // -------------------------------------------------
    // 4) Scan running processes
    // -------------------------------------------------
    private static boolean hasFridaProcessRunning() {
        try {
            File proc = new File("/proc");
            File[] files = proc.listFiles();
            if (files == null)
                return false;

            for (File f : files) {
                if (!f.isDirectory())
                    continue;

                String pid = f.getName();
                if (!pid.matches("\\d+"))
                    continue;

                String cmdline = readCmdline(pid);
                if (containsSuspect(cmdline))
                    return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static String readCmdline(String pid) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/" + pid + "/cmdline"));
            return br.readLine();
        } catch (Throwable ignored) {
        } finally {
            closeQuietly(br);
        }
        return "";
    }

    private static boolean containsSuspect(String value) {
        if (value == null)
            return false;
        String lower = value.toLowerCase(Locale.US);
        for (String s : PROCESS_SUSPECT_STRINGS) {
            if (lower.contains(s))
                return true;
        }
        return false;
    }

    private static void closeQuietly(Closeable c) {
        try {
            if (c != null)
                c.close();
        } catch (Throwable ignored) {}
    }

    // -------------------------------------------------
    // Debug helper
    // -------------------------------------------------
    public static JSONObject getSignals() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("maps", hasFridaInProcMaps());
            obj.put("portAny", isFridaServerListeningOnAnyPort());
            obj.put("files", hasFridaFiles());
            obj.put("process", hasFridaProcessRunning());
        } catch (Exception ignored) {}
        return obj;
    }
}
