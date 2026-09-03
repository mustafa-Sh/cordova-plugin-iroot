#include "runtime_checks.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

// ---------------------------------------------------------
// Temporary readable indicators.
//
// IMPORTANT:
// We are intentionally keeping these readable for the first
// functional test. After the native checks are confirmed,
// we will protect/encode them in the hardening stage.
// ---------------------------------------------------------

const std::vector<std::string> MAP_INDICATORS = {
    "frida",
    "frida-gadget",
    "libfrida",
    "gum-js-loop",
    "frida-agent",
    "linjector",
    "memfd:frida",
    "re.frida"
};

const std::vector<std::string> THREAD_INDICATORS = {
    "frida",
    "gum-js-loop",
    "pool-frida",
    "linjector"
};

const std::vector<std::string> FD_INDICATORS = {
    "frida",
    "gum-js-loop",
    "frida-gadget",
    "libfrida",
    "linjector",
    "memfd:frida",
    "re.frida"
};

const std::vector<std::string> KNOWN_ARTIFACTS = {
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    "/system/bin/frida-server",
    "/system/xbin/frida-server"
};

// Default ports commonly used by Frida.
const int SUSPICIOUS_PORTS[] = {
    27042,
    27043
};


// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

std::string toLower(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        }
    );

    return value;
}


bool containsAny(
    const std::string& value,
    const std::vector<std::string>& indicators) {

    if (value.empty()) {
        return false;
    }

    const std::string lower = toLower(value);

    for (const std::string& indicator : indicators) {
        if (lower.find(indicator) != std::string::npos) {
            return true;
        }
    }

    return false;
}


bool fileExists(const char* path) {

    struct stat info {};

    return stat(path, &info) == 0;
}


bool readFirstLine(
    const std::string& path,
    std::string& result) {

    std::ifstream file(path);

    if (!file.is_open()) {
        return false;
    }

    if (!std::getline(file, result)) {
        return false;
    }

    return true;
}


// ---------------------------------------------------------
// 1) Inspect /proc/self/maps
//
// Detect suspicious injected libraries/modules inside
// our own process.
// ---------------------------------------------------------

bool checkProcMaps() {

    std::ifstream maps("/proc/self/maps");

    if (!maps.is_open()) {
        return false;
    }

    std::string line;

    while (std::getline(maps, line)) {

        if (containsAny(line, MAP_INDICATORS)) {
            return true;
        }
    }

    return false;
}


// ---------------------------------------------------------
// 2) Check TracerPid
//
// Detect whether this process is currently being traced.
// ---------------------------------------------------------

bool checkTracerPid() {

    std::ifstream status("/proc/self/status");

    if (!status.is_open()) {
        return false;
    }

    std::string line;

    while (std::getline(status, line)) {

        if (line.rfind("TracerPid:", 0) != 0) {
            continue;
        }

        std::string value =
            line.substr(std::strlen("TracerPid:"));

        value.erase(
                std::remove_if(
                    value.begin(),
                    value.end(),
                    [](unsigned char c) {
                        return std::isspace(c);
                    }
                ),
                value.end()
        );

        if (value.empty()) {
            return false;
        }

        return value != "0";
    }

    return false;
}


// ---------------------------------------------------------
// 3) Inspect native thread names
//
// Reads:
//
// /proc/self/task/<tid>/comm
//
// to detect suspicious instrumentation-related threads.
// ---------------------------------------------------------

bool checkThreads() {

    const char* taskPath = "/proc/self/task";

    DIR* taskDir = opendir(taskPath);

    if (taskDir == nullptr) {
        return false;
    }

    bool detected = false;

    struct dirent* entry;

    while ((entry = readdir(taskDir)) != nullptr) {

        if (entry->d_name[0] == '.') {
            continue;
        }

        bool numeric = true;

        for (const char* p = entry->d_name; *p; ++p) {

            if (!std::isdigit(
                static_cast<unsigned char>(*p))) {

                numeric = false;
                break;
            }
        }

        if (!numeric) {
            continue;
        }

        std::string path =
            std::string(taskPath) +
            "/" +
            entry->d_name +
            "/comm";

        std::string threadName;

        if (!readFirstLine(path, threadName)) {
            continue;
        }

        if (containsAny(
            threadName,
            THREAD_INDICATORS)) {

            detected = true;
            break;
        }
    }

    closedir(taskDir);

    return detected;
}


// ---------------------------------------------------------
// 4) Inspect open file descriptors
//
// Reads symbolic links under:
//
// /proc/self/fd
//
// This can reveal injected modules, memfd objects,
// sockets or other instrumentation artifacts associated
// with the current process.
// ---------------------------------------------------------

bool checkFileDescriptors() {

    const char* fdPath = "/proc/self/fd";

    DIR* fdDir = opendir(fdPath);

    if (fdDir == nullptr) {
        return false;
    }

    bool detected = false;

    struct dirent* entry;

    while ((entry = readdir(fdDir)) != nullptr) {

        if (entry->d_name[0] == '.') {
            continue;
        }

        std::string linkPath =
            std::string(fdPath) +
            "/" +
            entry->d_name;

        char target[PATH_MAX];

        const ssize_t length =
            readlink(
                linkPath.c_str(),
                target,
                sizeof(target) - 1
            );

        if (length <= 0) {
            continue;
        }

        target[length] = '\0';

        std::string resolved(target);

        if (containsAny(
            resolved,
            FD_INDICATORS)) {

            detected = true;
            break;
        }
    }

    closedir(fdDir);

    return detected;
}


// ---------------------------------------------------------
// 5) Known artifact checks
//
// Native equivalent of the file checks currently present
// in FridaDetection.java.
// ---------------------------------------------------------

bool checkKnownArtifacts() {

    for (const std::string& path : KNOWN_ARTIFACTS) {

        if (fileExists(path.c_str())) {
            return true;
        }
    }

    return false;
}


// ---------------------------------------------------------
// 6) Parse /proc/net/tcp or tcp6 looking for listening ports
// ---------------------------------------------------------

bool checkPortFile(const char* path) {

    std::ifstream file(path);

    if (!file.is_open()) {
        return false;
    }

    std::string line;

    // Skip header.
    std::getline(file, line);

    while (std::getline(file, line)) {

        std::istringstream stream(line);

        std::string slot;
        std::string localAddress;
        std::string remoteAddress;
        std::string state;

        if (!(stream
            >> slot
            >> localAddress
            >> remoteAddress
            >> state)) {

            continue;
        }

        // 0A = LISTEN
        if (state != "0A") {
            continue;
        }

        const std::size_t colon =
            localAddress.find(':');

        if (colon == std::string::npos) {
            continue;
        }

        const std::string portHex =
            localAddress.substr(colon + 1);

        char* end = nullptr;

        const long port =
            std::strtol(
                portHex.c_str(),
                &end,
                16
            );

        if (end == portHex.c_str()) {
            continue;
        }

        for (int suspiciousPort : SUSPICIOUS_PORTS) {

            if (port == suspiciousPort) {
                return true;
            }
        }
    }

    return false;
}


bool checkSuspiciousPorts() {

    if (checkPortFile("/proc/net/tcp")) {
        return true;
    }

    if (checkPortFile("/proc/net/tcp6")) {
        return true;
    }

    return false;
}

} // namespace


// ---------------------------------------------------------
// Main native runtime decision
// ---------------------------------------------------------

bool runRuntimeChecks() {

    if (checkProcMaps()) {
        return true;
    }

    if (checkTracerPid()) {
        return true;
    }

    if (checkThreads()) {
        return true;
    }

    if (checkFileDescriptors()) {
        return true;
    }

    if (checkKnownArtifacts()) {
        return true;
    }

    if (checkSuspiciousPorts()) {
        return true;
    }

    return false;
}