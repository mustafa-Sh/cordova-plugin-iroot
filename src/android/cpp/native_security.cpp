#include <jni.h>
#include "runtime_checks.h"

extern "C"
JNIEXPORT jboolean JNICALL
Java_de_cyberkatze_iroot_NativeSecurity_checkRuntime(
        JNIEnv* env,
        jclass clazz) {

    return runRuntimeChecks()
           ? JNI_TRUE
           : JNI_FALSE;
}