// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// JNI bridge: JVM strings ↔ C strings ↔ Rust FFI (ratls_mobile).

#include <jni.h>
#include <string.h>

// From ratls_mobile static library
extern char *ratls_inspect(const char *host, unsigned short port, const char *ca_cert_path);
extern char *ratls_verify(const char *host, unsigned short port, const char *ca_cert_path,
                          const char *policy_json);
extern char *ratls_post(const char *host, unsigned short port, const char *ca_cert_path,
                        const char *path, const char *body, const char *headers_json);
extern char *ratls_request(const char *method, const char *host, unsigned short port,
                           const char *ca_cert_path, const char *path, const char *body,
                           const char *headers_json);
extern void ratls_free_string(char *ptr);

JNIEXPORT jstring JNICALL
Java_org_privasys_nativeratls_NativeRaTlsBridge_nativeInspect(
    JNIEnv *env, jclass clazz, jstring host, jint port, jstring ca_cert_path) {
    const char *host_c = (*env)->GetStringUTFChars(env, host, NULL);
    const char *ca_c = ca_cert_path ? (*env)->GetStringUTFChars(env, ca_cert_path, NULL) : NULL;

    char *result = ratls_inspect(host_c, (unsigned short)port, ca_c);

    (*env)->ReleaseStringUTFChars(env, host, host_c);
    if (ca_c) (*env)->ReleaseStringUTFChars(env, ca_cert_path, ca_c);

    jstring json = (*env)->NewStringUTF(env, result ? result : "{\"error\":\"FFI returned null\"}");
    if (result) ratls_free_string(result);
    return json;
}

// RA-TLS HTTP POST. Arg order mirrors the FFI (host, port, ca, path, body,
// headers). ca_cert_path and headers_json may be null.
JNIEXPORT jstring JNICALL
Java_org_privasys_nativeratls_NativeRaTlsBridge_nativePost(
    JNIEnv *env, jclass clazz, jstring host, jint port, jstring ca_cert_path,
    jstring path, jstring body, jstring headers_json) {
    const char *host_c = (*env)->GetStringUTFChars(env, host, NULL);
    const char *ca_c = ca_cert_path ? (*env)->GetStringUTFChars(env, ca_cert_path, NULL) : NULL;
    const char *path_c = (*env)->GetStringUTFChars(env, path, NULL);
    const char *body_c = (*env)->GetStringUTFChars(env, body, NULL);
    const char *headers_c = headers_json ? (*env)->GetStringUTFChars(env, headers_json, NULL) : NULL;

    char *result = ratls_post(host_c, (unsigned short)port, ca_c, path_c, body_c, headers_c);

    (*env)->ReleaseStringUTFChars(env, host, host_c);
    if (ca_c) (*env)->ReleaseStringUTFChars(env, ca_cert_path, ca_c);
    (*env)->ReleaseStringUTFChars(env, path, path_c);
    (*env)->ReleaseStringUTFChars(env, body, body_c);
    if (headers_c) (*env)->ReleaseStringUTFChars(env, headers_json, headers_c);

    jstring json = (*env)->NewStringUTF(env, result ? result : "{\"error\":\"FFI returned null\"}");
    if (result) ratls_free_string(result);
    return json;
}

// RA-TLS HTTP request with an explicit method (GET/POST/PUT/DELETE/...). An
// empty body sends no body. Arg order mirrors the FFI (method, host, port, ca,
// path, body, headers). ca_cert_path and headers_json may be null.
JNIEXPORT jstring JNICALL
Java_org_privasys_nativeratls_NativeRaTlsBridge_nativeRequest(
    JNIEnv *env, jclass clazz, jstring method, jstring host, jint port,
    jstring ca_cert_path, jstring path, jstring body, jstring headers_json) {
    const char *method_c = (*env)->GetStringUTFChars(env, method, NULL);
    const char *host_c = (*env)->GetStringUTFChars(env, host, NULL);
    const char *ca_c = ca_cert_path ? (*env)->GetStringUTFChars(env, ca_cert_path, NULL) : NULL;
    const char *path_c = (*env)->GetStringUTFChars(env, path, NULL);
    const char *body_c = (*env)->GetStringUTFChars(env, body, NULL);
    const char *headers_c = headers_json ? (*env)->GetStringUTFChars(env, headers_json, NULL) : NULL;

    char *result = ratls_request(method_c, host_c, (unsigned short)port, ca_c, path_c, body_c, headers_c);

    (*env)->ReleaseStringUTFChars(env, method, method_c);
    (*env)->ReleaseStringUTFChars(env, host, host_c);
    if (ca_c) (*env)->ReleaseStringUTFChars(env, ca_cert_path, ca_c);
    (*env)->ReleaseStringUTFChars(env, path, path_c);
    (*env)->ReleaseStringUTFChars(env, body, body_c);
    if (headers_c) (*env)->ReleaseStringUTFChars(env, headers_json, headers_c);

    jstring json = (*env)->NewStringUTF(env, result ? result : "{\"error\":\"FFI returned null\"}");
    if (result) ratls_free_string(result);
    return json;
}

JNIEXPORT jstring JNICALL
Java_org_privasys_nativeratls_NativeRaTlsBridge_nativeVerify(
    JNIEnv *env, jclass clazz, jstring host, jint port, jstring ca_cert_path,
    jstring policy_json) {
    const char *host_c = (*env)->GetStringUTFChars(env, host, NULL);
    const char *ca_c = ca_cert_path ? (*env)->GetStringUTFChars(env, ca_cert_path, NULL) : NULL;
    const char *policy_c = (*env)->GetStringUTFChars(env, policy_json, NULL);

    char *result = ratls_verify(host_c, (unsigned short)port, ca_c, policy_c);

    (*env)->ReleaseStringUTFChars(env, host, host_c);
    if (ca_c) (*env)->ReleaseStringUTFChars(env, ca_cert_path, ca_c);
    (*env)->ReleaseStringUTFChars(env, policy_json, policy_c);

    jstring json = (*env)->NewStringUTF(env, result ? result : "{\"error\":\"FFI returned null\"}");
    if (result) ratls_free_string(result);
    return json;
}
