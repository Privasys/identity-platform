// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativeratls

/** JNI bridge to the Rust ratls_mobile FFI. */
internal object NativeRaTlsBridge {
    init {
        System.loadLibrary("ratls_jni")
    }

    @JvmStatic
    external fun nativeInspect(host: String, port: Int, caCertPath: String?): String

    @JvmStatic
    external fun nativeVerify(host: String, port: Int, caCertPath: String?, policyJson: String): String

    @JvmStatic
    external fun nativePost(
        host: String, port: Int, caCertPath: String?,
        path: String, body: String, headersJson: String?
    ): String

    @JvmStatic
    external fun nativeRequest(
        method: String, host: String, port: Int, caCertPath: String?,
        path: String, body: String, headersJson: String?
    ): String
}
