// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativeratls

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

class NativeRaTlsModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("NativeRaTls")

        AsyncFunction("inspect") { host: String, port: Int, caCertPath: String? ->
            runBlocking(Dispatchers.IO) {
                NativeRaTlsBridge.nativeInspect(host, port, caCertPath)
            }
        }

        AsyncFunction("verify") { host: String, port: Int, caCertPath: String?, policyJson: String ->
            runBlocking(Dispatchers.IO) {
                NativeRaTlsBridge.nativeVerify(host, port, caCertPath, policyJson)
            }
        }

        // Arg order matches the JS surface (native-ratls/src/index.ts): the TS
        // `post`/`request` pass headers before caCertPath, so the bridge call
        // re-orders them to the FFI (ca, path, body, headers) shape.
        AsyncFunction("post") { host: String, port: Int, path: String, body: String, headersJson: String?, caCertPath: String? ->
            runBlocking(Dispatchers.IO) {
                NativeRaTlsBridge.nativePost(host, port, caCertPath, path, body, headersJson)
            }
        }

        AsyncFunction("request") { method: String, host: String, port: Int, path: String, body: String, headersJson: String?, caCertPath: String? ->
            runBlocking(Dispatchers.IO) {
                NativeRaTlsBridge.nativeRequest(method, host, port, caCertPath, path, body, headersJson)
            }
        }
    }
}
