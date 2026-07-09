// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import ExpoModulesCore
import NativeRaTlsC

public class NativeRaTlsModule: Module {
    public func definition() -> ModuleDefinition {
        Name("NativeRaTls")

        AsyncFunction("inspect") { (host: String, port: Int, caCertPath: String?) -> String in
            return await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let result = host.withCString { hostPtr in
                        if let path = caCertPath {
                            return path.withCString { pathPtr in
                                ratls_inspect(hostPtr, UInt16(port), pathPtr)
                            }
                        } else {
                            return ratls_inspect(hostPtr, UInt16(port), nil)
                        }
                    }

                    guard let result else {
                        continuation.resume(returning: "{\"error\":\"FFI returned null\"}")
                        return
                    }

                    let json = String(cString: result)
                    ratls_free_string(result)
                    continuation.resume(returning: json)
                }
            }
        }

        AsyncFunction("verify") { (host: String, port: Int, caCertPath: String?, policyJson: String) -> String in
            return await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let result = host.withCString { hostPtr in
                        policyJson.withCString { policyPtr in
                            if let path = caCertPath {
                                return path.withCString { pathPtr in
                                    ratls_verify(hostPtr, UInt16(port), pathPtr, policyPtr)
                                }
                            } else {
                                return ratls_verify(hostPtr, UInt16(port), nil, policyPtr)
                            }
                        }
                    }

                    guard let result else {
                        continuation.resume(returning: "{\"error\":\"FFI returned null\"}")
                        return
                    }

                    let json = String(cString: result)
                    ratls_free_string(result)
                    continuation.resume(returning: json)
                }
            }
        }

        AsyncFunction("post") { (host: String, port: Int, path: String, body: String, headersJson: String?, caCertPath: String?) -> String in
            return await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let result = host.withCString { hostPtr in
                        path.withCString { pathPtr in
                            body.withCString { bodyPtr in
                                // Resolve the optional CA path and headers-JSON to
                                // C pointers (or NULL) before the single FFI call.
                                func call(_ caPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
                                    if let headersJson {
                                        return headersJson.withCString { hPtr in
                                            ratls_post(hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, hPtr)
                                        }
                                    }
                                    return ratls_post(hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, nil)
                                }
                                if let caPath = caCertPath {
                                    return caPath.withCString { caPtr in call(caPtr) }
                                } else {
                                    return call(nil)
                                }
                            }
                        }
                    }

                    guard let result else {
                        continuation.resume(returning: "{\"error\":\"FFI returned null\"}")
                        return
                    }

                    let json = String(cString: result)
                    ratls_free_string(result)
                    continuation.resume(returning: json)
                }
            }
        }

        // Method-generic RA-TLS request (GET, POST, PUT, DELETE, ...).
        // An empty body sends no body (correct for GET/DELETE). Mirrors
        // `post`, calling the ratls_request FFI with an explicit method.
        AsyncFunction("request") { (method: String, host: String, port: Int, path: String, body: String, headersJson: String?, caCertPath: String?) -> String in
            return await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let result = method.withCString { methodPtr in
                        host.withCString { hostPtr in
                            path.withCString { pathPtr in
                                body.withCString { bodyPtr in
                                    func call(_ caPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
                                        if let headersJson {
                                            return headersJson.withCString { hPtr in
                                                ratls_request(methodPtr, hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, hPtr)
                                            }
                                        }
                                        return ratls_request(methodPtr, hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, nil)
                                    }
                                    if let caPath = caCertPath {
                                        return caPath.withCString { caPtr in call(caPtr) }
                                    } else {
                                        return call(nil)
                                    }
                                }
                            }
                        }
                    }

                    guard let result else {
                        continuation.resume(returning: "{\"error\":\"FFI returned null\"}")
                        return
                    }

                    let json = String(cString: result)
                    ratls_free_string(result)
                    continuation.resume(returning: json)
                }
            }
        }
    }
}
