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

        // `request` with connection options (JSON: attestation and trust), so a
        // host that is not an enclave can be reached over an ordinary
        // public-PKI TLS connection without an evidence exchange.
        AsyncFunction("requestWith") { (method: String, host: String, port: Int, path: String, body: String, headersJson: String?, caCertPath: String?, optionsJson: String?) -> String in
            return await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let result = method.withCString { methodPtr in
                        host.withCString { hostPtr in
                            path.withCString { pathPtr in
                                body.withCString { bodyPtr in
                                    func call(_ caPtr: UnsafePointer<CChar>?, _ hPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
                                        if let optionsJson {
                                            return optionsJson.withCString { oPtr in
                                                ratls_request_with(methodPtr, hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, hPtr, oPtr)
                                            }
                                        }
                                        return ratls_request_with(methodPtr, hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, hPtr, nil)
                                    }
                                    func withHeaders(_ caPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
                                        if let headersJson {
                                            return headersJson.withCString { hPtr in call(caPtr, hPtr) }
                                        }
                                        return call(caPtr, nil)
                                    }
                                    if let caPath = caCertPath {
                                        return caPath.withCString { caPtr in withHeaders(caPtr) }
                                    } else {
                                        return withHeaders(nil)
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

        // `requestWith`, with the response body as bytes (a JS Uint8Array)
        // rather than inside a JSON string, so a binary body arrives intact.
        // Resolves {status, body} or {error} (the same error JSON as a string).
        AsyncFunction("requestBytes") { (method: String, host: String, port: Int, path: String, body: String, headersJson: String?, caCertPath: String?, optionsJson: String?) -> [String: Any] in
            return await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let resp = method.withCString { methodPtr in
                        host.withCString { hostPtr in
                            path.withCString { pathPtr in
                                body.withCString { bodyPtr in
                                    func call(_ caPtr: UnsafePointer<CChar>?, _ hPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<RatlsResponse>? {
                                        if let optionsJson {
                                            return optionsJson.withCString { oPtr in
                                                ratls_request_bytes(methodPtr, hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, hPtr, oPtr)
                                            }
                                        }
                                        return ratls_request_bytes(methodPtr, hostPtr, UInt16(port), caPtr, pathPtr, bodyPtr, hPtr, nil)
                                    }
                                    func withHeaders(_ caPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<RatlsResponse>? {
                                        if let headersJson {
                                            return headersJson.withCString { hPtr in call(caPtr, hPtr) }
                                        }
                                        return call(caPtr, nil)
                                    }
                                    if let caPath = caCertPath {
                                        return caPath.withCString { caPtr in withHeaders(caPtr) }
                                    } else {
                                        return withHeaders(nil)
                                    }
                                }
                            }
                        }
                    }

                    guard let resp else {
                        continuation.resume(returning: ["error": "{\"error\":\"FFI returned null\"}"])
                        return
                    }
                    let r = resp.pointee
                    var out: [String: Any]
                    if let err = r.error {
                        out = ["error": String(cString: err)]
                    } else {
                        let bytes = r.body_len > 0 && r.body != nil ? Data(bytes: r.body, count: Int(r.body_len)) : Data()
                        out = ["status": Int(r.status), "body": bytes]
                    }
                    ratls_free_response(resp)
                    continuation.resume(returning: out)
                }
            }
        }
    }
}
