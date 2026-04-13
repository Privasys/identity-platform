require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'NativeRaTls'
  s.version        = package['version']
  s.summary        = 'RA-TLS attestation verification for Privasys Wallet'
  s.homepage       = 'https://github.com/Privasys/privasys-id'
  s.license        = { type: 'AGPL-3.0-only' }
  s.author         = 'Privasys'
  s.source         = { git: '' }

  s.platform       = :ios, '16.0'
  s.swift_version  = '5.9'
  s.source_files   = '*.swift'
  s.static_framework = true

  # Pre-built Rust static library
  s.vendored_libraries = 'lib/libratls_mobile.a'
  s.preserve_paths     = 'lib/**', 'include/**'

  # C header for the Rust FFI (exposed via module.modulemap)
  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/include"',
    'SWIFT_INCLUDE_PATHS'  => '"${PODS_TARGET_SRCROOT}/include"',
    'OTHER_LDFLAGS'       => '-lratls_mobile -lc++ -framework Security -framework SystemConfiguration',
    'LIBRARY_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/lib"'
  }

  s.dependency 'ExpoModulesCore'
end
