require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'NativeRaTls'
  s.version        = package['version']
  s.summary        = 'RA-TLS attestation verification for Privasys Wallet'
  s.homepage       = 'https://github.com/Privasys/identity-platform'
  s.license        = { type: 'AGPL-3.0-only' }
  s.author         = 'Privasys'
  s.source         = { git: '' }

  s.platform       = :ios, '16.0'
  s.swift_version  = '5.9'
  s.source_files   = '*.swift'
  s.static_framework = true

  # Pre-built Rust static library. The demo build (EXPO_PUBLIC_DEMO=1) runs on
  # the iOS simulator for screenshots and links the simulator slice; every
  # other build links the device library, as before.
  demo = ENV['EXPO_PUBLIC_DEMO'] == '1'
  ratls_lib = demo ? 'ratls_mobile-simulator' : 'ratls_mobile'
  s.vendored_libraries = "lib/lib#{ratls_lib}.a"
  s.preserve_paths     = 'lib/**', 'include/**'

  # C header for the Rust FFI (exposed via module.modulemap)
  pod_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/include"',
    'SWIFT_INCLUDE_PATHS'  => '"${PODS_TARGET_SRCROOT}/include"',
    'OTHER_LDFLAGS'       => "-l#{ratls_lib} -lc++ -framework Security -framework SystemConfiguration",
    'LIBRARY_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/lib"'
  }

  # The simulator library is Apple silicon only, and a simulator Release
  # build would also ask for Intel (x86_64): the demo leaves Intel out.
  if demo
    pod_xcconfig['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
    s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'x86_64' }
  end
  s.pod_target_xcconfig = pod_xcconfig

  s.dependency 'ExpoModulesCore'
end
