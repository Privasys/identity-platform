require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'NativeKeys'
  s.version        = package['version']
  s.summary        = 'Secure Enclave key management for Privasys Wallet'
  s.homepage       = 'https://github.com/Privasys/privasys-id'
  s.license        = { type: 'AGPL-3.0-only' }
  s.author         = 'Privasys'
  s.source         = { git: '' }

  s.platform       = :ios, '16.0'
  s.swift_version  = '5.9'
  s.source_files   = '*.swift'
  s.static_framework = true

  s.frameworks     = 'Security', 'LocalAuthentication'

  s.dependency 'ExpoModulesCore'
end
