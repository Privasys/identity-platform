Pod::Spec.new do |s|
  s.name           = 'AppAttest'
  s.version        = '0.1.0'
  s.summary        = 'iOS App Attest for Privasys Wallet'
  s.homepage       = 'https://privasys.org'
  s.license        = { :type => 'AGPL-3.0-only' }
  s.author         = 'Privasys'
  s.source         = { :git => '' }
  s.platform       = :ios, '16.0'
  s.swift_version  = '5.9'
  s.source_files   = '*.swift'
  s.frameworks     = 'DeviceCheck', 'CryptoKit'
  s.dependency 'ExpoModulesCore'
end
