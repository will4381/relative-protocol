Pod::Spec.new do |spec|
  spec.name              = "RelativeProtocol"
  spec.version           = "1.0.0"
  spec.summary           = "High-performance, privacy-focused VPN framework for iOS"
  spec.description       = <<-DESC
    RelativeProtocol is a production-ready VPN framework built in C with comprehensive 
    testing and enterprise-grade reliability. Features include DNS leak protection, 
    IPv6 leak protection, NAT64 translation, and complete NetworkExtension integration.
  DESC

  spec.homepage          = "https://github.com/will4381/relative-protocol"
  spec.license           = { :type => "GPL-3.0", :file => "LICENSE" }
  spec.author            = { "RelativeProtocol Team" => "will@relativecompanies.com" }
  spec.social_media_url  = "https://twitter.com/hellakusch"

  spec.platform          = :ios, "14.0"
  spec.source            = { 
    :git => "https://github.com/will4381/relative-protocol.git", 
    :tag => "v#{spec.version}" 
  }

  spec.source_files      = [
    "src/**/*.{c,h}",
    "include/**/*.h"
  ]
  
  spec.public_header_files = "include/**/*.h"
  spec.private_header_files = "src/**/*.h"

  spec.frameworks        = "NetworkExtension", "Security", "Foundation"
  spec.libraries         = "c"

  spec.compiler_flags    = [
    "-DENABLE_LOGGING=0",
    "-DENABLE_SECURITY_FEATURES=1", 
    "-DTARGET_OS_IOS=1"
  ]

  spec.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => [
      '$(PODS_TARGET_SRCROOT)/include',
      '$(PODS_TARGET_SRCROOT)/third_party/lwip/src/include'
    ],
    'GCC_C_LANGUAGE_STANDARD' => 'c11',
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
    'ENABLE_BITCODE' => 'NO'
  }

  spec.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'tests/**/*.{cpp,h}'
    test_spec.frameworks = 'XCTest'
    test_spec.dependency 'GoogleTest'
  end

  spec.subspec 'Core' do |core|
    core.source_files = [
      'src/core/**/*.{c,h}',
      'src/api/**/*.{c,h}',
      'include/core/**/*.h',
      'include/api/**/*.h'
    ]
  end

  spec.subspec 'Networking' do |net|
    net.dependency 'RelativeProtocol/Core'
    net.source_files = [
      'src/packet/**/*.{c,h}',
      'src/tcp_udp/**/*.{c,h}',
      'src/socket_bridge/**/*.{c,h}',
      'include/packet/**/*.h',
      'include/tcp_udp/**/*.h',
      'include/socket_bridge/**/*.h'
    ]
  end

  spec.subspec 'Privacy' do |privacy|
    privacy.dependency 'RelativeProtocol/Core'
    privacy.source_files = [
      'src/privacy/**/*.{c,h}',
      'src/dns/**/*.{c,h}',
      'include/privacy/**/*.h',
      'include/dns/**/*.h'
    ]
  end

  spec.subspec 'NAT64' do |nat64|
    nat64.dependency 'RelativeProtocol/Core'
    nat64.source_files = [
      'src/nat64/**/*.{c,h}',
      'include/nat64/**/*.h'
    ]
  end

  spec.subspec 'Metrics' do |metrics|
    metrics.dependency 'RelativeProtocol/Core'
    metrics.source_files = [
      'src/metrics/**/*.{c,h}',
      'include/metrics/**/*.h'
    ]
  end

  spec.default_subspecs = 'Core', 'Networking', 'Privacy', 'NAT64', 'Metrics'
end