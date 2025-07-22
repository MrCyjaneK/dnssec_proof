#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint dnssec_proof.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'dnssec_proof'
  s.version          = '0.0.1'
  s.summary          = 'Flutter FFI plugin for DNSSEC proof generation.'
  s.description      = <<-DESC
Flutter FFI plugin for DNSSEC proof generation.
                       DESC
  s.homepage         = 'https://github.com/mrcyjanek/dnssec_proof'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Czarek Nakamoto' => 'cyjan@mrcyjanek.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'

  s.script_phase = {
    :name => 'Build Rust library',
    :script => 'sh "$PODS_TARGET_SRCROOT/../cargokit/build_pod.sh" ../rust dnssec_proof',
    :execution_position => :before_compile,
    :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
    :output_files => ["${BUILT_PRODUCTS_DIR}/libdnssec_proof.a"],
  }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    # Flutter.framework does not contain a i386 slice.
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/libdnssec_proof.a',
    'MACOSX_DEPLOYMENT_TARGET' => '10.15',
  }
end
