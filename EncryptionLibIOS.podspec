#
# Be sure to run `pod lib lint EncryptionLibIOS.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'EncryptionLibIOS'
  s.version          = '1.0.0'
  s.summary          = 'SDK de encriptacion de boletos electronicos de SuperBoletos'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = 'SDK dedicado a la encriptacion de boletos electronicos mediante un token asignado a un boleto'

  s.homepage         = 'https://github.com/estreteca/EncryptionLibIOS'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'estreteca' => 'javier.alejandro@estrateca.com' }
  s.source           = { :git => 'https://github.com/estreteca/EncryptionLibIOS.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '12.0'

  s.source_files = 'EncryptionLibIOS/Classes/**/*'
  
  # s.resource_bundles = {
  #   'EncryptionLibIOS' => ['EncryptionLibIOS/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
    s.swift_versions = ['5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9', '5.10']
end
