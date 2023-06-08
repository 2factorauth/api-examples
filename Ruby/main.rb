#!/usr/bin/env ruby
# frozen_string_literal: true
require 'rubygems'
require 'net/http'
require 'uri'
require 'gpgme'
require 'dnsruby'
require 'base64'

# Retrieve signature
resolver = Dnsruby::Resolver.new
Dnsruby::Dnssec.default_resolver = resolver
Dnsruby::Dnssec.validation_policy = Dnsruby::Dnssec::ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS
resolver.dnssec = true
resolver.do_validation = true
ret = resolver.query('security.2fa.directory', 'CERT')
raise "Insecure DNS response. DNSSEC: #{ret.security_level}" unless ret.security_level.eql? 'SECURE'

# Import public key(s) from CERT RR
imports = GPGME::Key.import(ret.answer.rrsets[0][0].cert).imports

# Fetch fingerprints from imported key(s)
fingerprints = imports.map(&:fpr)

# Specify which file to download
filename = ARGV[0]

# Fetch file
res = Net::HTTP.get_response(URI("https://api.2fa.directory/v3/#{filename}.sig")).body

# Decipher signed data file
data = GPGME::Crypto.new.verify(GPGME::Data.new(res)) do |sig|
  # Verify that the same key as the one from CERT RR
  raise 'Invalid key' unless sig.valid?
  raise 'Mismatching key' unless fingerprints.include? sig.fingerprint
end

# Write verified data to new file
File.open(filename, 'w') { |file| file.write data }
