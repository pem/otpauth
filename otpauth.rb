# pem 2024-08-31
#
# An OTP Authentication module, implementing HOTP and TOTP. See README.txt.
#
# MIT License. See LICENSE.txt.
#
require 'base32'
require 'openssl'
require 'uri'

module OTPAuth

  # Note that some apps only support the default values.

  # Digits should be 6 - 10.
  DEFAULT_DIGITS = 6
  # The HMAC hash algorithm.
  DEFAULT_ALGORITHM = 'SHA1'
  # The HOTP start counter.
  DEFAULT_HOTP_COUNTER = 0
  # The TOTP period in seconds.
  DEFAULT_TOTP_PERIOD = 30

  # Generate a HOTP code. (RFC4226)
  def self.hotp(counter, b32secret,
                digits = DEFAULT_DIGITS,
                algorithm = DEFAULT_ALGORITHM)
    secret = Base32.decode(b32secret.strip.upcase)
    algorithm = algorithm.upcase
    mac = OpenSSL::HMAC.digest(algorithm, secret, [counter].pack("Q>")).bytes
    i = mac[-1] & 0xF
    trunc = ((mac[i] & 0x7F) << 24) |
            (mac[i+1] << 16) |
            (mac[i+2] << 8) |
            mac[i+3]
    return sprintf("%0*u", digits, trunc % (10**digits))
  end

  # Generate a TOTP code at this time. (RFC6238)
  # Returns two values, the code and the time remaining in the period
  def self.totp(b32secret,
                period = DEFAULT_TOTP_PERIOD,
                digits = DEFAULT_DIGITS,
                algorithm = DEFAULT_ALGORITHM)
    totp_at(Time.now.to_i, b32secret, period, digits, algorithm)
  end

  # Generate a TOTP code at a specific Unix timestamp t seconds.
  # Returns two values, the code and the time remaining in the period
  def self.totp_at(t, b32secret,
                   period = DEFAULT_TOTP_PERIOD,
                   digits = DEFAULT_DIGITS,
                   algorithm = DEFAULT_ALGORITHM)
    c,r = t.divmod(period)
    return hotp(c, b32secret, digits, algorithm), period-r
  end


  # Generate a Base32 encoded secret. (RFC4648 p.6)
  # Minimum 16 (128 bits), recommended 20 (160 bits), or larger
  def self.generate_secret(bytes)
    s = Base32.encode(OpenSSL::Random.random_bytes(bytes))
    s.delete!('=')              # We don't need padding
    return s
  end


  # Return an otpauth HOTP or TOTP URI. This can be converted into a QR code to be scanned
  # by an authenticator app.
  # The issuer:label is used by the app to identify the token.
  # Image should be an URL to a small image the app can add to the token entry. This is optional.

  def self.hotp_uri(b32secret, issuer, label, image = nil,
                    counter = DEFAULT_HOTP_COUNTER,
                    digits = DEFAULT_DIGITS,
                    algorithm = DEFAULT_ALGORITHM)
    uri('hotp', issuer, label, image, b32secret, digits, algorithm, counter, nil)
  end

  def self.totp_uri(b32secret, issuer, label, image = nil,
                    period = DEFAULT_TOTP_PERIOD,
                    digits = DEFAULT_DIGITS,
                    algorithm = DEFAULT_ALGORITHM)
    uri('totp', issuer, label, image, b32secret, digits, algorithm, nil, period)
  end


  private

  # Return an otpauth URI.
  def self.uri(type, issuer, label, image, b32secret, digits, algorithm,
               counter, period)
    i = URI.encode_uri_component(issuer)
    name = URI.encode_uri_component("#{issuer}:#{label}")
    algorithm = algorithm.downcase unless algorithm.nil? || algorithm == DEFAULT_ALGORITHM
    image = URI.encode_uri_component(image) unless image.nil?
    u = "otpauth://#{type}/#{name}?secret=#{b32secret}&issuer=#{i}"
    u << "&image=#{image}" unless image.nil?
    u << "&algorithm=#{algorithm}" unless algorithm.nil? || algorithm == DEFAULT_ALGORITHM
    u << "&digits=#{digits}" unless digits.nil? || digits == DEFAULT_DIGITS
    u << "&counter=#{counter}" unless counter.nil? || counter == DEFAULT_HOTP_COUNTER
    u << "&period=#{period}" unless period.nil? || period == DEFAULT_TOTP_PERIOD
    return u
  end

end # module OTPAuth
