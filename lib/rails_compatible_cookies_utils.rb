require 'rails_compatible_cookies_utils/version'
require 'json'
require 'cgi'
require 'openssl'
require 'base64'

class RailsCompatibleCookiesUtils

  ##
  # Initializes it by providing the required secret_key_base as defined by your Rails app.
  # The default Rails serializer in recent versions is +JSON+, but +Marshal+ used to be the
  # default. If your Rails application is old and still uses +Marshal+, set the +serializer+
  # argument to +Marshal+: RailsCompatibleCookiesUtils.new(secret_key_base, serializer: Marshal).

  def initialize(secret_key_base, serializer: JSON, encrypted_salt: 'encrypted cookie',
       encrypted_signed_salt: 'signed encrypted cookie', signed_salt: 'signed cookie',
       iterations: 1000, key_size: 64, cipher: 'aes-256-cbc', digest: 'SHA1')
    @secret_key_base, @serializer, @encrypted_salt, @encrypted_signed_salt,
        @signed_salt, @iterations, @key_size, @cipher, @digest =
      secret_key_base, serializer, encrypted_salt, encrypted_signed_salt,
        signed_salt, iterations, key_size, cipher, digest
  end

  # Decrypts an specific key from a raw cookie string. Returns nil if invalid.
  def decrypt_cookie_key(cookie, key)
    decrypt cookie_value(cookie, key)
  end

  # Decrypts an specific key from a raw cookie string.
  # Raises RailsCompatibleCookiesUtils::InvalidSignature if invalid.
  def decrypt_cookie_key!(cookie, key)
    decrypt! cookie_value(cookie, key)
  end

  InvalidSignature = Class.new StandardError
  # Decrypt an unescaped value and raise RailsCompatibleCookiesUtils::InvalidSignature if invalid.
  def decrypt!(value)
    decrypt value or raise InvalidSignature
  end

  # Decrypts an unescaped value and return nil if invalid.
  def decrypt(value)
    return nil unless encoded_encrypted = verify_and_decode(value, encrypted_signed_secret)
    cipher = new_cipher
    encrypted, iv = encoded_encrypted.split('--').map{|v| decode v }
    cipher.decrypt
    cipher.key = encrypted_secret
    cipher.iv = iv
    decrypted = cipher.update encrypted
    decrypted << cipher.final
    @serializer.load decrypted
  end

  # Decodes value, returning nil if it's invalid.
  def verify_and_decode(value, secret)
    return nil if value.nil? || !value.valid_encoding? || value.strip.empty?
    data, digest = value.split '--'
    return nil if [data, digest].any?{|v| v.nil? || v.strip.empty?}
    return nil unless generate_digest(data, secret) == digest
    decode data
  end

  def encrypted_secret
    @encrypted_secret ||= generate_key(@encrypted_salt)[0, new_cipher.key_len]
  end

  def generate_key(salt)
    OpenSSL::PKCS5.pbkdf2_hmac_sha1 @secret_key_base, salt, @iterations, @key_size
  end

  def encrypted_signed_secret
    @encrypted_signed_secret ||= generate_key @encrypted_signed_salt
  end

  def signed_secret
    @signed_secret ||= generate_key @signed_salt
  end

  # Gets first value for +key+ from the raw +cookie+ (env['HTTP_COOKIE']).
  def cookie_value(cookie, key)
    cookies(cookie)[key]
  end

  # Returns a hash with the first value for each key from the raw cookie string.
  def cookies(cookie)
    Hash[CGI::Cookie::parse(cookie).map{|k, v| [k, v.first]}]
  end

  # Returns signed encrypted +value+.
  def encrypt(value)
    sign_and_encode _encrypt(value), encrypted_signed_secret
  end

  # Signs and encode value only, without encrypting (session.signed[key] = value).
  def sign_and_encode(value, secret)
    data = encode value
    "#{data}--#{generate_digest data, secret}"
  end

  # Fetches a signed-only value from the raw cookie (env['HTTP_COOKIE']): session.signed['key'].
  # Raises RailsCompatibleCookiesUtils::InvalidSignature if invalid.
  def signed_cookie_key!(cookie, key)
    signed_cookie_key cookie, key or raise InvalidSignature
  end

  # Fetches a signed-only value from the raw cookie (env['HTTP_COOKIE']): session.signed['key'].
  # Returns nil if invalid.
  def signed_cookie_key(cookie, key)
    verify_and_deserialize cookie_value(cookie, key)
  end

  # Decodes and deserializes a signed value.
  # Raises RailsCompatibleCookiesUtils::InvalidSignature if invalid.
  def verify_and_deserialize!(value)
    verify_and_deserialize value or raise InvalidSignature
  end

  # Decodes and deserializes a signed value, returning nil if invalid.
  def verify_and_deserialize(value)
    return nil unless decoded = verify_and_decode(value, signed_secret)
    @serializer.load decoded
  end

  # Serializes and sign +value+ (session.signed['key'] = value)
  def serialize_and_sign(value)
    sign_and_encode @serializer.dump(value), signed_secret
  end

  private

  def generate_digest(data, secret)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest.const_get(@digest).new, secret, data)
  end

  def encode(data)
    ::Base64.strict_encode64 data
  end

  def decode(data)
    ::Base64.strict_decode64 data
  end

  def new_cipher
    OpenSSL::Cipher.new @cipher
  end

  def _encrypt(value)
    cipher = new_cipher
    cipher.encrypt
    cipher.key = encrypted_secret
    iv = cipher.random_iv

    encrypted = cipher.update @serializer.dump value
    encrypted << cipher.final
    "#{encode encrypted}--#{encode iv}"
  end
end
