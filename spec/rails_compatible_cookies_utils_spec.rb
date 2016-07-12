require 'spec_helper'
require 'rails_compatible_cookies_utils'

describe RailsCompatibleCookiesUtils do
  let(:secret_key_base){
    'a4fd2bd2d7e7b92a32711a91f39ebc293ec3884768c1ff7d65eb0b8cc02bcac894dec9f987713498062deba78ba5a93bfd2057d5c725f22cc3777410f85f694e'
  }

  let(:json_instance) { RailsCompatibleCookiesUtils.new secret_key_base }
  let(:marshal_instance) { RailsCompatibleCookiesUtils.new secret_key_base, serializer: Marshal }

  let(:unencrypted_value) { 'revealed' }
  let(:json_encrypted_cookie) {
    'encrypted_key=VTVSajdXQlNHOTJTbE1OVktmRTRqdz09LS02NGc4OGEyWnVzVitEYUw0bU9oZ1RnPT0%3D--7f3a476b45580498430cd2c78a693da9a811175a; other_key=abc'
  }
  let(:unescaped_encrypted_json_value) {
    'VTVSajdXQlNHOTJTbE1OVktmRTRqdz09LS02NGc4OGEyWnVzVitEYUw0bU9oZ1RnPT0=--7f3a476b45580498430cd2c78a693da9a811175a'
  }
  let(:marshal_encrypted_cookie) {
    'encrypted_key=VXdhY0NxOURzRm1FM1g3T0xuclJKYzJNSWtWY0VrZ0drMlhTSllIK2dTVT0tLW9Id3VUVXVuS3ovbUM4VGRYbzFRcXc9PQ%3D%3D--c952286bdb6e328b6a715f00ded1a51b382106f1'
  }
  let(:marshal_encrypted_json_value) {
    'VXdhY0NxOURzRm1FM1g3T0xuclJKYzJNSWtWY0VrZ0drMlhTSllIK2dTVT0tLW9Id3VUVXVuS3ovbUM4VGRYbzFRcXc9PQ==--c952286bdb6e328b6a715f00ded1a51b382106f1'
  }
  let(:unsigned_sample_array){ [ 'signed', true ] }
  let(:json_encoded_signed_sample_hash_cookie) { 'signed=WyJzaWduZWQiLHRydWVd--9262a03fc6d9af0a3ef21636bc6af334b16fe455' }
  let(:marshal_encoded_signed_sample_hash_cookie) { 'signed=BAhbB0kiC3NpZ25lZAY6BkVUVA%3D%3D--b4fbf072bcfc0914feaa3d55c091b972d6bbaa66' }

  it 'convert cookies string to hash with first value for each key' do
    expect(json_instance.cookies json_encrypted_cookie).to eq({
      'encrypted_key' => unescaped_encrypted_json_value, 'other_key' => 'abc'
    })
  end

  it 'decrypts a JSON serialized session value from cookie' do
    expect(json_instance.decrypt_cookie_key! json_encrypted_cookie, 'encrypted_key').
      to eq unencrypted_value
  end

  it 'serializes with JSON and encrypts a value' do
    expect(json_instance.decrypt! json_instance.encrypt unencrypted_value).
      to eq unencrypted_value
  end

  it 'decrypts a Marshal serialized session value from cookie' do
    expect(marshal_instance.decrypt_cookie_key! marshal_encrypted_cookie, 'encrypted_key').
      to eq unencrypted_value
  end

  it 'encrypts serializes with Marshal and encrypts a value' do
    expect(marshal_instance.decrypt! marshal_instance.encrypt unencrypted_value).
      to eq unencrypted_value
  end

  it 'loads a signed-only value encoded with JSON' do
    expect(json_instance.
             signed_cookie_key! json_encoded_signed_sample_hash_cookie, 'signed').
      to eq unsigned_sample_array
  end

  it 'loads a signed-only value encoded with Marshal' do
    expect(marshal_instance.
             signed_cookie_key! marshal_encoded_signed_sample_hash_cookie, 'signed').
      to eq unsigned_sample_array
  end

  it 'serializes with JSON and sign a value' do
    expect(json_instance.
           verify_and_deserialize! json_instance.serialize_and_sign unencrypted_value).
      to eq unencrypted_value
  end

  it 'serializes with Marshal and sign a value' do
    expect(marshal_instance.
           verify_and_deserialize! marshal_instance.serialize_and_sign unencrypted_value).
      to eq unencrypted_value
  end
end
