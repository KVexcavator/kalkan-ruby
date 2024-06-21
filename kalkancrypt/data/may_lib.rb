require 'ffi'
require 'json'

module MyLib
  extend FFI::Library
  ffi_lib File.expand_path('./libkalkancryptjws.so', __dir__)
  attach_function :create_jws_from_json, [:string, :string, :string], :string
end

payload = {
  "extRefNo": "004",
  "srvId": 141,
  "amount": 100,
  "currency": "KZT",
  "fee": 0,
  "point": "Sandbox",
  "accept": 0,
  "srvParams": [
    {
      "code": "iin",
      "value": "960913350158"
    },
    {
      "code": "account",
      "value": "KZ39821T2P5L10000001"
    },
    {
      "code": "name",
      "value": "Аманбаев Асыл Ержанович"
    },
    {
      "code": "knp",
      "value": "119"
    },
    {
      "code": "code",
      "value": "19"
    },
    {
      "code": "narrative",
      "value": "Платёж СБВ"
    }
  ]
}.to_json

begin
  result = MyLib.create_jws_from_json(payload, "/rails-api/lib/kalkancrypt/GOSTKNCA.p12", "Aa1234")
  puts result
rescue FFI::Library::FunctionNotFoundError => e
  puts "Function not found: #{e.message}"
rescue LoadError => e
  puts "Library not found: #{e.message}"
rescue StandardError => e
  puts "An error occurred: #{e.message}"
end
