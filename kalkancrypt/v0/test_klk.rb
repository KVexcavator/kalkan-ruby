require_relative 'ext/kalkancrypt/kalkancrypt'

kc = KalkanCrypt::KalkanCrypt.new
result = kc.init
p result
puts "Initialization result: #{result}"
