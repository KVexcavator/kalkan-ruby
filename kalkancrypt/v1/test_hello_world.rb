require_relative 'ext/kalkancrypt/kalkancrypt'

kc = KalkanCrypt::KalkanCrypt.new
puts kc.hello_world("Иван", "Иванович", "Иванов")
