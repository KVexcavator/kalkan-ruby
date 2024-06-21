require_relative 'ext/kalkancrypt/kalkancrypt'


# Инициализация библиотеки
KalkanCrypt.init

# Создание JWS подписи
payload = "example payload"
p12_path = "./GOSTKNCA.p12"
password = "Aa1234"
jws_signature = KalkanCrypt.create_jws_signature(payload, p12_path, password)

puts "JWS Signature: #{jws_signature}"
