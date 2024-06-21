# Определение функции для переключения версий OpenSSL
def switch_openssl(version)
  case version
  when "1.1.0"
    system("export PATH=/usr/local/openssl-1.1.0/bin:$PATH")
    system("export LD_LIBRARY_PATH=/usr/local/openssl-1.1.0/lib:$LD_LIBRARY_PATH")
  when "default"
    system("export PATH=$(echo $PATH | sed -e 's#/usr/local/openssl-1.1.0/bin:##')")
    system("export LD_LIBRARY_PATH=$(echo $LD_LIBRARY_PATH | sed -e 's#/usr/local/openssl-1.1.0/lib:##')")
  else
    raise "Unsupported OpenSSL version: #{version}"
  end
end

# Переключение на нужную версию OpenSSL
switch_openssl("1.1.0")

# Подключение библиотеки kalkancrypt
require_relative 'ext/kalkancrypt/kalkancrypt'

# Инициализация библиотеки
KalkanCrypt.init

# Создание JWS подписи
payload = "example payload"
p12_path = "./GOSTKNCA.p12"
password = "Aa1234"
jws_signature = KalkanCrypt.create_jws_signature(payload, p12_path, password)

puts "JWS Signature: #{jws_signature}"

# Переключение обратно на стандартную версию OpenSSL (если необходимо)
switch_openssl("default")
