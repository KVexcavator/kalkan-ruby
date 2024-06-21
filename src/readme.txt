==============================================
sudo cp -f libkalkancryptwr-64.so libkalkancryptwr-64.so.1.1.1 /usr/lib/
--------------------------------------------
выкинуть битый файл
sudo rm /lib/libkalkancryptwr-64.so
проверить
ls -l /lib/libkalkancryptwr-64.so
сделать симв ссылку
sudo ln -s /lib/libkalkancryptwr-64.so.2.0.2 /lib/libkalkancryptwr-64.so
проверить
=============================================
### компиляция и запуск

```bash
cd ext/kalkancrypt
ruby extconf.rb
make
cd ../../
ruby test_klk.rb
```
после внесения изменений надо заново
=============================================
ruby test_klk.rb
Initialization result: 0
Полученное вами сообщение "Initialization result: 0" указывает на успешное выполнение инициализации библиотеки KalkanCrypt. (init в списке возвращает void)
=============================================
основная магия в kalkancrypt.c !
==============================================
kalkancrypt.c:4:10: fatal error: jansson.h: No such file or directory
sudo apt-get update
sudo apt-get install libjansson-dev
==============================================
ruby test_payload.rb
SignData error: 8f00042
Error message: ERROR 0x8f00042: Load certificate from system store - failed to load root or intermediate certificate. Unable convert to X509.
----------------------------------------------
Error message: ERROR 0x8f00042: Load certificate from system store - failed to load root or intermediate certificate. Unable convert to X509.
```
ls -l ./GOSTKNCA.p12
```
-rw-rw-r-- 1 vk vk 1875 Jun 20 10:17 ./GOSTKNCA.p12

Убедитесь, что пароль от P12 файла указан правильно.

Убедитесь, что ваш P12 файл и сертификаты внутри него в правильном формате и содержат необходимые корневые и промежуточные сертификаты.

Убедитесь, что P12 файл не поврежден и содержит необходимые сертификаты и ключи. Вы можете проверить содержимое P12 файла с помощью OpenSSL:
```
openssl pkcs12 -info -in GOSTKNCA.p12 -noout
```
Enter Import Password: Aa1234
MAC: sha1, Iteration 1024
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 1024
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 1024
Error outputting keys and certificates
40278BA9B1790000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:../crypto/evp/evp_fetch.c:373:Global default library context, Algorithm (RC2-40-CBC : 0), Properties ()
-------------------------------------------
Ошибка, которую вы видите, указывает на проблему с алгоритмом шифрования RC2-40-CBC в OpenSSL. Это алгоритм, который не поддерживается вашей версией OpenSSL.
------------------------------------------
sudo apt-get update
sudo apt-get install libssl-dev libjansson-dev
не помогло
------------------------------------------
openssl pkcs12 -in GOSTKNCA.p12 -out GOSTKNCA.pem -nodes
не работает даже при переключении верий openssl
=========================================================
ruby test_payload.rb
Successfully loaded key store.
SignData error: 8f00042
Error message: ERROR 0x8f00042: Load certificate from system store - failed to load root or intermediate certificate. Unable convert to X509.
---------------------------------------------------------
документации код 0x08F00042 KCR_CERTTIMEINVALID Срок действия сертификата истек либо еще не наступил
Cообщение об ошибке: Загрузить сертификат из системного хранилища — не удалось загрузить корневой или промежуточный сертификат. Невозможно преобразовать в X509.
поломано в kalkancrypt.c pp114
==========================================================
X509CertificateGetInfo()
Функция - Обеспечивает получение значений полей/расширений из сертификата. Сертификат должен быть предварительно загружен с помощью одной из функций: LoadKeyStore(), X509LoadCertificateFromFile(),X509LoadCertificateFromBuffer().
Обзор - unsigned long (*X509CertificateGetInfo)(char *inCert, int inCertLength, int propId, unsigned char *outData, int *outDataLength);
Описание - Параметры:
[in] CHAR * inCert — сертификат в виде строки; [in] INT propId — идентификатор полей/расширений сертификата (см. KalkanCrypt CertPropID);
[out] CHAR * outData — указатель на значение указанного поля/расширения.
Возвращаемые значения - При успешном завершении возвращает 0,в противном случае – 1. Код ошибки и подробный текст можно получить с помощью функции GetLastError.

KC_GetLastError ()
Функция - Обеспечивает получение подробного кода и описание ошибки, возникшей в процессе выполнения функций криптопровайдера KalkanCryptCOM.
Обзор - unsigned long (*KC_GetLastError)(void);
Возвращаемые значения - Возвращает 0, если не найдена ошибка, иначе — значение > 0 (см. KalkanCryptCOM Errors).
При вызове очищается протокол работы криптопровайдера и значение кода последней ошибки.
=============================================
ошибка подробнее:
Successfully loaded key store.
SignData error: 8f00042
Error message: ERROR 0x8f00042: Load certificate from system store - failed to load root or intermediate certificate. Unable convert to X509.

Alias:
Data: example payload
Flags: 801
Output buffer size: 4096
Attempting to retrieve certificate details...
X509CertificateGetInfo error: 8f0001b
Error message: ERROR 0x8f0001b: Get PKI data properties - failed to load certificate.

0x08F0001b KCR_CERTNOTFOUND Не найден сертификат пользователя
