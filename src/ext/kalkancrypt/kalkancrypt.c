#include "ruby.h"
#include "KalkanCrypt.h"
#include <dlfcn.h>
#include <jansson.h>
#include <stdlib.h>
#include <string.h>

// Определение размеров буферов
#define BUFFER_SIZE 4096

// Объявление указателя на структуру, которая будет хранить функции KalkanCrypt
static stKCFunctionsType *kc_funcs = NULL;

// Прототипы функций
void base64_encode(const unsigned char *input, int length, char *output);
void load_and_sign_data(const char *data, char *signed_data, const char *p12_path, const char *password);
char *create_jws_signature(const char *payload, const char *p12_path, const char *password);

// Метод для инициализации библиотеки KalkanCrypt
static VALUE rb_kalkancrypt_init(VALUE self) {
    if (kc_funcs == NULL) {
        // Загрузка библиотеки libkalkancryptwr-64.so
        void *handle = dlopen("libkalkancryptwr-64.so", RTLD_LAZY);
        if (!handle) {
            rb_raise(rb_eRuntimeError, "Failed to load libkalkancryptwr-64.so: %s", dlerror());
        }

        // Поиск функции KC_GetFunctionList
        int (*KC_GetFunctionList)(stKCFunctionsType **) = (int (*)(stKCFunctionsType **))dlsym(handle, "KC_GetFunctionList");
        if (!KC_GetFunctionList) {
            dlclose(handle);
            rb_raise(rb_eRuntimeError, "Failed to find KC_GetFunctionList: %s", dlerror());
        }

        // Вызов функции KC_GetFunctionList
        if (KC_GetFunctionList(&kc_funcs) != KCR_OK) {
            dlclose(handle);
            rb_raise(rb_eRuntimeError, "Failed to get function list from KalkanCrypt library");
        }
    }

    // Вызов функции KC_Init() из KalkanCrypt.h
    unsigned long result = kc_funcs->KC_Init();
    return ULONG2NUM(result);
}

// Метод для кодирования Base64
void base64_encode(const unsigned char *input, int length, char *output) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int i = 0, j = 0;
    for (i = 0; i < length - 2; i += 3) {
        output[j++] = table[(input[i] >> 2) & 0x3F];
        output[j++] = table[((input[i] & 0x3) << 4) | ((input[i + 1] >> 4) & 0xF)];
        output[j++] = table[((input[i + 1] & 0xF) << 2) | ((input[i + 2] >> 6) & 0x3)];
        output[j++] = table[input[i + 2] & 0x3F];
    }
    if (i < length) {
        output[j++] = table[(input[i] >> 2) & 0x3F];
        if (i == (length - 1)) {
            output[j++] = table[((input[i] & 0x3) << 4)];
            output[j++] = '=';
        } else {
            output[j++] = table[((input[i] & 0x3) << 4) | ((input[i + 1] >> 4) & 0xF)];
            output[j++] = table[((input[i + 1] & 0xF) << 2)];
        }
        output[j++] = '=';
    }
    output[j] = '\0';
}

// Метод для загрузки данных и их подписи
void load_and_sign_data(const char *data, char *signed_data, const char *p12_path, const char *password) {
    unsigned int rv = 0;
    void *handle = dlopen("libkalkancryptwr-64.so", RTLD_LAZY);
    if (!handle) {
        fputs(dlerror(), stderr);
        exit(1);
    }

    int (*KC_GetFunctionList)(stKCFunctionsType **) = (int (*)(stKCFunctionsType **))dlsym(handle, "KC_GetFunctionList");
    if (KC_GetFunctionList == NULL) {
        fprintf(stderr, "Error loading KC_GetFunctionList: %s\n", dlerror());
        exit(1);
    }

    rv = KC_GetFunctionList(&kc_funcs);
    if (rv != 0) {
        fprintf(stderr, "KC_GetFunctionList error: %x\n", rv);
        exit(1);
    }

    rv = kc_funcs->KC_Init();
    if (rv != 0) {
        fprintf(stderr, "KC_Init error: %x\n", rv);
        exit(1);
    }

    const char *alias = "";
    rv = kc_funcs->KC_LoadKeyStore(KCST_PKCS12, (char *)password, strlen(password), (char *)p12_path, strlen(p12_path), (char *)alias);
    if (rv != 0) {
        char err_str[BUFFER_SIZE];
        int errLen = BUFFER_SIZE;
        kc_funcs->KC_GetLastErrorString(err_str, &errLen);
        fprintf(stderr, "KC_LoadKeyStore error: %x\nError message: %s\n", rv, err_str);
        exit(1);
    }

    fprintf(stderr, "Successfully loaded key store.\n");

    unsigned long flags_sign = KC_SIGN_DRAFT | KC_OUT_BASE64;
    unsigned char outSign[BUFFER_SIZE];
    int outSignLength = sizeof(outSign);

    rv = kc_funcs->SignData((char *)alias, flags_sign, (char *)data, strlen(data), NULL, 0, outSign, &outSignLength);
    if (rv != 0) {
        char err_str[BUFFER_SIZE];
        int errLen = BUFFER_SIZE;
        kc_funcs->KC_GetLastErrorString(err_str, &errLen);
        fprintf(stderr, "SignData error: %x\nError message: %s\n", rv, err_str);

        // Дополнительный вывод для диагностики
        fprintf(stderr, "Alias: %s\n", alias);
        fprintf(stderr, "Data: %s\n", data);
        fprintf(stderr, "Flags: %lx\n", flags_sign);
        fprintf(stderr, "Output buffer size: %d\n", outSignLength);

        // Попробуйте загрузить и проверить сертификат вручную
        fprintf(stderr, "Attempting to retrieve certificate details...\n");

        int propId = 1;  // Пример идентификатора свойства (из документации KalkanCrypt CertPropID)
        unsigned char certData[BUFFER_SIZE];
        int certDataLength = BUFFER_SIZE;

        rv = kc_funcs->X509CertificateGetInfo((char *)alias, strlen(alias), propId, certData, &certDataLength);
        if (rv != 0) {
            fprintf(stderr, "X509CertificateGetInfo error: %x\n", rv);
            kc_funcs->KC_GetLastErrorString(err_str, &errLen);
            fprintf(stderr, "Error message: %s\n", err_str);
        } else {
            fprintf(stderr, "Certificate Info (propId %d): %s\n", propId, certData);
        }

        exit(1);
    }

    strncpy(signed_data, (char *)outSign, outSignLength);
    signed_data[outSignLength] = '\0';

    printf("Successfully signed data:\n%s\n", signed_data);

    kc_funcs->KC_Finalize();
    dlclose(handle);
}

// Метод для создания JWS подписи
char *create_jws_signature(const char *payload, const char *p12_path, const char *password) {
    char *jws_signature = (char *)malloc(BUFFER_SIZE * sizeof(char));
    char *signed_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    const char *cert_base64 = "MIIElDCCBD6gAwIBAgIUW5hhR6EvhCHYE6/gxrQpj8X+Y5IwDQYJKoMOAwoBAQECBQAwUzELMAkGA1UEBhMCS1oxRDBCBgNVBAMMO9Kw0JvQotCi0KvSmiDQmtCj05jQm9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr0pogKEdPU1QpMB4XDTI0MDMxNDA4Mzk0NloXDTI1MDMxNDA4Mzk0NlowggEmMTUwMwYDVQQDDCzQk9Ce0JzQl9Cv0JrQntCS0JAg0JjQoNCY0J3QkCDQrtCg0KzQldCS0J3QkDEbMBkGA1UEBAwS0JPQntCc0JfQr9Ca0J7QktCQMRgwFgYDVQQFEw9JSU44NTExMTUwMDEzNDAxCzAJBgNVBAYTAktaMYGOMIGLBgNVBAoMgYPQotC+0LLQsNGA0LjRidC10YHRgtCy0L4g0YEg0L7Qs9GA0LDQvdC40YfQtdC90L3QvtC5INC+0YLQstC10YLRgdGC0LLQtdC90L3QvtGB0YLRjNGOICJEcmVpZGVsIEZpbmFuY2UgKNCU0YDQtdC50LTQuyDQpNC40L3QsNC90YEpIjEYMBYGA1UECwwPQklOMjIwNDQwMDQxOTM4MGwwJQYJKoMOAwoBAQEBMBgGCiqDDgMKAQEBAQEGCiqDDgMKAQMBAQADQwAEQDrr5G8FGs7XMpOLbaWwO7V2+5uZ+UuPbHGxsaycaScvfgeEit2EkffPLuUpMK7VlLVv/kPupEjKOsk5Hq7Aj0ujggIDMIIB/zAOBgNVHQ8BAf8EBAMCBsAwKAYDVR0lBCEwHwYIKwYBBQUHAwQGCCqDDgMDBAECBgkqgw4DAwQBAgEwXgYDVR0gBFcwVTBTBgcqgw4DAwIBMEgwIQYIKwYBBQUHAgEWFWh0dHA6Ly9wa2kuZ292Lmt6L2NwczAjBggrBgEFBQcCAjAXDBVodHRwOi8vcGtpLmdvdi5rei9jcHMwWAYDVR0fBFEwTzBNoEugSYYiaHR0cDovL2NybC5wa2kuZ292Lmt6L25jYV9nb3N0LmNybIYjaHR0cDovL2NybDEucGtpLmdvdi5rei9uY2FfZ29zdC5jcmwwXAYDVR0uBFUwUzBRoE+gTYYkaHR0cDovL2NybC5wa2kuZ292Lmt6L25jYV9kX2dvc3QuY3JshiVodHRwOi8vY3JsMS5wa2kuZ292Lmt6L25jYV9kX2dvc3QuY3JsMGMGCCsGAQUFBwEBBFcwVTAvBggrBgEFBQcwAoYjaHR0cDovL3BraS5nb3Yua3ovY2VydC9uY2FfZ29zdC5jZXIwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnBraS5nb3Yua3owHQYDVR0OBBYEFNuYYUehL4Qh2BOv4Ma0KY/F/mOSMA8GA1UdIwQIMAaABFtqc+kwFgYGKoMOAwMFBAwwCgYIKoMOAwMFAQEwDQYJKoMOAwoBAQECBQADQQBctb1j4kVFj2w53k8+4IC2mooApbvMIPW6MfnMW3dlKQ+t4XaZ4jfF4Sw9UDVQv7905z8uzirEHQY3Vttn7zq3";

    load_and_sign_data(payload, signed_data, p12_path, password);

    json_t *jws_signature_obj = json_object();
    json_t *jws_signature_header = json_object();
    json_t *jws_signature_signatures = json_array();

    json_object_set_new(jws_signature_header, "x5c", json_pack("[s]", cert_base64));
    json_object_set_new(jws_signature_header, "alg", json_string("ECGOST34310"));

    json_t *jws_signature_signature_obj = json_object();
    json_object_set_new(jws_signature_signature_obj, "header", jws_signature_header);
    json_object_set_new(jws_signature_signature_obj, "signature", json_string(signed_data));

    json_array_append_new(jws_signature_signatures, jws_signature_signature_obj);

    char payload_base64[BUFFER_SIZE];
    base64_encode((unsigned char *)payload, strlen(payload), payload_base64);

    json_object_set_new(jws_signature_obj, "payload", json_string(payload_base64));
    json_object_set_new(jws_signature_obj, "signatures", jws_signature_signatures);

    char *jws_string = json_dumps(jws_signature_obj, JSON_COMPACT);

    strcpy(jws_signature, jws_string);

    free(jws_string);
    json_decref(jws_signature_obj);
    free(signed_data);

    return jws_signature;
}

// Обертка для Ruby-метода create_jws_signature
static VALUE rb_create_jws_signature(VALUE self, VALUE payload, VALUE p12_path, VALUE password) {
    Check_Type(payload, T_STRING);
    Check_Type(p12_path, T_STRING);
    Check_Type(password, T_STRING);

    char *c_payload = StringValueCStr(payload);
    char *c_p12_path = StringValueCStr(p12_path);
    char *c_password = StringValueCStr(password);

    char *jws_signature = create_jws_signature(c_payload, c_p12_path, c_password);
    VALUE result = rb_str_new2(jws_signature);
    free(jws_signature);
    return result;
}

// Инициализация библиотеки
void Init_kalkancrypt() {
    VALUE KalkanCrypt = rb_define_module("KalkanCrypt");
    rb_define_singleton_method(KalkanCrypt, "init", rb_kalkancrypt_init, 0);
    rb_define_singleton_method(KalkanCrypt, "create_jws_signature", rb_create_jws_signature, 3);
}
