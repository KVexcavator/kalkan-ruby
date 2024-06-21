#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <jansson.h>  // Для работы с JSON

#include "KalkanCrypt.h"

#define BUFFER_SIZE 50000
#define CERT_LENGTH 32768

typedef int (*KC_GetFunctionList1)(stKCFunctionsType **KCfunc);
KC_GetFunctionList1 lib_funcList = NULL;
stKCFunctionsType *kc_funcs;

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

void load_and_sign_data(const char *data, char *signed_data, const char *p12_path, const char *password) {
    unsigned int rv = 0;
    void *handle = dlopen("./libkalkancryptwr-64.so", RTLD_LAZY);
    if (!handle) {
        fputs(dlerror(), stderr);
        exit(1);
    }

    lib_funcList = (KC_GetFunctionList1)dlsym(handle, "KC_GetFunctionList");
    if (lib_funcList == NULL) {
        fprintf(stderr, "Error loading KC_GetFunctionList: %s\n", dlerror());
        exit(1);
    }

    rv = lib_funcList(&kc_funcs);
    if (rv != 0) {
        fprintf(stderr, "KC_GetFunctionList error: %x\n", rv);
        exit(1);
    }

    rv = kc_funcs->KC_Init();
    if (rv != 0) {
        fprintf(stderr, "KC_Init error: %x\n", rv);
        exit(1);
    }

    // Загрузка ключа из p12 файла
    const char *alias = "";
    rv = kc_funcs->KC_LoadKeyStore(KCST_PKCS12, (char *)password, strlen(password), (char *)p12_path, strlen(p12_path), (char *)alias);
    if (rv != 0) {
        char err_str[BUFFER_SIZE];
        int errLen = BUFFER_SIZE;
        kc_funcs->KC_GetLastErrorString(err_str, &errLen);
        fprintf(stderr, "KC_LoadKeyStore error: %x\nError message: %s\n", rv, err_str);
        exit(1);
    }

    // Подписание данных
    unsigned long flags_sign = KC_SIGN_DRAFT | KC_OUT_BASE64;
    unsigned char outSign[BUFFER_SIZE];
    int outSignLength = sizeof(outSign);

    rv = kc_funcs->SignData((char *)alias, flags_sign, (char *)data, strlen(data), NULL, 0, outSign, &outSignLength);
    if (rv != 0) {
        char err_str[BUFFER_SIZE];
        int errLen = BUFFER_SIZE;
        kc_funcs->KC_GetLastErrorString(err_str, &errLen);
        fprintf(stderr, "SignData error: %x\nError message: %s\n", rv, err_str);
        exit(1);
    }

    strncpy(signed_data, (char *)outSign, outSignLength);
    signed_data[outSignLength] = '\0';

    printf("Successfully signed data:\n%s\n", signed_data);

    kc_funcs->KC_Finalize();
    dlclose(handle);
}

char *create_jws_signature(const char *payload, const char *p12_path, const char *password) {
    char *jws_signature = (char *)malloc(BUFFER_SIZE * sizeof(char));
    char *signed_data = (char *)malloc(BUFFER_SIZE * sizeof(char));

    // Захардкоженный сертификат в base64
    const char *cert_base64 = "MIIElDCCBD6gAwIBAgIUW5hhR6EvhCHYE6/gxrQpj8X+Y5IwDQYJKoMOAwoBAQECBQAwUzELMAkGA1UEBhMCS1oxRDBCBgNVBAMMO9Kw0JvQotCi0KvSmiDQmtCj05jQm9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr0pogKEdPU1QpMB4XDTI0MDMxNDA4Mzk0NloXDTI1MDMxNDA4Mzk0NlowggEmMTUwMwYDVQQDDCzQk9Ce0JzQl9Cv0JrQntCS0JAg0JjQoNCY0J3QkCDQrtCg0KzQldCS0J3QkDEbMBkGA1UEBAwS0JPQntCc0JfQr9Ca0J7QktCQMRgwFgYDVQQFEw9JSU44NTExMTUwMDEzNDAxCzAJBgNVBAYTAktaMYGOMIGLBgNVBAoMgYPQotC+0LLQsNGA0LjRidC10YHRgtCy0L4g0YEg0L7Qs9GA0LDQvdC40YfQtdC90L3QvtC5INC+0YLQstC10YLRgdGC0LLQtdC90L3QvtGB0YLRjNGOICJEcmVpZGVsIEZpbmFuY2UgKNCU0YDQtdC50LTQuyDQpNC40L3QsNC90YEpIjEYMBYGA1UECwwPQklOMjIwNDQwMDQxOTM4MGwwJQYJKoMOAwoBAQEBMBgGCiqDDgMKAQEBAQEGCiqDDgMKAQMBAQADQwAEQDrr5G8FGs7XMpOLbaWwO7V2+5uZ+UuPbHGxsaycaScvfgeEit2EkffPLuUpMK7VlLVv/kPupEjKOsk5Hq7Aj0ujggIDMIIB/zAOBgNVHQ8BAf8EBAMCBsAwKAYDVR0lBCEwHwYIKwYBBQUHAwQGCCqDDgMDBAECBgkqgw4DAwQBAgEwXgYDVR0gBFcwVTBTBgcqgw4DAwIBMEgwIQYIKwYBBQUHAgEWFWh0dHA6Ly9wa2kuZ292Lmt6L2NwczAjBggrBgEFBQcCAjAXDBVodHRwOi8vcGtpLmdvdi5rei9jcHMwWAYDVR0fBFEwTzBNoEugSYYiaHR0cDovL2NybC5wa2kuZ292Lmt6L25jYV9nb3N0LmNybIYjaHR0cDovL2NybDEucGtpLmdvdi5rei9uY2FfZ29zdC5jcmwwXAYDVR0uBFUwUzBRoE+gTYYkaHR0cDovL2NybC5wa2kuZ292Lmt6L25jYV9kX2dvc3QuY3JshiVodHRwOi8vY3JsMS5wa2kuZ292Lmt6L25jYV9kX2dvc3QuY3JsMGMGCCsGAQUFBwEBBFcwVTAvBggrBgEFBQcwAoYjaHR0cDovL3BraS5nb3Yua3ovY2VydC9uY2FfZ29zdC5jZXIwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnBraS5nb3Yua3owHQYDVR0OBBYEFNuYYUehL4Qh2BOv4Ma0KY/F/mOSMA8GA1UdIwQIMAaABFtqc+kwFgYGKoMOAwMFBAwwCgYIKoMOAwMFAQEwDQYJKoMOAwoBAQECBQADQQBctb1j4kVFj2w53k8+4IC2mooApbvMIPW6MfnMW3dlKQ+t4XaZ4jfF4Sw9UDVQv7905z8uzirEHQY3Vttn7zq3";

    // Подписание данных
    load_and_sign_data(payload, signed_data, p12_path, password);

    // Создание JSON Web Signature (JWS)
    json_t *jws_signature_obj = json_object();
    json_t *jws_signature_header = json_object();
    json_t *jws_signature_signatures = json_array();

    // Заполнение JOSE Header
    json_object_set_new(jws_signature_header, "x5c", json_pack("[s]", cert_base64));
    json_object_set_new(jws_signature_header, "alg", json_string("ECGOST34310"));

    json_t *jws_signature_signature_obj = json_object();
    json_object_set_new(jws_signature_signature_obj, "header", jws_signature_header);
    json_object_set_new(jws_signature_signature_obj, "signature", json_string(signed_data));

    json_array_append_new(jws_signature_signatures, jws_signature_signature_obj);

    // Base64 encode payload for JWS
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

int main() {
    // Чтение JSON файла для получения payload
    FILE *file = fopen("payload.json", "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open JSON file\n");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *payload = (char *)malloc(file_size + 1);
    fread(payload, 1, file_size, file);
    payload[file_size] = '\0';
    fclose(file);

    const char *p12_path = "./GOSTKNCA.p12";
    const char *password = "Aa1234";

    char *jws_signature = create_jws_signature(payload, p12_path, password);
    printf("JWS Signature: %s\n", jws_signature);

    // Кодирование JWS строки в base64
    char jws_base64[BUFFER_SIZE];
    base64_encode((unsigned char *)jws_signature, strlen(jws_signature), jws_base64);

    printf("Base64-encoded JWS: %s\n", jws_base64);

    free(payload);
    free(jws_signature);

    return 0;
}
