#include "ruby.h"
#include "KalkanCrypt.h"
#include <dlfcn.h>

// Объявление указателя на структуру, которая будет хранить функции KalkanCrypt
static stKCFunctionsType *kc_funcs = NULL;

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

// Пример произвольного метода hello_world
static VALUE rb_hello_world(VALUE self, VALUE first_name, VALUE middle_name, VALUE last_name) {
    const char *first = StringValueCStr(first_name);
    const char *middle = StringValueCStr(middle_name);
    const char *last = StringValueCStr(last_name);

    char greeting[256];
    snprintf(greeting, sizeof(greeting), "Hello, %s %s %s!", first, middle, last);

    return rb_str_new2(greeting);
}

// Другие методы могут быть определены здесь

void Init_kalkancrypt() {
    VALUE mKalkanCrypt = rb_define_module("KalkanCrypt");
    VALUE cKalkanCrypt = rb_define_class_under(mKalkanCrypt, "KalkanCrypt", rb_cObject);

    rb_define_method(cKalkanCrypt, "init", rb_kalkancrypt_init, 0);
    rb_define_method(cKalkanCrypt, "hello_world", rb_hello_world, 3);

    // Добавьте определения других методов здесь
}
