#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#if _WIN32
#define FFI_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FFI_PLUGIN_EXPORT
#endif

FFI_PLUGIN_EXPORT const unsigned char* get_txt_proof(
    const char* sockaddr,
    const char* query_name,
    int* result_len,
    const char** error_msg
);

FFI_PLUGIN_EXPORT void free_error_string(const char* error_msg);
