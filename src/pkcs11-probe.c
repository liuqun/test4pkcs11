/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include "pkcs11-probe.h"

/* K&R 代码风格: 使用 4 个空格, 不使用 Tab */

typedef struct api_instance_t *api_t;
extern api_t new_api_instance();
extern void delete_api_instance(api_t instance);
extern probe_result_t api_probe(api_t api, const char *lib);
extern const char *api_which_lib(api_t api);

typedef void (*instance_cleanup_func_t)(void *instance);

struct api_instance_t {
    void *handle;
    char *from_which_lib;
    instance_cleanup_func_t cleanup;
};

static void dummy_instance_cleanup(void *instance)
{
    (void) instance; /* gcc -Wunused-parameter */
}

static void api_instance_init(struct api_instance_t *instance)
{
    instance->handle = NULL;
    instance->from_which_lib = NULL;
    instance->cleanup = dummy_instance_cleanup;
}

static void api_instance_cleanup(void *instance)
{
    api_t api;

    api = instance;
    if (api->handle) {
        dlclose(api->handle);
        api->handle = NULL;
    }
    if (api->from_which_lib) {
        free(api->from_which_lib);
        api->from_which_lib = NULL;
    }
    api->cleanup = dummy_instance_cleanup;
}


#include <string.h>

#ifndef __USE_XOPEN2K8
static char *strndup(const char *s, size_t n)
{
    char *dst;
    char *compact;
    int i;

    dst = malloc(n + 1);

    for (i = 0; i < n && *s; i++, s++) {
        dst[i] = *s;
    }
    dst[i] = '\0';
    if (i < n && (compact = realloc(dst, i + 1))) {
        dst = compact;
    }
    return dst;
}
#endif /* __USE_XOPEN2K8 */

probe_result_t api_probe(api_t self, const char *lib)
{
    void *handle;

    assert(self);
    self->cleanup(self);

    handle = NULL;
    handle = dlopen(lib, RTLD_NOW);
    if (!handle) {
        int rc = errno;
        fprintf(stderr, "Failed to open dll library: %s: rc=0x%X\n", dlerror(), rc);
        return PROBE_GENERIC_FAILURE;
    }

    self->handle = handle;
    const int MAX_BYTES = /* Hard-coded max filepath length: */ 1024;
    self->from_which_lib = strndup(lib, MAX_BYTES);
    self->cleanup = api_instance_cleanup;
    return (PROBE_SUCCESS);
}

const char *api_which_lib(api_t self)
{
    return (self->from_which_lib);
}

struct pkcs11_instance_t {
    struct api_instance_t api;
    CK_FUNCTION_LIST_PTR functions;
    instance_cleanup_func_t cleanup;
};

static void pkcs11_instance_cleanup(void *instance)
{
    pkcs11_t u;

    u.ptr = instance;

    /* First, clean up sub items. */
    u.api->cleanup(instance);
    /* Then reset each member variable. */
    u.pkcs11->functions = NULL;
    /* Last, relink clean-up function pointer to the dummy one. */
    u.pkcs11->cleanup = dummy_instance_cleanup;
}

probe_result_t pkcs11_probe(pkcs11_t self, const char *lib)
{
    CK_FUNCTION_LIST_PTR functions;
    CK_C_GetFunctionList C_GetFunctionList;

    assert(self.ptr);

    self.pkcs11->cleanup(self.ptr);

    if (lib && '\0' != lib[0]) {
        int rc = api_probe(self.api, lib);
        if (rc != PROBE_SUCCESS) {
            return rc;
        }
    }
    if (!lib || '\0' == lib[0]) {
        /* 如果调用者未指定动态库名称, 则从下列备选项中依次进行尝试 */
        const char *list[] = {"/usr/lib/opencryptoki/libopencryptoki.so", NULL};
        lib = list[0];
        do {
            if (api_probe(self.api, lib) == PROBE_SUCCESS) {
                break;
            }
            ++lib;
        } while(lib);
    }
    if (!lib) {
        return PROBE_GENERIC_FAILURE;
    }
    self.pkcs11->cleanup = pkcs11_instance_cleanup;

    /* Get the list of the PKCS11 functions this token supports */
    C_GetFunctionList = (CK_C_GetFunctionList) dlsym(self.api->handle, "C_GetFunctionList");
    if (!C_GetFunctionList) {
        int rc = errno;
        fprintf(stderr, "Error getting function list from DLL: %s: rc=0x%X\n", dlerror(), rc);
        return PROBE_GENERIC_FAILURE;
    }
    functions = NULL;
    C_GetFunctionList(&functions);
    /* FIXME: Error cases returned by C_GetFunctionList() should be checked here. */
    self.pkcs11->functions = functions;
    return PROBE_SUCCESS;
}

const char *pkcs11_which_lib(pkcs11_t instance)
{
    return (api_which_lib(instance.api));
}

const CK_FUNCTION_LIST_PTR pkcs11_get_api_function_list(pkcs11_t instance)
{
    return (instance.pkcs11->functions);
}

static void pkcs11_instance_init(struct pkcs11_instance_t *instance)
{
    assert(instance);

    api_instance_init(&(instance->api));
    instance->functions = NULL;
    instance->cleanup = dummy_instance_cleanup;
}

pkcs11_t new_pkcs11_instance()
{
    struct pkcs11_instance_t *instance;

    instance = malloc(sizeof(struct pkcs11_instance_t));
    assert(instance);
    pkcs11_instance_init(instance);
    return ((pkcs11_t) instance);
}

void delete_pkcs11_instance(pkcs11_t instance)
{
    if (!instance.ptr) {
        return;
    }
    instance.pkcs11->cleanup(instance.ptr);
    free(instance.pkcs11);
}
