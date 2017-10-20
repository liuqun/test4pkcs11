/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include "config.h"

#ifndef HAVE_STDINT_H
#error // 找不到 stdint.h
#endif
#include <stdint.h>

#include "symbol-from-rc.h"

const struct {
    uint32_t rc;
    const char *symbol_description;
} CryptokiErrorTable[] = {
    /* Basic return codes */
    {0x00000000, "CKR_OK"},
    {0x00000001, "CKR_CANCEL"},
    {0x00000002, "CKR_HOST_MEMORY"},
    {0x00000003, "CKR_SLOT_ID_INVALID"},
    {0x00000004, "Warning! CKR_FLAGS_INVALID was removed since PKCS#11 standard v2.0"},
    {0x00000005, "CKR_GENERAL_ERROR"},
    {0x00000006, "CKR_FUNCTION_FAILED"},
    {0x00000007, "CKR_ARGUMENTS_BAD"},
    {0x00000008, "CKR_NO_EVENT"},
    {0x00000009, "CKR_NEED_TO_CREATE_THREADS"},
    {0x0000000A, "CKR_CANT_LOCK"},

    /* ATTRIBUTE errors: */
    {0x00000010, "CKR_ATTRIBUTE_READ_ONLY"},
    {0x00000011, "CKR_ATTRIBUTE_SENSITIVE"},
    {0x00000012, "CKR_ATTRIBUTE_TYPE_INVALID"},
    {0x00000013, "CKR_ATTRIBUTE_VALUE_INVALID"},

    /* DATA errors: */
    {0x00000020, "CKR_DATA_INVALID"},
    {0x00000021, "CKR_DATA_LEN_RANGE"},

    /* DEVICE errors: */
    {0x00000030, "CKR_DEVICE_ERROR"},
    {0x00000031, "CKR_DEVICE_MEMORY"},
    {0x00000032, "CKR_DEVICE_REMOVED"},

    /* ENCRYPTED_DATA errors: */
    {0x00000040, "CKR_ENCRYPTED_DATA_INVALID"},
    {0x00000041, "CKR_ENCRYPTED_DATA_LEN_RANGE"},

    /* FUNCTION errors: */
    {0x00000050, "CKR_FUNCTION_CANCELED"},
    {0x00000051, "CKR_FUNCTION_NOT_PARALLEL"},
    {0x00000054, "CKR_FUNCTION_NOT_SUPPORTED"},

    /* KEY errors: */
    {0x00000060, "CKR_KEY_HANDLE_INVALID"},
    {0x00000061, "Warning! CKR_KEY_SENSITIVE was removed since PKCS#11 standard v2.0"},
    {0x00000062, "CKR_KEY_SIZE_RANGE"},
    {0x00000063, "CKR_KEY_TYPE_INCONSISTENT"},
    {0x00000064, "CKR_KEY_NOT_NEEDED"},
    {0x00000065, "CKR_KEY_CHANGED"},
    {0x00000066, "CKR_KEY_NEEDED"},
    {0x00000067, "CKR_KEY_INDIGESTIBLE"},
    {0x00000068, "CKR_KEY_FUNCTION_NOT_PERMITTED"},
    {0x00000069, "CKR_KEY_NOT_WRAPPABLE"},
    {0x0000006A, "CKR_KEY_UNEXTRACTABLE"},

    /* MECHANISM errors: */
    {0x00000070, "CKR_MECHANISM_INVALID"},
    {0x00000071, "CKR_MECHANISM_PARAM_INVALID"},

    /* OBJECT errors: */
    {0x00000080, "CKR_OBJECT_CLASS_INCONSISTENT was removed since PKCS#11 standard v2.0"},
    {0x00000081, "CKR_OBJECT_CLASS_INVALID was removed since PKCS#11 standard v2.0"},
    {0x00000082, "CKR_OBJECT_HANDLE_INVALID"},

    /* OPERATION errors: */
    {0x00000090, "CKR_OPERATION_ACTIVE"},
    {0x00000091, "CKR_OPERATION_NOT_INITIALIZED"},

    /* PIN errors: */
    {0x000000A0, "CKR_PIN_INCORRECT"},
    {0x000000A1, "CKR_PIN_INVALID"},
    {0x000000A2, "CKR_PIN_LEN_RANGE"},
    {0x000000A3, "CKR_PIN_EXPIRED"},
    {0x000000A4, "CKR_PIN_LOCKED"},

    /* SESSION errors:
       I don't known why 0xB2 was missing */
    {0x000000B0, "CKR_SESSION_CLOSED"},
    {0x000000B1, "CKR_SESSION_COUNT"},
    {0x000000B3, "CKR_SESSION_HANDLE_INVALID"},
    {0x000000B4, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"},
    {0x000000B5, "CKR_SESSION_READ_ONLY"},
    {0x000000B6, "CKR_SESSION_EXISTS"},
    {0x000000B7, "CKR_SESSION_READ_ONLY_EXISTS"},
    {0x000000B8, "CKR_SESSION_READ_WRITE_SO_EXISTS"},

    /* SIGNATURE errors: */
    {0x000000C0, "CKR_SIGNATURE_INVALID"},
    {0x000000C1, "CKR_SIGNATURE_LEN_RANGE"},

    /* TEMPLATE errors: */
    {0x000000D0, "CKR_TEMPLATE_INCOMPLETE"},
    {0x000000D1, "CKR_TEMPLATE_INCONSISTENT"},

    /* TOKEN errors: */
    {0x000000E0, "CKR_TOKEN_NOT_PRESENT"},
    {0x000000E1, "CKR_TOKEN_NOT_RECOGNIZED"},
    {0x000000E2, "CKR_TOKEN_WRITE_PROTECTED"},

    /* UNWRAPPING errors: */
    {0x000000F0, "CKR_UNWRAPPING_KEY_HANDLE_INVALID"},
    {0x000000F1, "CKR_UNWRAPPING_KEY_SIZE_RANGE"},
    {0x000000F2, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"},

    /* USER errors: */
    {0x00000100, "CKR_USER_ALREADY_LOGGED_IN"},
    {0x00000101, "CKR_USER_NOT_LOGGED_IN"},
    {0x00000102, "CKR_USER_PIN_NOT_INITIALIZED"},
    {0x00000103, "CKR_USER_TYPE_INVALID"},
    {0x00000104, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"},
    {0x00000105, "CKR_USER_TOO_MANY_TYPES"},

    /* WRAPPED_KEY errors:
       I don't known why 0x111 was missing */
    {0x00000110, "CKR_WRAPPED_KEY_INVALID"},
    {0x00000112, "CKR_WRAPPED_KEY_LEN_RANGE"},
    {0x00000113, "CKR_WRAPPING_KEY_HANDLE_INVALID"},
    {0x00000114, "CKR_WRAPPING_KEY_SIZE_RANGE"},
    {0x00000115, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"},

    /* RNG errors: */
    {0x00000120, "CKR_RANDOM_SEED_NOT_SUPPORTED"},
    {0x00000121, "CKR_RANDOM_NO_RNG"},

    /* DOMAIN/BUFFER/STATE/INFORMATION stuffs: */
    {0x00000130, "CKR_DOMAIN_PARAMS_INVALID"},
    {0x00000150, "CKR_BUFFER_TOO_SMALL"},
    {0x00000160, "CKR_SAVED_STATE_INVALID"},
    {0x00000170, "CKR_INFORMATION_SENSITIVE"},
    {0x00000180, "CKR_STATE_UNSAVEABLE"},

    /* CRYPTOKI initialization errors (since v2.01) */
    {0x00000190, "CKR_CRYPTOKI_NOT_INITIALIZED"},
    {0x00000191, "CKR_CRYPTOKI_ALREADY_INITIALIZED"},

    /* MUTEX errors: */
    {0x000001A0, "CKR_MUTEX_BAD"},
    {0x000001A1, "CKR_MUTEX_NOT_LOCKED"},

    /* Other vendor defined errors: */
    {0x80000000, "CKR_VENDOR_DEFINED"},
};

const unsigned int COUNT = (
        sizeof(CryptokiErrorTable) / sizeof(CryptokiErrorTable[0])
        );

/* 二分查找指定的rc数字对应的符号字符串 */
const char *symbol_from_rc(uint32_t rc)
{
    const char *symbol;
    unsigned int mid;
    unsigned int start;
    unsigned int end;

    symbol = "undefined code";

    start = 0;
    end = COUNT - 1;
    while (start <= end) {
        mid = (start+end) / 2;
        if (CryptokiErrorTable[mid].rc == rc) {
            symbol = CryptokiErrorTable[mid].symbol_description;
            break;
        }
        if (rc > CryptokiErrorTable[mid].rc) {
            start = mid + 1;
        } else {
            /* rc < CryptokiErrorTable[mid].rc */
            end = mid - 1;
        }
    }
    return (symbol);
}
