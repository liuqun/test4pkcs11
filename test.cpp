/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <set>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include "config.h"
#ifndef HAVE_OPENCRYPTOKI_PKCS11_H
#error // 找不到 opencryptoki/pkcs11.h
#endif
#include <opencryptoki/pkcs11.h>
#include "ApplicationResourceRecorder.h"
#include "pkcs11-api-loader.h"

CK_RV print_slot_info(CK_SLOT_INFO slot_info);
CK_RV print_token_info(CK_TOKEN_INFO token_info);
CK_RV print_info(CK_INFO info);

int main(int argc, char *argv[])
{
    CK_FUNCTION_LIST_PTR function_ptr = NULL;
    CK_RV rc;
    pkcs11_api_t *api;
    ApplicationResourceRecorder recorder;

    api = new_pkcs11_api_instance("/usr/lib/opencryptoki/libopencryptoki.so");
    if (!api) {
        fprintf(stderr, "Error initializing the PKCS11 library\n");
        exit(0xFF);
    }
    recorder.registerInstance((instance_ptr_t)api, (instance_destructor_func_t)delete_pkcs11_api_instance);

    function_ptr = api->functions;

    /* PKCS#11 library initialize */
    rc = function_ptr->C_Initialize(NULL);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error initializing the PKCS#11 library: rc=%X\n", (int)rc);
        exit(0xFF);
    }
    recorder.registerInstance(NULL, (instance_destructor_func_t) function_ptr->C_Finalize);

    if (rc == CKR_OK) {
        CK_INFO info;

        /* Get the PKCS11 infomation structure */
        rc = function_ptr->C_GetInfo(&info);
        if (rc != CKR_OK) {
            printf("Error getting PKCS#11 info: 0x%X\n", (int)rc);
        } else {
            print_info(info);
        }
    }

    do {
        CK_ULONG slot_count = 0;

        /* Find out how many tokens are present in the slots */
        rc = function_ptr->C_GetSlotList(TRUE, NULL, &slot_count);
        if (rc != CKR_OK) {
            printf("Error getting number of slots: 0x%X\n", (int)rc);
            break;
        }
        if (slot_count > 0) {
            int i;
            CK_SLOT_ID_PTR slot_list = NULL;

            slot_list = (CK_SLOT_ID_PTR) calloc(slot_count, sizeof(CK_SLOT_ID));
            recorder.registerInstance(slot_list, free);
            rc = function_ptr->C_GetSlotList(TRUE, slot_list, &slot_count);

            /* Display token info and slot info for each slot ID in "slot_list" */
            for (i = 0; i < slot_count; i++) {
                CK_RV token_info_err;
                CK_RV slot_info_err;
                CK_TOKEN_INFO token_info; ///< Structure to hold token information
                CK_SLOT_INFO slot_info; ///< Structure to hold slot information
                CK_SLOT_ID id;

                id = slot_list[i];
                token_info_err = function_ptr->C_GetTokenInfo(id, &token_info);
                slot_info_err = function_ptr->C_GetSlotInfo(id, &slot_info);
                if (token_info_err) {
                    printf("Error getting token info: 0x%X\n", (int)token_info_err);
                }
                if (slot_info_err) {
                    printf("Error getting the slot info: 0x%X\n", (int)slot_info_err);
                }
                if (token_info_err || slot_info_err) {
                    continue;
                }
                printf("Token #%d Info:\n", (int)id);
                print_token_info(token_info);
                printf("Slot #%d Info\n", (int)id);
                print_slot_info(slot_info);
                /* Check the mechanism set supported by current token */
                {
                    int j;
                    CK_ULONG mechanism_count = 0;
                    CK_MECHANISM_TYPE_PTR mechanism_list;
                    std::set<CK_MECHANISM_TYPE> mechanism_set;

                    /* Find out how many mechanisms are present */
                    rc = function_ptr->C_GetMechanismList(id, NULL, &mechanism_count);
                    if (rc != CKR_OK) {
                        printf("Error getting number of mechanisms: 0x%X\n", (int)rc);
                        continue;
                    }
                    printf("There are totally %d different mechanisms supported by Token #%d\n", (int)mechanism_count, (int)id);

                    mechanism_list = (CK_MECHANISM_TYPE_PTR) calloc(mechanism_count, sizeof(CK_MECHANISM_TYPE));
                    recorder.registerInstance(mechanism_list, free);
                    rc = function_ptr->C_GetMechanismList(id, mechanism_list, &mechanism_count);
                    mechanism_set.insert(mechanism_list, mechanism_list+mechanism_count);
                    {
                        CK_MECHANISM_INFO m;
                        const CK_MECHANISM_TYPE type = CKM_RSA_X_509;
                        const char *label= "CKM_RSA_X_509";
                        if (mechanism_set.count(type) >= 1) {
                            printf("%s is supported by Token #%d.\n", label, (int)id);

                            /* Get the Mechanism Info */
                            rc = function_ptr->C_GetMechanismInfo(id, type, &m);
                            if (rc != CKR_OK) {
                                printf("Error getting mechanisms info: 0x%X\n", (int)rc);
                            } else {
                                printf("\tKey Size: %d-%d\n", (int)m.ulMinKeySize, (int)m.ulMaxKeySize);
                                printf("\tFlags: 0x%X = [ %s%s%s%s%s%s%s%s%s%s%s%s%s]\n",
                                        (int) m.flags,
                                        m.flags & CKF_HW ? "HW " : "",
                                        m.flags & CKF_ENCRYPT ? "ENCR " : "",
                                        m.flags & CKF_DECRYPT ? "DECR " : "",
                                        m.flags & CKF_DIGEST ? "DGST " : "",
                                        m.flags & CKF_SIGN ? "SIGN " : "",
                                        m.flags & CKF_SIGN_RECOVER ? "SIGN_RCVR " : "",
                                        m.flags & CKF_VERIFY ? "VRFY " : "",
                                        m.flags & CKF_VERIFY_RECOVER ? "VRFY_RCVR " : "",
                                        m.flags & CKF_GENERATE ? "GEN " : "",
                                        m.flags & CKF_GENERATE_KEY_PAIR ? "GEN_KEY_PAIR " : "",
                                        m.flags & CKF_WRAP ? "WRAP " : "",
                                        m.flags & CKF_UNWRAP ? "UNWRAP " : "",
                                        m.flags & CKF_DERIVE ? "DERIVE " : "");
                            }
                        } else {
                            printf("Token #%d does not support %s.\n", (int)id, label);
                        }
                    }

                    mechanism_list = NULL;
                    mechanism_count = 0;
                }
            }

            slot_list = NULL;
        }
    } while (0);

    return 0;
}

CK_RV print_slot_info(CK_SLOT_INFO slot_info)
{
    /* Display the slot information */
    printf("\tDescription: %.64s\n", slot_info.slotDescription);
    printf("\tManufacturer: %.32s\n", slot_info.manufacturerID);
    printf("\tFlags: 0x%X\n", (int)slot_info.flags);
    printf("\tHardware Version: %d.%d\n", slot_info.hardwareVersion.major,
                                          slot_info.hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", slot_info.firmwareVersion.major,
                                          slot_info.firmwareVersion.minor);
    return CKR_OK;
}

CK_RV print_token_info(CK_TOKEN_INFO token_info)
{
    /* Display the token information */
    printf("\tLabel: %.32s\n", token_info.label);
    printf("\tManufacturer: %.32s\n", token_info.manufacturerID);
    printf("\tModel: %.16s\n", token_info.model);
    printf("\tSerial Number: %.16s\n", token_info.serialNumber);
    printf("\tFlags: 0x%X\n", (int)token_info.flags);
    printf("\tSessions: %d/%d\n", (int)token_info.ulSessionCount,
                                  (int)token_info.ulMaxSessionCount);
    printf("\tR/W Sessions: %d/%d\n", (int)token_info.ulRwSessionCount,
                                      (int)token_info.ulMaxRwSessionCount);
    printf("\tPIN Length: %d-%d\n", (int)token_info.ulMinPinLen,
                                    (int)token_info.ulMaxPinLen);
    printf("\tPublic Memory: 0x%X/0x%X\n", (int)token_info.ulFreePublicMemory,
                                           (int)token_info.ulTotalPublicMemory);
    printf("\tPrivate Memory: 0x%X/0x%X\n", (int)token_info.ulFreePrivateMemory,
                                           (int)token_info.ulTotalPrivateMemory);
    printf("\tHardware Version: %d.%d\n", (int)token_info.hardwareVersion.major,
                                          (int)token_info.hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", token_info.firmwareVersion.major,
                                          token_info.firmwareVersion.minor);
    printf("\tTime: %.16s\n", token_info.utcTime);
    return CKR_OK;
}

CK_RV print_info(CK_INFO info)
{
    /* display the header and information */
    printf("PKCS#11 Info\n");
    printf("\tVersion %d.%d \n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    printf("\tManufacturer: %.32s \n", info.manufacturerID);
    printf("\tFlags: 0x%lX  \n", info.flags);
    printf("\tLibrary Description: %.32s \n", info.libraryDescription);
    printf("\tLibrary Version %d.%d \n", info.libraryVersion.major, info.libraryVersion.minor);
    return CKR_OK;
}
