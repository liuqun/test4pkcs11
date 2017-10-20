/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef SYMBOL_FROM_RC_H_
#define SYMBOL_FROM_RC_H_

#include "config.h"

#ifndef HAVE_STDINT_H
#error // 找不到 stdint.h
#endif
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 二分查找 Cryptoki 错误码对应的字符串符号名 */
const char *symbol_from_rc(uint32_t rc);

#ifdef __cplusplus
}; // end of extern "C"
#endif

#endif /* SYMBOL_FROM_RC_H_ */
