/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef APPLICATION_RESOURCE_RECORDER_H
#define APPLICATION_RESOURCE_RECORDER_H

#include <stack>
#include "config.h"

extern "C" {

/// Pointing to an instance
typedef void *instance_ptr_t;

/// Destructor function type
typedef void (*instance_destructor_func_t)(instance_ptr_t);

/// A structure to hold an item
typedef struct item_t {
    instance_ptr_t instance;
    instance_destructor_func_t destructorFunc;
} item_t;

};

/// A collector to record dynamic allocated objects
///
/// At the end of the recorder's life-time, all registered objects will be destructed automatically.
/// You do not need to call free() or fclose() on each item before exit(ERROR).
///
/// Usage:
/// ```
/// #include <stdlib.h>
/// #include "ApplicationResourceRecorder.h"
/// int main ()
/// {
///     ApplicationResourceRecorder recorder;
///     long int *lp = malloc(sizeof(*lp));
///     recorder.registerInstance(lp, free);
///     FILE *fp;
///     if (fp = fopen("data.txt", "rb")) {
///         recorder.registerInstance(fp, (instance_destructor_func_t)fclose);
///     }
///
///     // ...
///
///     // if (ErrorHappened()) {
///     //     exit(255);
///     // }
///
///     // ...
///     return (0);
/// }
/// ```
class ApplicationResourceRecorder {
public:
    void registerInstance(instance_ptr_t instance, instance_destructor_func_t destructorFunc);
    ApplicationResourceRecorder();
    ~ApplicationResourceRecorder();

private:
    std::stack<item_t> m_items;
};

#endif /* APPLICATION_RESOURCE_RECORDER_H */
