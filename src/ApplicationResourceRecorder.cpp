/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include "ApplicationResourceRecorder.h"
#include "config.h"

void ApplicationResourceRecorder::registerInstance(instance_ptr_t instance, instance_destructor_func_t destructorFunc)
{
    item_t item;

    item.destructorFunc = destructorFunc;
    item.instance = instance;
    m_items.push(item);
}

ApplicationResourceRecorder::ApplicationResourceRecorder()
{
}

ApplicationResourceRecorder::~ApplicationResourceRecorder()
{
    while(!m_items.empty()) {
        item_t& item = m_items.top();
        m_items.pop();
        if (!item.destructorFunc) {
            continue;
        }
        item.destructorFunc(item.instance);
    }
}
