/****************************************************************************
 *  Copyright (C) 2024 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ***************************************************************************/
#define LOG_TAG "connection_manager"

#include "connection_manager.h"
#include "bluetooth.h"

typedef struct
{
    bool inited;
} bt_connection_manager_t;

static bt_connection_manager_t g_connection_manager;

void bt_cm_init(void)
{
    bt_connection_manager_t* manager = &g_connection_manager;

    if (manager->inited)
        return;

    manager->inited = true;
}

void bt_cm_cleanup(void)
{
    bt_connection_manager_t* manager = &g_connection_manager;

    if (!manager->inited)
        return;

    manager->inited = false;
}

bt_status_t bt_cm_enable_enhanced_mode(bt_address_t* addr, uint8_t mode)
{
    switch (mode) {
    default:
        return BT_STATUS_NOT_SUPPORTED;
    }
}

bt_status_t bt_cm_disable_enhanced_mode(bt_address_t* addr, uint8_t mode)
{
    switch (mode) {
    default:
        return BT_STATUS_NOT_SUPPORTED;
    }
}