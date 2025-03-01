/*
 * This file is auto-generated by jsongensource.py, Do not modify it directly!
 */

/*
 * Copyright (C) 2023 Xiaomi Corporation. All rights reserved.
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
 *
 */
#include "bluetooth.h"
#include "bt_adapter.h"
#include "feature_bluetooth.h"
#include "feature_exports.h"
#include "feature_log.h"
#include "system_bluetooth.h"
#include "system_bluetooth_bt.h"

#define file_tag "system_bluetooth"

void system_bluetooth_onRegister(const char* feature_name)
{
    FEATURE_LOG_DEBUG("%s::%s()", file_tag, __FUNCTION__);
}

void system_bluetooth_onCreate(FeatureRuntimeContext ctx, FeatureProtoHandle handle)
{
    feature_bluetooth_init_bt_ins(FEATURE_BLUETOOTH, handle);
    FEATURE_LOG_DEBUG("%s::%s()", file_tag, __FUNCTION__);
}

void system_bluetooth_onRequired(FeatureRuntimeContext ctx, FeatureInstanceHandle handle)
{
    feature_bluetooth_add_feature_callback(handle, FEATURE_BLUETOOTH);
    FEATURE_LOG_DEBUG("%s::%s()", file_tag, __FUNCTION__);
}

void system_bluetooth_onDetached(FeatureRuntimeContext ctx, FeatureInstanceHandle handle)
{
    feature_bluetooth_free_feature_callback(handle, FEATURE_BLUETOOTH);
    FEATURE_LOG_DEBUG("%s::%s()", file_tag, __FUNCTION__);
}

void system_bluetooth_onDestroy(FeatureRuntimeContext ctx, FeatureProtoHandle handle)
{
    feature_bluetooth_uninit_bt_ins(FEATURE_BLUETOOTH, handle);
    FEATURE_LOG_DEBUG("%s::%s()", file_tag, __FUNCTION__);
}

void system_bluetooth_onUnregister(const char* feature_name)
{
    FEATURE_LOG_DEBUG("%s::%s()", file_tag, __FUNCTION__);
}

void system_bluetooth_wrap_openAdapter(FeatureInstanceHandle feature, AppendData append_data, system_bluetooth_OpenAdapterParams* params)
{
    bt_status_t status = bt_adapter_enable(feature_bluetooth_get_bt_ins(feature));
    if (status == BT_STATUS_SUCCESS) {
        if (!FeatureInvokeCallback(feature, params->success)) {
            FEATURE_LOG_ERROR("invoke success openAdapter callback failed, feature is %p, params->success is %d!", feature, params->success);
        }
    } else {
        if (!FeatureInvokeCallback(feature, params->fail, "enable fail!", status)) {
            FEATURE_LOG_ERROR("invoke fail openAdapter callback failed!");
        }
    }
    if (!FeatureInvokeCallback(feature, params->complete)) {
        FEATURE_LOG_ERROR("invoke complete openAdapter callback failed!");
    }

    FeatureRemoveCallback(feature, params->success);
    FeatureRemoveCallback(feature, params->fail);
    FeatureRemoveCallback(feature, params->complete);
}

void system_bluetooth_wrap_closeAdapter(FeatureInstanceHandle feature, AppendData append_data, system_bluetooth_CloseAdapterParams* params)
{
    bt_status_t status = bt_adapter_disable(feature_bluetooth_get_bt_ins(feature));
    if (status == BT_STATUS_SUCCESS) {
        if (!FeatureInvokeCallback(feature, params->success)) {
            FEATURE_LOG_ERROR("invoke success closeAdapter callback failed!");
        }
    } else {
        if (!FeatureInvokeCallback(feature, params->fail, "enable fail!", status)) {
            FEATURE_LOG_ERROR("invoke fail closeAdapter callback failed!");
        }
    }
    if (!FeatureInvokeCallback(feature, params->complete)) {
        FEATURE_LOG_ERROR("invoke complete closeAdapter callback failed!");
    }

    FeatureRemoveCallback(feature, params->success);
    FeatureRemoveCallback(feature, params->fail);
    FeatureRemoveCallback(feature, params->complete);
}

void system_bluetooth_wrap_getAdapterState(FeatureInstanceHandle feature, AppendData append_data, system_bluetooth_GetAdapterStateParams* params)
{
    bt_instance_t* ins = feature_bluetooth_get_bt_ins(feature);
    bt_adapter_state_t state = bt_adapter_get_state(ins);
    bool is_discovering = bt_adapter_is_discovering(ins);
    system_bluetooth_GetAdapterSuccessResult* success_result = system_bluetoothMallocGetAdapterSuccessResult();
    success_result->available = state == BT_ADAPTER_STATE_ON;
    success_result->discovering = is_discovering;

    if (!FeatureInvokeCallback(feature, params->success, success_result)) {
        FEATURE_LOG_ERROR("invoke success getAdapterState callback failed!");
    }

    FeatureFreeValue(success_result);

    if (!FeatureInvokeCallback(feature, params->complete)) {
        FEATURE_LOG_ERROR("invoke complete getAdapterState callback failed!");
    }

    FeatureRemoveCallback(feature, params->success);
    FeatureRemoveCallback(feature, params->fail);
    FeatureRemoveCallback(feature, params->complete);
}

FtCallbackId system_bluetooth_get_onadapterstatechange(void* feature, AppendData append_data)
{
    return feature_bluetooth_get_feature_callback(feature, ON_ADAPTER_STATE_CHANGE);
}

void system_bluetooth_set_onadapterstatechange(void* feature, AppendData append_data, FtCallbackId onadapterstatechange)
{
    FEATURE_LOG_DEBUG("set onadapterstatechange feature: %p, callbackId: %d", feature, onadapterstatechange);
    feature_bluetooth_set_feature_callback(feature, onadapterstatechange, ON_ADAPTER_STATE_CHANGE);
}
