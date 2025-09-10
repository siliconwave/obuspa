/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2016-2024  CommScope, Inc
 * Copyright (C) 2020, BT PLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file device_local_agent.c
 *
 * Implements the Device.LocalAgent data model object
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdbool.h>
#include <unistd.h>  // at the top of the file
#include "usp_err_codes.h"
#include "common_defs.h"
#include "usp_api.h"
#include "dm_access.h"
#include "data_model.h"
#include "device.h"
#include "version.h"
#include "nu_macaddr.h"
#include "nu_ipaddr.h"
#include "text_utils.h"
#include "uptime.h"
#include "hostname.h"
#include "iso8601.h"
#include "os_utils.h"
#include "bdc_exec.h"



//------------------------------------------------------------------------------
// Cached version of the endpoint_id, which is populated at boot up by DEVICE_LOCAL_AGENT_SetDefaults()
static char agent_endpoint_id[MAX_ENDPOINT_ID_LEN] = {0};

//------------------------------------------------------------------------------
// By default when a stop of USP Agent is scheduled, it just exits rather than rebooting
exit_action_t scheduled_exit_action = kExitAction_Exit;

#ifndef REMOVE_DEVICE_BOOT_EVENT
//------------------------------------------------------------------------------
// Database paths to parameters associated with rebooting and whether firmware has been activated
char *reboot_cause_path = "Internal.Reboot.Cause";
char *reboot_reason_path = "Internal.Reboot.Reason";
static char *reboot_command_key_path = "Internal.Reboot.CommandKey";
static char *reboot_request_instance_path = "Internal.Reboot.RequestInstance";
static char *last_software_version_path = "Internal.Reboot.LastSoftwareVersion";

static char *default_reboot_cause_str = "LocalReboot";
static char *default_reboot_reason_str = "Unknown";
#endif

//------------------------------------------------------------------------------
// Database paths associated with device parameters
static char *manufacturer_oui_path = "Device.DeviceInfo.ManufacturerOUI";
static char *serial_number_path = "Device.DeviceInfo.SerialNumber";
static char *endpoint_id_path = "Device.LocalAgent.EndpointID";

//------------------------------------------------------------------------------
// Number of seconds after reboot at which USP Agent was started
static unsigned usp_agent_start_time;

#ifndef REMOVE_DEVICE_BOOT_EVENT
//------------------------------------------------------------------------------
// Cause of last reboot, and other variables calculated at Boot-up time related to cause of reboot
static reboot_info_t reboot_info = { 0 };
#endif

//------------------------------------------------------------------------------
// Variables relating to Dual Stack preference - whether to prefer IPv4 or IPv6 addresses, when both are available eg on an interface or DNS resolution
char *dual_stack_preference_path = "Internal.DualStackPreference";
static bool dual_stack_prefer_ipv6 = false;


#ifndef REMOVE_DEVICE_SCHEDULE_TIMER
//------------------------------------------------------------------------------
// Structure containing input conditions for ScheduleTimer task
typedef struct
{
    int request_instance;
    time_t time_ref;
    unsigned delay_seconds;
} sched_timer_input_cond_t;

//------------------------------------------------------------------------------------
// Array of valid input arguments for ScheduleTimer() operation
static char *sched_timer_input_args[] =
{
    "DelaySeconds",
};

// Forward declarations for functions related to ScheduleTimer
int Start_ScheduleTimer(dm_req_t *req, kv_vector_t *input_args, int instance);
void *ScheduleTimerThreadMain(void *param);
int Restart_ScheduleTimer(dm_req_t *req, int instance, bool *is_restart, int *err_code, char *err_msg, int err_msg_len, kv_vector_t *output_args);
#endif

//------------------------------------------------------------------------------------
// Array of valid input arguments for Reboot() command
#ifndef REMOVE_DEVICE_REBOOT
static char *reboot_input_args[] =
{
    "Cause",
    "Reason",
};
#endif

//------------------------------------------------------------------------------------
// Array of valid input arguments for FactoryReset() command
#ifndef REMOVE_DEVICE_FACTORY_RESET
static char *factory_reset_input_args[] =
{
    "Cause",
    "Reason",
};
#endif

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int Validate_DualStackPreference(dm_req_t *req, char *value);
int NotifyChange_DualStackPreference(dm_req_t *req, char *value);
int GetAgentUpTime(dm_req_t *req, char *buf, int len);
int GetDefaultOUI(char *buf, int len);
int GetDefaultSerialNumber(char *buf, int len);
int GetDefaultEndpointID(char *buf, int len, char *oui, char *serial_number);
int GetActiveSoftwareVersion(dm_req_t *req, char *buf, int len);

#ifndef REMOVE_DEVICE_INFO
int GetHardwareVersion(dm_req_t *req, char *buf, int len);
int GetKernelUpTime(dm_req_t *req, char *buf, int len);
int GetHostName(dm_req_t *req, char *value, int len);
int SetHostName(dm_req_t *req, char *value);
int GetOSName(dm_req_t *req, char *buf, int len);
int GetOSVersion(dm_req_t *req, char *buf, int len);
int GetKernelVersion(dm_req_t *req, char *buf, int len);
int GetArchitecture(dm_req_t *req, char *buf, int len);
int GetCPUCount(dm_req_t *req, char *buf, int len);
int GetIPAddress(dm_req_t *req, char *buf, int len);
int GetMACAddress(dm_req_t *req, char *buf, int len);
int GetPublicIP(dm_req_t *req, char *buf, int len);
int GetTimezone(dm_req_t *req, char *buf, int len);
int GetLocation(dm_req_t *req, char *buf, int len);
int GetStorageUsed(dm_req_t *req, char *buf, int len);
int GetStorageAvailable(dm_req_t *req, char *buf, int len);
int GetMemoryUsed(dm_req_t *req, char *buf, int len);
int GetMemoryAvailable(dm_req_t *req, char *buf, int len);
int GetCPUUsage(dm_req_t *req, char *buf, int len);
#endif

#ifndef REMOVE_DEVICE_REBOOT
int ScheduleReboot(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args);
#endif
#ifndef REMOVE_DEVICE_FACTORY_RESET
int ScheduleFactoryReset(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args);
#endif
#ifndef REMOVE_DEVICE_BOOT_EVENT
int PopulateRebootInfo(void);
#endif

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_Init
**
** Initialises this component, and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int DEVICE_LOCAL_AGENT_Init(void)
{
    int err = USP_ERR_OK;

    // Register parameters implemented by this component
    // NOTE: Device.LocalAgent.EndpointID is registered in DEVICE_LOCAL_AGENT_RegisterEndpointID()
    err = USP_ERR_OK;
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.LocalAgent.UpTime", GetAgentUpTime, DM_UINT);





    // Register supported protocols and software version
    err |= USP_REGISTER_Param_SupportedList("Device.LocalAgent.SupportedProtocols", mtp_protocols, NUM_ELEM(mtp_protocols));
    err |= USP_REGISTER_Param_Constant("Device.LocalAgent.SoftwareVersion", AGENT_SOFTWARE_VERSION, DM_STRING);

#ifndef REMOVE_DEVICE_SCHEDULE_TIMER
    // Register ScheduleTimer operation
    err |= USP_REGISTER_AsyncOperation("Device.ScheduleTimer()", Start_ScheduleTimer, Restart_ScheduleTimer);
    err |= USP_REGISTER_OperationArguments("Device.ScheduleTimer()", sched_timer_input_args, NUM_ELEM(sched_timer_input_args), NULL, 0);
#endif

#ifndef REMOVE_DEVICE_REBOOT
    // Register Reboot operation
    err |= USP_REGISTER_SyncOperation("Device.Reboot()", ScheduleReboot);
    err |= USP_REGISTER_OperationArguments("Device.Reboot()", reboot_input_args, NUM_ELEM(reboot_input_args), NULL, 0);
#endif

#ifndef REMOVE_DEVICE_FACTORY_RESET
    // Register Factory Reset operation
    err |= USP_REGISTER_SyncOperation("Device.FactoryReset()", ScheduleFactoryReset);
    err |= USP_REGISTER_OperationArguments("Device.FactoryReset()", factory_reset_input_args, NUM_ELEM(factory_reset_input_args), NULL, 0);
#endif

#ifndef REMOVE_DEVICE_BOOT_EVENT
    // Register parameters associated with tracking the cause of a reboot
    err |= USP_REGISTER_DBParam_ReadWrite(reboot_cause_path, "FactoryReset", NULL, NULL, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(reboot_reason_path, "Unknown", NULL, NULL, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(reboot_command_key_path, "", NULL, NULL, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(reboot_request_instance_path, "-1", NULL, NULL, DM_INT);
    err |= USP_REGISTER_DBParam_ReadWrite(last_software_version_path, "", NULL, NULL, DM_STRING);


#endif

#ifndef REMOVE_DEVICE_INFO
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.SoftwareVersion", GetActiveSoftwareVersion, DM_STRING);
    err |= USP_REGISTER_Param_Constant("Device.DeviceInfo.ProductClass", VENDOR_PRODUCT_CLASS, DM_STRING);
    err |= USP_REGISTER_Param_Constant("Device.DeviceInfo.Manufacturer", VENDOR_MANUFACTURER, DM_STRING);
    err |= USP_REGISTER_Param_Constant("Device.DeviceInfo.ModelName", VENDOR_MODEL_NAME, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.HardwareVersion", GetHardwareVersion, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadWrite(
    "Device.DeviceInfo.HostName",
    GetHostName,
    SetHostName,
    NULL,
    DM_STRING
);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.OSName", GetOSName, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.OSVersion", GetOSVersion, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.KernelVersion", GetKernelVersion, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.Architecture", GetArchitecture, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.CPUCount", GetCPUCount, DM_UINT);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.IPAddress", GetIPAddress, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.MACAddress", GetMACAddress, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.PublicIP", GetPublicIP, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.Timezone", GetTimezone, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.Location", GetLocation, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.StorageUsed", GetStorageUsed, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.StorageAvailable", GetStorageAvailable, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.MemoryUsed", GetMemoryUsed, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.MemoryAvailable", GetMemoryAvailable, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.CPUUsage", GetCPUUsage, DM_STRING);

    err |= USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.UpTime", GetKernelUpTime, DM_UINT);

    // NOTE: The default values of these database parameters are setup later in DEVICE_LOCAL_AGENT_SetDefaults()
    err |= USP_REGISTER_DBParam_ReadOnly(manufacturer_oui_path, "", DM_STRING);
    err |= USP_REGISTER_DBParam_ReadOnly(serial_number_path, "", DM_STRING);
#endif

    // NOTE: The default value of this database parameter is setup later in DEVICE_LOCAL_AGENT_SetDefaults()
    err |= USP_REGISTER_DBParam_ReadOnly(endpoint_id_path, "", DM_STRING);

    err |= USP_REGISTER_DBParam_ReadWrite(dual_stack_preference_path, "IPv4", Validate_DualStackPreference, NotifyChange_DualStackPreference, DM_STRING);
    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_SetDefaults
**
** Sets the default values for the database parameters: OUI, SerialNumber and EndpointID
** And caches the value of the retrieved EndpointID
** NOTE: This can only be performed after vendor hooks have been registered and after any factory reset (if required)
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_LOCAL_AGENT_SetDefaults(void)
{
    int err;
    char default_value[MAX_DM_SHORT_VALUE_LEN];
    char oui[MAX_DM_SHORT_VALUE_LEN];
    char serial_number[MAX_DM_SHORT_VALUE_LEN];

    //-------------------------------------------------------------
    // ManufacturerOUI
    // Exit if unable to get the default value of ManufacturerOUI (ie the value if not overridden by the USP DB)
    // This is either set by an environment variable or failing that, set by VENDOR_OUI define in vendor_defs.h
    err = GetDefaultOUI(default_value, sizeof(default_value));
    if (err != USP_ERR_OK)
    {
        return err;
    }

#ifndef REMOVE_DEVICE_INFO
    // Register the default value of OUI (if DeviceInfo parameters are being registered by USP Agent core)
    err = DM_PRIV_ReRegister_DBParam_Default(manufacturer_oui_path, default_value);
    if (err != USP_ERR_OK)
    {
        return err;
    }
#endif

    // Get the actual value of OUI
    // This may be the value in the USP DB, the default value (if not present in DB) or a value retrieved by vendor hook (if REMOVE_DEVICE_INFO is defined)
    err = DATA_MODEL_GetParameterValue(manufacturer_oui_path, oui, sizeof(oui), DONT_LOG_NOT_REGISTERED_ERROR);

#ifdef REMOVE_DEVICE_INFO
    // If vendor has not registered Device.DeviceInfo.ManufacturerOUI, then use the default value
    if (err == USP_ERR_INVALID_PATH)
    {
        USP_LOG_Warning("%s: WARNING: No implementation of Device.DeviceInfo.ManufacturerOUI registered. Using OUI=%s", __FUNCTION__, default_value);
        USP_STRNCPY(oui, default_value, sizeof(oui));
        err = USP_ERR_OK;
    }
#endif

    if (err != USP_ERR_OK)
    {
        return err;
    }

    //-------------------------------------------------------------
    // SERIAL NUMBER
    // Exit if unable to get the default value of Serial Number (ie the value if not overridden by the USP DB)
    // This is either set by a vendor hook, failing that by an environment variable, or failing that by the MAC address of the WAN interface
    err = GetDefaultSerialNumber(default_value, sizeof(default_value));
    if (err != USP_ERR_OK)
    {
        return err;
    }

#ifndef REMOVE_DEVICE_INFO
    // Register the default value of SerialNumber (if DeviceInfo parameters are being registered by USP Agent core)
    err = DM_PRIV_ReRegister_DBParam_Default(serial_number_path, default_value);
    if (err != USP_ERR_OK)
    {
        return err;
    }
#endif

    // Get the actual value of Serial Number
    // This may be the value in the USP DB, the default value (if not present in DB) or a value retrieved by vendor hook (if REMOVE_DEVICE_INFO is defined)
    err = DATA_MODEL_GetParameterValue(serial_number_path, serial_number, sizeof(serial_number), DONT_LOG_NOT_REGISTERED_ERROR);

#ifdef REMOVE_DEVICE_INFO
    // If vendor has not registered Device.DeviceInfo.SerialNumber, then use the default value
    if (err == USP_ERR_INVALID_PATH)
    {
        USP_LOG_Warning("%s: WARNING: No implementation of Device.DeviceInfo.SerialNumber registered. Using SerialNumber=%s", __FUNCTION__, default_value);
        USP_STRNCPY(serial_number, default_value, sizeof(serial_number));
        err = USP_ERR_OK;
    }
#endif

    if (err != USP_ERR_OK)
    {
        return err;
    }

    //-------------------------------------------------------------
    // ENDPOINT_ID
    // Exit if unable to get the default value of EndpointID (ie the value if not overridden by the USP DB)
    // This is either set by a vendor hook, or failing that formed using the OUI and serial numbers retrieved above
    err = GetDefaultEndpointID(default_value, sizeof(default_value), oui, serial_number);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Register the default value of Device.LocalAgent.EndpointID
    err = DM_PRIV_ReRegister_DBParam_Default(endpoint_id_path, default_value);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Get the actual value of Device.LocalAgent.EndpointID
    // This may be the value in the USP DB or the default value (if not present in DB)
    err = DATA_MODEL_GetParameterValue(endpoint_id_path, agent_endpoint_id, sizeof(agent_endpoint_id), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_Start
**
** Starts this component, adding all instances to the data model
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_LOCAL_AGENT_Start(void)
{
    int err;
    char value[MAX_DM_SHORT_VALUE_LEN];

    // Get the time (after boot) at which USP Agent was started
    usp_agent_start_time = (unsigned)tu_uptime_secs();

#ifndef REMOVE_DEVICE_BOOT_EVENT
    PopulateRebootInfo();
#endif

    // Exit if unable to get the Dual stack preference for IPv4 or IPv6
    err = DATA_MODEL_GetParameterValue(dual_stack_preference_path, value, sizeof(value), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Cache the Dual stack preference in 'dual_stack_prefer_ipv6'
    NotifyChange_DualStackPreference(NULL, value);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_Stop
**
** Frees all memory used by this component
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void DEVICE_LOCAL_AGENT_Stop(void)
{
#ifndef REMOVE_DEVICE_BOOT_EVENT
    USP_SAFE_FREE(reboot_info.cause);
    USP_SAFE_FREE(reboot_info.reason);
    USP_SAFE_FREE(reboot_info.command_key);
    USP_SAFE_FREE(reboot_info.cur_software_version);
    USP_SAFE_FREE(reboot_info.last_software_version);
#endif
}

#if !defined(REMOVE_DEVICE_REBOOT) || !defined(REMOVE_DEVICE_FACTORY_RESET)
/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_ScheduleReboot
**
** Schedules a reboot to occur once all connections have finished sending.
**
** \param   exit_action - action to perform on exit
** \param   reboot_cause - cause of reboot
** \param   reboot_reason - reason for reboot
** \param   command_key - pointer to string containing the command key for this operation
** \param   request_instance - instance number of the request that initiated the reboot, or INVALID if reboot was not initiated by an operation
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_LOCAL_AGENT_ScheduleReboot(exit_action_t exit_action, char *reboot_cause, char *reboot_reason, char *command_key, int request_instance)
{
#ifndef REMOVE_DEVICE_BOOT_EVENT
    int err;

    // Exit if unable to persist the cause of reboot
    err = DATA_MODEL_SetParameterValue(reboot_cause_path, reboot_cause, 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to persist the reason for reboot
    err = DATA_MODEL_SetParameterValue(reboot_reason_path, reboot_reason, 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to persist the command key, so that it can be returned in the Boot event
    err = DATA_MODEL_SetParameterValue(reboot_command_key_path, command_key, 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to persist the request instance of the operation which caused the reboot
    err = DM_ACCESS_SetInteger(reboot_request_instance_path, request_instance);
    if (err != USP_ERR_OK)
    {
        return err;
    }
#endif

    scheduled_exit_action = exit_action;
#ifndef REMOVE_DEVICE_BULKDATA
    BDC_EXEC_ScheduleExit();
#endif
    MTP_EXEC_ScheduleExit();
    return USP_ERR_OK;
}
#endif

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_GetExitAction
**
** Returns what action to perform when gracefully exiting USP Agent
** This function is called during a scheduled exit, once all responses have been sent,
** to determine whether to just exit, or to reboot, or to factory reset
** NOTE: This function may be called from any thread
**
** \param   None
**
** \return  action to perform
**
**************************************************************************/
exit_action_t DEVICE_LOCAL_AGENT_GetExitAction(void)
{
    return scheduled_exit_action;
}

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_GetEndpointID
**
** Returns the cached value of the EndpointID of this device
** NOTE: This function is threadsafe as the value does not change after being
** determined. It is determined after VENDOR_Init(), but before VENDOR_Start() is called
**
** \param   None
**
** \return  pointer to string containing EndpointID
**
**************************************************************************/
char *DEVICE_LOCAL_AGENT_GetEndpointID(void)
{
    return agent_endpoint_id;
}

#ifndef REMOVE_DEVICE_BOOT_EVENT
/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_GetRebootInfo
**
** Gets the cause of the last reboot and associated data
**
** \param   reboot_info - pointer to structure in which to return the information
**
** \return  None
**
**************************************************************************/
void DEVICE_LOCAL_AGENT_GetRebootInfo(reboot_info_t *info)
{
    memcpy(info, &reboot_info, sizeof(reboot_info_t));
}
#endif

/*********************************************************************//**
**
** DEVICE_LOCAL_AGENT_GetDualStackPreference
**
** Gets the value of Device.DualStackPreference as a boolean
** NOTE: This function may be called from any thread
**
** \param   None
**
** \return  true if IPv6 is preferred over IPv4, if the WAN interface or DNS lookup supports both
**
**************************************************************************/
bool DEVICE_LOCAL_AGENT_GetDualStackPreference(void)
{
    return dual_stack_prefer_ipv6;
}


/*********************************************************************//**
**
** Validate_DualStackPreference
**
** Function called to validate Internal.DualStackPreference
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_DualStackPreference(dm_req_t *req, char *value)
{
    // Exit if new value is valid
    if ((strcmp(value, "IPv4")==0) || (strcmp(value, "IPv6")==0))
    {
        return USP_ERR_OK;
    }

    // Otherwise value is invalid
    USP_ERR_SetMessage("%s: Only allowed values are 'IPv4' or 'IPv6'", __FUNCTION__);
    return USP_ERR_INVALID_VALUE;
}

/*********************************************************************//**
**
** NotifyChange_DualStackPreference
**
** Function called after Internal.DualStackPreference is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_DualStackPreference(dm_req_t *req, char *value)
{
    // Set local cached copy of this value
    if (strcmp(value, "IPv6")==0)
    {
        // Prefer IPv6, if interface or DNS resolution has an IPv4 and IPv6 address
        dual_stack_prefer_ipv6 = true;
    }
    else
    {
        // Default to preferring IPv4
        dual_stack_prefer_ipv6 = false;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetAgentUpTime
**
** Gets the number of seconds that the agent software has been running (Device.LocalAgent.UpTime)
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetAgentUpTime(dm_req_t *req, char *buf, int len)
{
    val_uint = (unsigned)tu_uptime_secs() - usp_agent_start_time;

    return USP_ERR_OK;
}


// getter prototype
int GetHostName(dm_req_t *req, char *value, int len)
{
    (void)req;
    if (gethostname(value, (size_t)len) != 0)
    {
        if (len > 0)
            value[0] = '\0';
        return USP_ERR_INTERNAL_ERROR;
    }
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** SetHostName
**
** Sets the system hostname
**
** \param   req - pointer to structure identifying the parameter
** \param   value - new hostname value to set
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if failed to set hostname
**
**************************************************************************/
int SetHostName(dm_req_t *req, char *value)
{
    int result;
    char cmd[256];

    (void)req;  // Unused parameter

    // Validate hostname format
    if (value == NULL || strlen(value) == 0)
    {
        USP_ERR_SetMessage("%s: Hostname cannot be empty", __FUNCTION__);
        return USP_ERR_INVALID_VALUE;
    }

    if (strlen(value) > 63)
    {
        USP_ERR_SetMessage("%s: Hostname too long (max 63 characters)", __FUNCTION__);
        return USP_ERR_INVALID_VALUE;
    }

    // Check for valid hostname characters (letters, numbers, hyphens)
    for (int i = 0; value[i] != '\0'; i++)
    {
        char c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-'))
        {
            USP_ERR_SetMessage("%s: Invalid hostname character '%c'. Only letters, numbers, and hyphens allowed", __FUNCTION__, c);
            return USP_ERR_INVALID_VALUE;
        }
    }

    // Don't allow hostname to start or end with hyphen
    if (value[0] == '-' || value[strlen(value)-1] == '-')
    {
        USP_ERR_SetMessage("%s: Hostname cannot start or end with hyphen", __FUNCTION__);
        return USP_ERR_INVALID_VALUE;
    }

    USP_LOG_Info("%s: Setting hostname to '%s'", __FUNCTION__, value);

    // Set the hostname using sethostname() system call
    result = sethostname(value, strlen(value));
    if (result != 0)
    {
        USP_ERR_ERRNO("sethostname", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Also update /etc/hostname for persistence across reboots
    snprintf(cmd, sizeof(cmd), "echo '%s' > /etc/hostname", value);
    result = system(cmd);
    if (result != 0)
    {
        USP_LOG_Warning("%s: Failed to update /etc/hostname (exit code: %d). Hostname change may not persist after reboot.", __FUNCTION__, result);
        // Don't return error here as the immediate hostname change was successful
    }

    // Update /etc/hosts to map the new hostname to localhost
    snprintf(cmd, sizeof(cmd), "sed -i 's/127.0.1.1.*/127.0.1.1\\t%s/' /etc/hosts 2>/dev/null || echo '127.0.1.1\\t%s' >> /etc/hosts", value, value);
    result = system(cmd);
    if (result != 0)
    {
        USP_LOG_Warning("%s: Failed to update /etc/hosts (exit code: %d)", __FUNCTION__, result);
        // Don't return error here as the main hostname change was successful
    }

    USP_LOG_Info("%s: Hostname successfully set to '%s'", __FUNCTION__, value);
    return USP_ERR_OK;
}


#ifndef REMOVE_DEVICE_INFO
/*********************************************************************//**
**
** GetKernelUpTime
**
** Gets the total number of seconds that the cpe has been running (Device.DeviceInfo.UpTime)
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/



int GetKernelUpTime(dm_req_t *req, char *buf, int len)
{
    struct sysinfo info;
    int err;

    // Exit if unable to get the uptime of the Linux kernel
    err = sysinfo(&info);
    if (err != 0)
    {
        USP_ERR_ERRNO("sysinfo", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    val_uint = (unsigned)info.uptime;

    return USP_ERR_OK;
}
#endif


#ifndef REMOVE_DEVICE_REBOOT
/*********************************************************************//**
**
** ScheduleReboot
**
** Sync Operation handler for the Reboot operation
** The vendor reboot function will be called once all connections have finished sending.
** eg after the response message for this operation has been sent
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   command_key - pointer to string containing the command key for this operation
** \param   input_args - vector containing input arguments and their values
** \param   output_args - vector to return output arguments in
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ScheduleReboot(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
    int err;
    char *cause;
    char *reason;

    // Ensure that no output arguments are returned for this sync operation
    USP_ARG_Init(output_args);

    // Exit if reboot cause is not valid
    cause = USP_ARG_Get(input_args, "Cause", "RemoteReboot");
    if ((strcmp(cause, "LocalReboot") != 0) && (strcmp(cause, "RemoteReboot") != 0))
    {
        USP_ERR_SetMessage("%s: Invalid reboot Cause argument (`%s`)", __FUNCTION__, cause);
        return USP_ERR_INVALID_ARGUMENTS;
    }

    reason = USP_ARG_Get(input_args, "Reason", "Unknown");
    err = DEVICE_LOCAL_AGENT_ScheduleReboot(kExitAction_Reboot, cause, reason, command_key, INVALID);

    return err;
}
#endif

#ifndef REMOVE_DEVICE_FACTORY_RESET
/*********************************************************************//**
**
** ScheduleFactoryReset
**
** Sync Operation handler for the FactoryReset
** The vendor reboot function will be called once all connections have finished sending.
** eg after the response message for this operation has been sent
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   command_key - pointer to string containing the command key for this operation
** \param   input_args - vector containing input arguments and their values
** \param   output_args - vector to return output arguments in
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ScheduleFactoryReset(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
    int err;
    char *cause;
    char *reason;

    // Ensure that no output arguments are returned for this sync operation
    USP_ARG_Init(output_args);

    // Exit if reboot cause is not valid
    cause = USP_ARG_Get(input_args, "Cause", "RemoteFactoryReset");
    if ((strcmp(cause, "LocalFactoryReset") != 0) && (strcmp(cause, "RemoteFactoryReset") != 0))
    {
        USP_ERR_SetMessage("%s: Invalid reboot Cause argument (`%s`)", __FUNCTION__, cause);
        return USP_ERR_INVALID_ARGUMENTS;
    }

    reason = USP_ARG_Get(input_args, "Reason", "Unknown");
    err = DEVICE_LOCAL_AGENT_ScheduleReboot(kExitAction_FactoryReset, cause, reason, command_key, INVALID);

    return err;
}
#endif

/*********************************************************************//**
**
** GetDefaultOUI
**
** Gets the default OUI for this CPE
** This is the value of OUI if it is not overriden by a value in the USP DB
**
** \param   buf - pointer to buffer in which to return the default value
** \param   len = length of buffer
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetDefaultOUI(char *buf, int len)
{
    char *p;

    // Exit if OUI set by environment variable
    p = getenv("USP_BOARD_OUI");
    if ((p != NULL) && (*p != '\0'))
    {
        USP_STRNCPY(buf, p, len);
        return USP_ERR_OK;
    }

    // Otherwise use compile time OUI
    USP_STRNCPY(buf, VENDOR_OUI, len);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetDefaultSerialNumber
**
** Gets the default serial number for this CPE
** This is the value of serial number if it is not overriden by a value in the USP DB
**
** \param   buf - pointer to buffer in which to return the default value
** \param   len = length of buffer
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetDefaultSerialNumber(char *buf, int len)
{
    int err;
    dm_vendor_get_agent_serial_number_cb_t   get_agent_serial_number_cb;
    unsigned char mac_addr[MAC_ADDR_LEN];
    char *p;
    int i;
    int val;

    // Exit if serial number is determined by a vendor hook
    get_agent_serial_number_cb = vendor_hook_callbacks.get_agent_serial_number_cb;
    if (get_agent_serial_number_cb != NULL)
    {
        err = get_agent_serial_number_cb(buf, len);
        if (err != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s: get_agent_endpoint_id_cb() failed", __FUNCTION__);
            return USP_ERR_INTERNAL_ERROR;
        }

        return USP_ERR_OK;
    }

    // Exit if serial number set by environment variable
    p = getenv("USP_BOARD_SERIAL");
    if ((p != NULL) && (*p != '\0'))
    {
        USP_STRNCPY(buf, p, len);
        return USP_ERR_OK;
    }

    // Otherwise use serial number set by MAC address (default)
    err = nu_macaddr_wan_macaddr(mac_addr);
    if (err != USP_ERR_OK)
    {
        // If unable to get the WAN interface's MAC address, then set serial number to 'undefined'
        USP_LOG_Warning("%s: WARNING: Unable to determine a serial number for this device", __FUNCTION__);
        USP_STRNCPY(buf, "undefined", len);
        return USP_ERR_OK;
    }

    // Convert MAC address into ASCII string form
    USP_ASSERT(len > 2*MAC_ADDR_LEN+1);
    p = buf;
    for (i=0; i<MAC_ADDR_LEN; i++)
    {
        val = mac_addr[i];
        *p++ = TEXT_UTILS_ValueToHexDigit( (val & 0xF0) >> 4, USE_UPPERCASE_HEX_DIGITS );
        *p++ = TEXT_UTILS_ValueToHexDigit( val & 0x0F, USE_UPPERCASE_HEX_DIGITS );
    }
    *p = '\0';

    return USP_ERR_OK;
}


/*********************************************************************//**
**
** GetDefaultEndpointID
**
** Gets the default endpoint_id for this CPE
** This is the value of endpoint_id if it is not overriden by a value in the USP DB
**
** \param   buf - pointer to buffer in which to return the endpoint_id of this CPE
** \param   len - length of endpoint_id return buffer
** \param   oui - pointer to string containing oui of device
** \param   serial_number - pointer to string containing serial number of device
**
** \return  None
**
**************************************************************************/
int GetDefaultEndpointID(char *buf, int len, char *oui, char *serial_number)
{
    int err;
    dm_vendor_get_agent_endpoint_id_cb_t   get_agent_endpoint_id_cb;
    char oui_encoded[MAX_DM_SHORT_VALUE_LEN];
    char serial_number_encoded[MAX_DM_SHORT_VALUE_LEN];

    // Exit if endpoint_id is determined by a vendor hook
    get_agent_endpoint_id_cb = vendor_hook_callbacks.get_agent_endpoint_id_cb;
    if (get_agent_endpoint_id_cb != NULL)
    {
        err = get_agent_endpoint_id_cb(buf, len);
        if (err != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s: get_agent_endpoint_id_cb() failed", __FUNCTION__);
            return USP_ERR_INTERNAL_ERROR;
        }

        return USP_ERR_OK;
    }

    // Percent encode the OUI and serial number
    #define SAFE_CHARS "-._"
    TEXT_UTILS_PercentEncodeString(oui, oui_encoded, sizeof(oui_encoded), SAFE_CHARS, USE_UPPERCASE_HEX_DIGITS);
    TEXT_UTILS_PercentEncodeString(serial_number, serial_number_encoded, sizeof(serial_number_encoded), SAFE_CHARS, USE_UPPERCASE_HEX_DIGITS);

    // Form the final endpoint_id
    USP_SNPRINTF(buf, len, "os::%s-%s", oui_encoded, serial_number_encoded);

    return USP_ERR_OK;
}


#ifndef REMOVE_DEVICE_BOOT_EVENT
/*********************************************************************//**
**
** PopulateRebootInfo
**
** Cache the cause (and command key) of the last reboot, then
** setup the default cause and command key for the next reboot.
** This will be overridden if any other cause occurs
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int PopulateRebootInfo(void)
{
    int err;
    char last_value[MAX_DM_SHORT_VALUE_LEN];
    char cur_value[MAX_DM_SHORT_VALUE_LEN];
    char *last_version;
    modify_firmware_updated_cb_t  modify_firmware_updated_cb;

    // Set the default to indicate that the firmware image was not updated
    reboot_info.is_firmware_updated = false;

    //-------------------------------------------
    // Exit if unable to get the cause of the last reboot
    err = DATA_MODEL_GetParameterValue(reboot_cause_path, last_value, sizeof(last_value), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Cache the cause of the last reboot
    reboot_info.cause = USP_STRDUP(last_value);

    // Set the default cause of the next reboot (if we need to because it's changed from the last)
    if (strcmp(last_value, default_reboot_cause_str) != 0)
    {
        // Exit if unable to set the default cause of reboot for next time
        err = DATA_MODEL_SetParameterValue(reboot_cause_path, default_reboot_cause_str, 0);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    //-------------------------------------------
    // Exit if unable to get the reason for the last reboot
    err = DATA_MODEL_GetParameterValue(reboot_reason_path, last_value, sizeof(last_value), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Cache the reason for the last reboot
    reboot_info.reason = USP_STRDUP(last_value);

    // Set the default reason for the next reboot (if we need to because it's changed from the last)
    if (strcmp(last_value, default_reboot_reason_str) != 0)
    {
        // Exit if unable to set the default cause of reboot for next time
        err = DATA_MODEL_SetParameterValue(reboot_reason_path, default_reboot_reason_str, 0);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    //-------------------------------------------
    // Exit if unable to get the command_key for the last reboot
    err = DATA_MODEL_GetParameterValue(reboot_command_key_path, last_value, sizeof(last_value), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Cache the command key associated with the last reboot
    reboot_info.command_key = USP_STRDUP(last_value);

    // Set the default command key associated with the next reboot (if we need to because it's changed from the last)
    if (last_value[0] != '\0')
    {
        // Exit if unable to set the default command_key for reboot for next time
        DATA_MODEL_SetParameterValue(reboot_command_key_path, "", 0);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    //-------------------------------------------
    // Exit if unable to determine whether the reboot was initiated by an operation
    err = DM_ACCESS_GetInteger(reboot_request_instance_path, &reboot_info.request_instance);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Set the default for whether the next reboot was initiated by an operation
    if (reboot_info.request_instance != INVALID)
    {
        // Exit if unable to set the default for next time
        DATA_MODEL_SetParameterValue(reboot_request_instance_path, "-1", 0);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    //-------------------------------------------
    // Exit if unable to get the software version that was used in the last boot cycle
    err = DATA_MODEL_GetParameterValue(last_software_version_path, last_value, sizeof(last_value), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Get the software version used in this boot cycle
    err = DATA_MODEL_GetParameterValue("Device.DeviceInfo.SoftwareVersion", cur_value, sizeof(cur_value), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    reboot_info.cur_software_version = USP_STRDUP(cur_value);

    // Save the last software version. Note that if this is from a factory reset, then use the current software version
    last_version = (last_value[0] == '\0') ? cur_value : last_value;
    reboot_info.last_software_version = USP_STRDUP(last_version);


    // Save the software version used in this boot cycle, so next boot cycle we can see if its changed
    err = DATA_MODEL_SetParameterValue(last_software_version_path, cur_value, 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // If the software version used in the last boot cycle differs from the one used
    // in this boot cycle, then the firmware has been updated, unless this was a factory reset
    if ((strcmp(last_value, cur_value) != 0) && (last_value[0] != '\0'))
    {
        reboot_info.is_firmware_updated = true;
    }

    // Modify the firmware updated flag using a core vendor hook (if registered)
    modify_firmware_updated_cb = vendor_hook_callbacks.modify_firmware_updated_cb;
    if (modify_firmware_updated_cb != NULL)
    {
        modify_firmware_updated_cb( &reboot_info.is_firmware_updated );
    }

    return USP_ERR_OK;
}
#endif

#ifndef REMOVE_DEVICE_INFO
/*********************************************************************//**
**
** GetActiveSoftwareVersion
**
** Gets the current running software version
** This must match the software version of the active firmware image
** Wrapper function around VENDOR_GetActiveSoftwareVersion(), so that req does not have to be passed to it
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if validated successfully
**
**************************************************************************/
int GetActiveSoftwareVersion(dm_req_t *req, char *buf, int len)
{
    int err;
    get_active_software_version_cb_t   get_active_software_version_cb;

    // Exit if unable to get the active software version from the vendor
    *buf = '\0';
    get_active_software_version_cb = vendor_hook_callbacks.get_active_software_version_cb;
    if (get_active_software_version_cb != NULL)
    {
        err = get_active_software_version_cb(buf, len);
        if (err != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s: get_active_software_version_cb() failed", __FUNCTION__);
            return err;
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetHardwareVersion
**
** Gets the hardware version of the board on which this software is running
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if validated successfully
**
**************************************************************************/
int GetHardwareVersion(dm_req_t *req, char *buf, int len)
{
    int err;
    get_hardware_version_cb_t   get_hardware_version_cb;
    char *p;

    // Get the hardware version from the vendor hook (if set), otherwise fallback to using the environment variable
    *buf = '\0';
    get_hardware_version_cb = vendor_hook_callbacks.get_hardware_version_cb;
    if (get_hardware_version_cb != NULL)
    {
        // Exit if unable to get the hardware version from the vendor
        err = get_hardware_version_cb(buf, len);
        if (err != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s: get_hardware_version_cb() failed", __FUNCTION__);
            return err;
        }
    }
    else
    {
        // Copy the hardware version, if specified by an environment variable
        p = getenv("USP_BOARD_HW_VERSION");
        if (p != NULL)
        {
            USP_STRNCPY(buf, p, len);
        }
    }

    return USP_ERR_OK;
}
#endif // REMOVE_DEVICE_INFO

#ifndef REMOVE_DEVICE_SCHEDULE_TIMER
/*********************************************************************//**
**
** Start_ScheduleTimer
**
** Starts the ScheduleTimer() operation
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   input_args - vector containing input arguments and their values
** \param   instance - instance number of this operation in the Device.LocalAgent.Request table
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Start_ScheduleTimer(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err;
    sched_timer_input_cond_t *cond = NULL;
    char buf[MAX_ISO8601_LEN];

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(sched_timer_input_cond_t));
    memset(cond, 0, sizeof(sched_timer_input_cond_t));
    cond->request_instance = instance;

    // Exit if an error in reading DelaySeconds, or DelaySeconds is not specified
    #define INVALID_DELAY_SECONDS 0xFFFFFFFF
    err = USP_ARG_GetUnsigned(input_args, "DelaySeconds", INVALID_DELAY_SECONDS, &cond->delay_seconds);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    if (cond->delay_seconds == INVALID_DELAY_SECONDS)
    {
        USP_ERR_SetMessage("%s: DelaySeconds argument not specified", __FUNCTION__);
        err = USP_ERR_INVALID_COMMAND_ARGS;
        goto exit;
    }

    // Exit if unable to extract the time at which this operation was issued
    // NOTE: This may not be the current time, if this operation is being restarted after a reboot that interrupted it
    err = USP_ARG_GetDateTime(input_args, SAVED_TIME_REF_ARG_NAME, iso8601_cur_time(buf, sizeof(buf)), &cond->time_ref);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Log the input conditions for the operation
    USP_LOG_Info("=== ScheduleTimer Conditions ===");
    USP_LOG_Info("TimeRef: %s", iso8601_from_unix_time(cond->time_ref, buf, sizeof(buf)) );
    USP_LOG_Info("DelaySeconds: %d", cond->delay_seconds);

    // Exit if unable to start a thread to perform this operation
    // NOTE: ownership of input conditions passes to the thread
    err = OS_UTILS_CreateThread("ScheduleTimer", ScheduleTimerThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

exit:
    // Exit if an error occurred (freeing the input conditions)
    if (err != USP_ERR_OK)
    {
        USP_FREE(cond);
        return err;
    }

    // Ownership of the input conditions has passed to the thread
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Restart_ScheduleTimer
**
** This function is called at bootup to determine whether to restart the ScheduleTimer() Async Operations
**
** \param   req - pointer to structure containing path information
** \param   instance - instance number of this operation in the Request table
** \param   is_restart - pointer to variable in which to return whether the operation should be restarted or not
**
**                     The following parameters are only used if the operation should not be restarted
**                     They determine the values placed in the operation complete message
** \param   err_code - pointer to variable in which to return an error code
** \param   err_msg - pointer to buffer in which to return an error message (only used if error code is failed)
** \param   err_msg_len - length of buffer in which to return an error message (only used if error code is failed)
** \param   output_args - pointer to structure in which to return output arguments for the operation
**
** \return  USP_ERR_OK if validated successfully
**
**************************************************************************/
int Restart_ScheduleTimer(dm_req_t *req, int instance, bool *is_restart, int *err_code, char *err_msg, int err_msg_len, kv_vector_t *output_args)
{
    *is_restart = true;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ScheduleTimerThreadMain
**
** Main function for ScheduleTimer Asynchronous operation thread
**
** \param   param - pointer to input conditions
**
** \return  NULL
**
**************************************************************************/
void *ScheduleTimerThreadMain(void *param)
{
    time_t cur_time;
    int delay;
    sched_timer_input_cond_t *cond = (sched_timer_input_cond_t *) param;

    // Calculate time left to delay for
    // NOTE: This number might be negative if the timer was scheduled to fire when the device was turned off
    cur_time = time(NULL);
    delay = (int)(cond->time_ref - cur_time) + cond->delay_seconds;

    // Wait until the timer is scheduled to fire
    if (delay > 0)
    {
        sleep(delay);
    }

    USP_LOG_Info("=== ScheduleTimer completed ===");
    USP_SIGNAL_OperationComplete(cond->request_instance, USP_ERR_OK, NULL, NULL);

    // Free the input conditions that were passed into this function as an argument
    USP_FREE(cond);

    return NULL;
}
#endif

/*********************************************************************//**
**
** GetOSName
**
** Gets the operating system name
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetOSName(dm_req_t *req, char *buf, int len)
{
    struct utsname uts;
    int err;
    
    err = uname(&uts);
    if (err != 0)
    {
        USP_ERR_ERRNO("uname", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    USP_STRNCPY(buf, uts.sysname, len);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetOSVersion
**
** Gets the operating system version
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetOSVersion(dm_req_t *req, char *buf, int len) 
{
    struct utsname uts;
    int err;
    FILE *fp;
    char os_release[256];
    char os_name[128] = "";
    char os_version[64] = "";
    char temp_buf[512];
    
    // Get basic system info
    err = uname(&uts);
    if (err != 0) {
        USP_ERR_ERRNO("uname", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Try to read OS release information from /etc/os-release (standard)
    fp = fopen("/etc/os-release", "r");
    if (fp != NULL) {
        while (fgets(os_release, sizeof(os_release), fp)) {
            // Remove newline
            os_release[strcspn(os_release, "\n")] = 0;
            
            // Parse PRETTY_NAME first (contains full name with version)
            if (strncmp(os_release, "PRETTY_NAME=", 12) == 0) {
                char *value = os_release + 12;
                // Remove quotes if present
                if (value[0] == '"') {
                    value++;
                    char *end_quote = strchr(value, '"');
                    if (end_quote) *end_quote = '\0';
                }
                USP_STRNCPY(buf, value, len);
                fclose(fp);
                return USP_ERR_OK;
            }
            
            // Parse NAME (OS name)
            if (strncmp(os_release, "NAME=", 5) == 0) {
                char *value = os_release + 5;
                if (value[0] == '"') {
                    value++;
                    char *end_quote = strchr(value, '"');
                    if (end_quote) *end_quote = '\0';
                }
                USP_STRNCPY(os_name, value, sizeof(os_name));
            }
            
            // Parse VERSION (version number)
            if (strncmp(os_release, "VERSION=", 8) == 0) {
                char *value = os_release + 8;
                if (value[0] == '"') {
                    value++;
                    char *end_quote = strchr(value, '"');
                    if (end_quote) *end_quote = '\0';
                }
                USP_STRNCPY(os_version, value, sizeof(os_version));
            }
        }
        fclose(fp);
        
        // If we have both name and version, combine them
        if (strlen(os_name) > 0 && strlen(os_version) > 0) {
            snprintf(temp_buf, sizeof(temp_buf), "%s %s", os_name, os_version);
            USP_STRNCPY(buf, temp_buf, len);
            return USP_ERR_OK;
        }
        // If we only have name, use that
        else if (strlen(os_name) > 0) {
            USP_STRNCPY(buf, os_name, len);
            return USP_ERR_OK;
        }
    }

    // Fallback: Try /etc/lsb-release (Ubuntu/Debian specific)
    fp = fopen("/etc/lsb-release", "r");
    if (fp != NULL) {
        while (fgets(os_release, sizeof(os_release), fp)) {
            os_release[strcspn(os_release, "\n")] = 0;
            
            // Parse DISTRIB_DESCRIPTION first (full description)
            if (strncmp(os_release, "DISTRIB_DESCRIPTION=", 20) == 0) {
                char *value = os_release + 20;
                if (value[0] == '"') {
                    value++;
                    char *end_quote = strchr(value, '"');
                    if (end_quote) *end_quote = '\0';
                }
                USP_STRNCPY(buf, value, len);
                fclose(fp);
                return USP_ERR_OK;
            }
            
            // Parse DISTRIB_ID (distribution name)
            if (strncmp(os_release, "DISTRIB_ID=", 11) == 0) {
                char *value = os_release + 11;
                USP_STRNCPY(os_name, value, sizeof(os_name));
            }
            
            // Parse DISTRIB_RELEASE (version number)
            if (strncmp(os_release, "DISTRIB_RELEASE=", 16) == 0) {
                char *value = os_release + 16;
                USP_STRNCPY(os_version, value, sizeof(os_version));
            }
        }
        fclose(fp);
        
        // Combine name and version from lsb-release
        if (strlen(os_name) > 0 && strlen(os_version) > 0) {
            snprintf(temp_buf, sizeof(temp_buf), "%s %s", os_name, os_version);
            USP_STRNCPY(buf, temp_buf, len);
            return USP_ERR_OK;
        }
    }

    // Fallback: Try reading specific distribution files
    // Check for Ubuntu version file
    fp = fopen("/etc/debian_version", "r");
    if (fp != NULL) {
        if (fgets(os_version, sizeof(os_version), fp)) {
            os_version[strcspn(os_version, "\n")] = 0;
            // Check if it's Ubuntu by looking for ubuntu in /proc/version
            FILE *proc_fp = fopen("/proc/version", "r");
            if (proc_fp != NULL) {
                char proc_version[512];
                if (fgets(proc_version, sizeof(proc_version), proc_fp)) {
                    if (strstr(proc_version, "Ubuntu") != NULL) {
                        snprintf(temp_buf, sizeof(temp_buf), "Ubuntu %s", os_version);
                    } else {
                        snprintf(temp_buf, sizeof(temp_buf), "Debian %s", os_version);
                    }
                    USP_STRNCPY(buf, temp_buf, len);
                    fclose(proc_fp);
                    fclose(fp);
                    return USP_ERR_OK;
                }
                fclose(proc_fp);
            }
        }
        fclose(fp);
    }

    // Check for CentOS/RHEL/Fedora
    fp = fopen("/etc/redhat-release", "r");
    if (fp != NULL) {
        if (fgets(temp_buf, sizeof(temp_buf), fp)) {
            temp_buf[strcspn(temp_buf, "\n")] = 0;
            USP_STRNCPY(buf, temp_buf, len);
            fclose(fp);
            return USP_ERR_OK;
        }
        fclose(fp);
    }

    // Final fallback: Use system name from uname with kernel version
    snprintf(temp_buf, sizeof(temp_buf), "%s %s", uts.sysname, uts.release);
    USP_STRNCPY(buf, temp_buf, len);
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetKernelVersion
**
** Gets the kernel version
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetKernelVersion(dm_req_t *req, char *buf, int len)
{
    struct utsname uts;
    int err;
    
    err = uname(&uts);
    if (err != 0)
    {
        USP_ERR_ERRNO("uname", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    USP_STRNCPY(buf, uts.release, len);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetArchitecture
**
** Gets the system architecture
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetArchitecture(dm_req_t *req, char *buf, int len)
{
    struct utsname uts;
    int err;
    
    err = uname(&uts);
    if (err != 0)
    {
        USP_ERR_ERRNO("uname", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    USP_STRNCPY(buf, uts.machine, len);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetCPUCount
**
** Gets the number of CPU cores
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetCPUCount(dm_req_t *req, char *buf, int len)
{
    long num_cpus;
    
    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus == -1)
    {
        USP_ERR_ERRNO("sysconf(_SC_NPROCESSORS_ONLN)", errno);
        val_uint = 1;
        return USP_ERR_INTERNAL_ERROR;
    }
    
    val_uint = (unsigned)num_cpus;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetIPAddress
**
** Gets the primary IP address
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetIPAddress(dm_req_t *req, char *buf, int len)
{
    struct ifaddrs *ifaddrs_ptr = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmp_addr_ptr = NULL;
    char addr_str[INET_ADDRSTRLEN];
    int err;
    
    USP_STRNCPY(buf, "unknown", len);
    
    err = getifaddrs(&ifaddrs_ptr);
    if (err != 0)
    {
        USP_ERR_ERRNO("getifaddrs", errno);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL) continue;
        
        if ((ifa->ifa_addr->sa_family == AF_INET) && 
            (strcmp(ifa->ifa_name, "lo") != 0) &&
            (ifa->ifa_flags & IFF_RUNNING))
        {
            tmp_addr_ptr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, tmp_addr_ptr, addr_str, INET_ADDRSTRLEN);
            USP_STRNCPY(buf, addr_str, len);
            break;
        }
    }
    
    if (ifaddrs_ptr != NULL)
    {
        freeifaddrs(ifaddrs_ptr);
    }
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetMACAddress
**
** Gets the MAC address of the primary interface
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetMACAddress(dm_req_t *req, char *buf, int len)
{
    struct ifaddrs *ifaddrs_ptr = NULL;
    struct ifaddrs *ifa = NULL;
    int sock = -1;
    struct ifreq ifr;
    char *p;
    int i, val;
    int err;
    unsigned char *mac_addr;
    
    USP_STRNCPY(buf, "unknown", len);
    
    // Get list of all network interfaces
    err = getifaddrs(&ifaddrs_ptr);
    if (err != 0)
    {
        USP_ERR_ERRNO("getifaddrs", errno);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Create socket for ioctl operations
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        USP_ERR_ERRNO("socket", errno);
        freeifaddrs(ifaddrs_ptr);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Find first non-loopback interface that's running
    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL) continue;
        
        // Skip loopback interface
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        // Check if interface is up and running
        if (!(ifa->ifa_flags & IFF_RUNNING)) continue;
        
        // Try to get MAC address for this interface
        memset(&ifr, 0, sizeof(ifr));
        USP_STRNCPY(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
        
        err = ioctl(sock, SIOCGIFHWADDR, &ifr);
        if (err == 0)
        {
            // Successfully got MAC address
            mac_addr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            
            // Check if it's not a null MAC address
            bool is_null = true;
            for (i = 0; i < MAC_ADDR_LEN; i++)
            {
                if (mac_addr[i] != 0)
                {
                    is_null = false;
                    break;
                }
            }
            
            if (!is_null)
            {
                // Format MAC address with colons
                USP_ASSERT(len > 2*MAC_ADDR_LEN+6);
                p = buf;
                for (i = 0; i < MAC_ADDR_LEN; i++)
                {
                    if (i > 0)
                    {
                        *p++ = ':';
                    }
                    val = mac_addr[i];
                    *p++ = TEXT_UTILS_ValueToHexDigit((val & 0xF0) >> 4, USE_LOWERCASE_HEX_DIGITS);
                    *p++ = TEXT_UTILS_ValueToHexDigit(val & 0x0F, USE_LOWERCASE_HEX_DIGITS);
                }
                *p = '\0';
                
                close(sock);
                freeifaddrs(ifaddrs_ptr);
                return USP_ERR_OK;
            }
        }
    }
    
    // Cleanup if no valid MAC address found
    close(sock);
    freeifaddrs(ifaddrs_ptr);
    
    return USP_ERR_OK; // Return OK but with "unknown" value
}

/*********************************************************************//**
**
** GetPublicIP
**
** Gets the public IP address (placeholder implementation)
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetPublicIP(dm_req_t *req, char *buf, int len)
{
    int sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    int err;
    
    USP_STRNCPY(buf, "unavailable", len);
    
    // Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        USP_ERR_ERRNO("socket", errno);
        return USP_ERR_OK; // Return OK but with "unavailable"
    }
    
    // Set up a connection to a well-known external address (Google DNS)
    // This doesn't actually send data, just determines routing
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53); // DNS port
    inet_pton(AF_INET, "8.8.8.8", &server_addr.sin_addr);
    
    // Connect to determine which local IP would be used
    err = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (err < 0)
    {
        USP_ERR_ERRNO("connect", errno);
        close(sock);
        return USP_ERR_OK; // Return OK but with "unavailable"
    }
    
    // Get the local address that would be used for this connection
    err = getsockname(sock, (struct sockaddr*)&local_addr, &addr_len);
    if (err < 0)
    {
        USP_ERR_ERRNO("getsockname", errno);
        close(sock);
        return USP_ERR_OK; // Return OK but with "unavailable"
    }
    
    // Convert the IP address to string
    if (inet_ntop(AF_INET, &local_addr.sin_addr, buf, len) == NULL)
    {
        USP_ERR_ERRNO("inet_ntop", errno);
        close(sock);
        return USP_ERR_OK; // Return OK but with "unavailable"
    }
    
    close(sock);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTimezone
**
** Gets the system timezone
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTimezone(dm_req_t *req, char *buf, int len)
{
    FILE *fp;
    char *timezone = NULL;
    size_t timezone_len = 0;
    ssize_t read_len;
    
    fp = fopen("/etc/timezone", "r");
    if (fp == NULL)
    {
        char *tz_env = getenv("TZ");
        if (tz_env != NULL)
        {
            USP_STRNCPY(buf, tz_env, len);
        }
        else
        {
            USP_STRNCPY(buf, "unknown", len);
        }
        return USP_ERR_OK;
    }
    
    read_len = getline(&timezone, &timezone_len, fp);
    fclose(fp);
    
    if (read_len > 0)
    {
        if (timezone[read_len - 1] == '\n')
        {
            timezone[read_len - 1] = '\0';
        }
        USP_STRNCPY(buf, timezone, len);
        free(timezone);
    }
    else
    {
        USP_STRNCPY(buf, "unknown", len);
        if (timezone)
        {
            free(timezone);
        }
    }
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetLocation
**
** Gets the device location (placeholder implementation)
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetLocation(dm_req_t *req, char *buf, int len)
{
    // Simple placeholder coordinates - you can modify these or implement GPS detection
    USP_STRNCPY(buf, "37.7749,-122.4194", len); // San Francisco coordinates as example
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetStorageUsed
**
** Gets the used storage space in bytes for root filesystem
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetStorageUsed(dm_req_t *req, char *buf, int len)
{
    struct statvfs vfs;
    unsigned long long used_bytes;
    int err;
    
    err = statvfs("/", &vfs);
    if (err != 0)
    {
        USP_ERR_ERRNO("statvfs", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Calculate used space: (total blocks - free blocks) * block size
    used_bytes = (unsigned long long)(vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize;
    
    USP_SNPRINTF(buf, len, "%llu", used_bytes);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetStorageAvailable
**
** Gets the available storage space in bytes for root filesystem
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetStorageAvailable(dm_req_t *req, char *buf, int len)
{
    struct statvfs vfs;
    unsigned long long available_bytes;
    int err;
    
    err = statvfs("/", &vfs);
    if (err != 0)
    {
        USP_ERR_ERRNO("statvfs", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Available space: available blocks * block size
    available_bytes = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
    
    USP_SNPRINTF(buf, len, "%llu", available_bytes);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetMemoryUsed
**
** Gets the used memory in bytes
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetMemoryUsed(dm_req_t *req, char *buf, int len)
{
    struct sysinfo info;
    unsigned long long used_bytes;
    int err;
    
    err = sysinfo(&info);
    if (err != 0)
    {
        USP_ERR_ERRNO("sysinfo", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Calculate used memory: total - free - buffers - cached
    used_bytes = (unsigned long long)(info.totalram - info.freeram - info.bufferram) * info.mem_unit;
    
    USP_SNPRINTF(buf, len, "%llu", used_bytes);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetMemoryAvailable
**
** Gets the available memory in bytes
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetMemoryAvailable(dm_req_t *req, char *buf, int len)
{
    struct sysinfo info;
    unsigned long long available_bytes;
    int err;
    
    err = sysinfo(&info);
    if (err != 0)
    {
        USP_ERR_ERRNO("sysinfo", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Available memory: free + buffers + cached
    available_bytes = (unsigned long long)(info.freeram + info.bufferram) * info.mem_unit;
    
    USP_SNPRINTF(buf, len, "%llu", available_bytes);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetCPUUsage
**
** Gets the current CPU usage percentage
**
** \param   req - pointer to structure containing path information
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetCPUUsage(dm_req_t *req, char *buf, int len)
{
    FILE *fp;
    char line[256];
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    unsigned long long total, idle_total;
    static unsigned long long prev_total = 0, prev_idle = 0;
    double cpu_usage = 0.0;
    
    fp = fopen("/proc/stat", "r");
    if (fp == NULL)
    {
        USP_ERR_ERRNO("fopen(/proc/stat)", errno);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Read the first line (overall CPU stats)
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        USP_ERR_ERRNO("fgets", errno);
        fclose(fp);
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    fclose(fp);
    
    // Parse CPU times: user, nice, system, idle, iowait, irq, softirq, steal
    if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) != 8)
    {
        USP_STRNCPY(buf, "unknown", len);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Calculate totals
    idle_total = idle + iowait;
    total = user + nice + system + idle + iowait + irq + softirq + steal;
    
    // Calculate CPU usage percentage (only if we have previous values)
    if (prev_total != 0)
    {
        unsigned long long total_diff = total - prev_total;
        unsigned long long idle_diff = idle_total - prev_idle;
        
        if (total_diff > 0)
        {
            cpu_usage = ((double)(total_diff - idle_diff) / total_diff) * 100.0;
        }
    }
    
    // Store current values for next calculation
    prev_total = total;
    prev_idle = idle_total;
    
    USP_SNPRINTF(buf, len, "%.1f%%", cpu_usage);
    return USP_ERR_OK;
}
