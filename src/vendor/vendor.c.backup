// vendor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "usp_api.h"
#include "usp_err_codes.h"
#include "core/usp_log.h"

// ----------------------------------------------------------------------
// Forward declarations
int PackageUpdateOperation(dm_req_t *req, kv_vector_t *input_args, int instance);
void LogOperation(const char* operation, const char* message);
int VendorReboot(void);

// ----------------------------------------------------------------------
// Simple logging function for operations
void LogOperation(const char* operation, const char* message)
{
    USP_LOG_Info("%s: %s", operation, message);
}

// ----------------------------------------------------------------------
// Vendor Reboot Callback
int VendorReboot(void)
{
    USP_LOG_Info("VendorReboot: Initiating system reboot...");

    // Perform system reboot using the reboot command
    // This will actually reboot the system
    int result = system("reboot");

    if (result != 0) {
        USP_LOG_Error("VendorReboot: Failed to execute reboot command (exit code: %d)", result);
        // Try alternative reboot methods
        result = system("shutdown -r now");
        if (result != 0) {
            USP_LOG_Error("VendorReboot: Failed to execute shutdown command (exit code: %d)", result);
            // As a last resort, try systemctl
            result = system("systemctl reboot");
            if (result != 0) {
                USP_LOG_Error("VendorReboot: All reboot methods failed");
                return USP_ERR_INTERNAL_ERROR;
            }
        }
    }

    USP_LOG_Info("VendorReboot: Reboot command executed successfully");

    // The system should be rebooting now, but we'll exit the process anyway
    exit(0);

    return USP_ERR_OK;
}

// ----------------------------------------------------------------------
// Vendor Init Hook
int VENDOR_Init(void)
{
    vendor_hook_cb_t callbacks;

    USP_LOG_Info("VENDOR_Init: Registering vendor operations...");

    // Initialize vendor hook callbacks structure
    memset(&callbacks, 0, sizeof(callbacks));

    // Register reboot callback
    callbacks.reboot_cb = VendorReboot;

    // Register the vendor hook callbacks
    USP_REGISTER_CoreVendorHooks(&callbacks);

    // Register async operation
    USP_REGISTER_AsyncOperation("Device.PackageManager.UpdatePackage()",
                                PackageUpdateOperation,
                                NULL);

    return USP_ERR_OK;
}

// ----------------------------------------------------------------------
// Implementation: Generic Package Update with Progress Tracking
int PackageUpdateOperation(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err;
    char *url = NULL;
    char *package = NULL;
    kv_vector_t *output_args = NULL;

    // Get arguments (default NULL if missing)
    url = USP_ARG_Get(input_args, "URL", NULL);
    package = USP_ARG_Get(input_args, "PackageName", NULL);

    if ((package == NULL) || (strlen(package) == 0)) {
        USP_ERR_SetMessage("Missing required argument: PackageName");
        output_args = USP_ARG_Create();
        USP_ARG_Add(output_args, "Result", "MissingPackageName");
        USP_SIGNAL_OperationComplete(instance, USP_ERR_INVALID_ARGUMENTS, "Missing required argument: PackageName", output_args);
        return USP_ERR_OK; // Return OK since we handled the completion
    }

    USP_LOG_Info("PackageUpdateOperation: Package=%s, URL=%s",
                 package, (url ? url : "NULL"));

    char cmd[2048];
    char download_path[512];

    if ((url != NULL) && (strlen(url) > 0)) {
        // Case 1: Download from provided URL
        LogOperation("DOWNLOAD", "Starting package download");

        snprintf(download_path, sizeof(download_path), "/tmp/%s.deb", package);

        // Remove existing file if it exists
        unlink(download_path);

        // Enhanced wget command with better error handling and longer timeout
        snprintf(cmd, sizeof(cmd),
                 "/usr/bin/wget --timeout=300 --tries=3 --progress=dot:mega --no-check-certificate -O %s '%s' 2>&1",
                 download_path, url);

        USP_LOG_Info("Executing download command: %s", cmd);
        err = system(cmd);

        // Check if wget succeeded (return code 0)
        if (WIFEXITED(err) && WEXITSTATUS(err) == 0) {
            LogOperation("DOWNLOAD", "Package download completed successfully");

            // Verify file was actually downloaded
            FILE *fp = fopen(download_path, "r");
            if (fp == NULL) {
                output_args = USP_ARG_Create();
                USP_ARG_Add(output_args, "Result", "DownloadFailed");
                USP_SIGNAL_OperationComplete(instance, USP_ERR_INTERNAL_ERROR, "Downloaded file not found", output_args);
                return USP_ERR_OK;
            }
            fclose(fp);

        } else {
            USP_LOG_Error("Download failed with exit code: %d (raw: %d)", WEXITSTATUS(err), err);
            output_args = USP_ARG_Create();
            USP_ARG_Add(output_args, "Result", "DownloadFailed");
            USP_SIGNAL_OperationComplete(instance, USP_ERR_INTERNAL_ERROR, "Failed to download package", output_args);
            return USP_ERR_OK;
        }

        // Install downloaded .deb (running as root, no sudo needed)
        LogOperation("INSTALL", "Starting package installation");

        snprintf(cmd, sizeof(cmd),
                 "dpkg -i %s 2>&1 || (apt-get update && apt-get -f install -y)", download_path);

        USP_LOG_Info("Executing install command: %s", cmd);
        err = system(cmd);

        if (WIFEXITED(err) && WEXITSTATUS(err) == 0) {
            LogOperation("INSTALL", "Package installation completed successfully");
        } else {
            USP_LOG_Error("Installation failed with exit code: %d (raw: %d)", WEXITSTATUS(err), err);
            output_args = USP_ARG_Create();
            USP_ARG_Add(output_args, "Result", "InstallFailed");
            USP_SIGNAL_OperationComplete(instance, USP_ERR_INTERNAL_ERROR, "Package installation failed", output_args);
            return USP_ERR_OK;
        }
    } else {
        // Case 2: Install directly from apt repo (running as root, no sudo needed)
        LogOperation("INSTALL", "Starting apt repository installation");

        snprintf(cmd, sizeof(cmd),
                 "apt-get update && apt-get install -y %s", package);

        USP_LOG_Info("Executing apt install command: %s", cmd);
        err = system(cmd);

        if (WIFEXITED(err) && WEXITSTATUS(err) == 0) {
            LogOperation("INSTALL", "Package installation via apt completed successfully");
        } else {
            USP_LOG_Error("Apt installation failed with exit code: %d (raw: %d)", WEXITSTATUS(err), err);
            output_args = USP_ARG_Create();
            USP_ARG_Add(output_args, "Result", "InstallFailed");
            USP_SIGNAL_OperationComplete(instance, USP_ERR_INTERNAL_ERROR, "Package installation via apt failed", output_args);
            return USP_ERR_OK;
        }
    }

    LogOperation("COMPLETE", "Package installation completed successfully");

    // Signal successful completion
    output_args = USP_ARG_Create();
    USP_ARG_Add(output_args, "Result", "Success");
    USP_SIGNAL_OperationComplete(instance, USP_ERR_OK, NULL, output_args);

    USP_LOG_Info("Package %s installed successfully", package);

    return USP_ERR_OK;
}

// ----------------------------------------------------------------------
// Vendor Start Hook
int VENDOR_Start(void)
{
    USP_LOG_Info("VENDOR_Start: Vendor-specific services starting...");
    return USP_ERR_OK;
}

// ----------------------------------------------------------------------
// Vendor Stop Hook
void VENDOR_Stop(void)
{
    USP_LOG_Info("VENDOR_Stop: Vendor-specific cleanup...");
}