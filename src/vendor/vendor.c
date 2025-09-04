// vendor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/wait.h>

#include "usp_api.h"
#include "usp_err_codes.h"
#include "core/usp_log.h"

// ----------------------------------------------------------------------
// Forward declaration
int PackageUpdateOperation(dm_req_t *req, kv_vector_t *input_args, int instance);

// ----------------------------------------------------------------------
// Vendor Init Hook
int VENDOR_Init(void)
{
    USP_LOG_Info("VENDOR_Init: Registering vendor operations...");

    // Register async operation
    USP_REGISTER_AsyncOperation("Device.PackageManager.UpdatePackage()",
                                PackageUpdateOperation,
                                NULL);

    return USP_ERR_OK;
}

// ----------------------------------------------------------------------
// Implementation: Generic Package Update
int PackageUpdateOperation(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err;
    char *url = NULL;
    char *package = NULL;

    // Get arguments (default NULL if missing)
    url = USP_ARG_Get(input_args, "URL", NULL);
    package = USP_ARG_Get(input_args, "PackageName", NULL);

    if ((package == NULL) || (strlen(package) == 0)) {
        USP_ERR_SetMessage("Missing required argument: PackageName");
        USP_ARG_Add(input_args, "Result", "MissingPackageName");
        return USP_ERR_INTERNAL_ERROR;
    }

    USP_LOG_Info("PackageUpdateOperation: Package=%s, URL=%s",
                 package, (url ? url : "NULL"));

    char cmd[2048];
    char download_path[512];

    if ((url != NULL) && (strlen(url) > 0)) {
        // Case 1: Download from provided URL
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
            USP_LOG_Info("Package download completed successfully");

            // Verify file was actually downloaded
            FILE *fp = fopen(download_path, "r");
            if (fp == NULL) {
                USP_ERR_SetMessage("Downloaded file not found");
                USP_ARG_Add(input_args, "Result", "DownloadFailed");
                return USP_ERR_INTERNAL_ERROR;
            }
            fclose(fp);

        } else {
            USP_LOG_Error("Download failed with exit code: %d (raw: %d)", WEXITSTATUS(err), err);
            USP_ERR_SetMessage("Failed to download package");
            USP_ARG_Add(input_args, "Result", "DownloadFailed");
            return USP_ERR_INTERNAL_ERROR;
        }

        // Install downloaded .deb (running as root, no sudo needed)
        snprintf(cmd, sizeof(cmd),
                 "dpkg -i %s 2>&1 || (apt-get update && apt-get -f install -y)", download_path);

        USP_LOG_Info("Executing install command: %s", cmd);
        err = system(cmd);

        if (WIFEXITED(err) && WEXITSTATUS(err) == 0) {
            USP_LOG_Info("Package installation completed successfully");
        } else {
            USP_LOG_Error("Installation failed with exit code: %d (raw: %d)", WEXITSTATUS(err), err);
            USP_ERR_SetMessage("Package installation failed");
            USP_ARG_Add(input_args, "Result", "InstallFailed");
            return USP_ERR_INTERNAL_ERROR;
        }
    } else {
        // Case 2: Install directly from apt repo (running as root, no sudo needed)
        snprintf(cmd, sizeof(cmd),
                 "apt-get update && apt-get install -y %s", package);

        USP_LOG_Info("Executing apt install command: %s", cmd);
        err = system(cmd);

        if (WIFEXITED(err) && WEXITSTATUS(err) == 0) {
            USP_LOG_Info("Package installation via apt completed successfully");
        } else {
            USP_LOG_Error("Apt installation failed with exit code: %d (raw: %d)", WEXITSTATUS(err), err);
            USP_ERR_SetMessage("Package installation via apt failed");
            USP_ARG_Add(input_args, "Result", "InstallFailed");
            return USP_ERR_INTERNAL_ERROR;
        }
    }

    USP_ARG_Add(input_args, "Result", "Success");
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