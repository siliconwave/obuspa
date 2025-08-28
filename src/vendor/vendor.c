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

    char cmd[1024];

    if ((url != NULL) && (strlen(url) > 0)) {
        // Case 1: Download from provided URL
        snprintf(cmd, sizeof(cmd),
                 "/usr/bin/wget -O /tmp/%s.deb %s", package, url);

        err = system(cmd);
        if (err != 0) {
            USP_ERR_SetMessage("Failed to download package");
            USP_ARG_Add(input_args, "Result", "DownloadFailed");
            return USP_ERR_INTERNAL_ERROR;
        }

        // Install downloaded .deb
        snprintf(cmd, sizeof(cmd),
                 "sudo dpkg -i /tmp/%s.deb || sudo apt-get -f install -y", package);

        err = system(cmd);
        if (err != 0) {
            USP_ERR_SetMessage("Package installation failed");
            USP_ARG_Add(input_args, "Result", "InstallFailed");
            return USP_ERR_INTERNAL_ERROR;
        }
    } else {
        // Case 2: Install directly from apt repo
        snprintf(cmd, sizeof(cmd),
                 "sudo apt-get update && sudo apt-get install -y %s", package);

        err = system(cmd);
        if (err != 0) {
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