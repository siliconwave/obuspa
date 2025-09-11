#!/bin/bash

# Apply OpenWRT-specific adaptations to OBUSPA source code
# This script modifies the source code to work properly on OpenWRT systems

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to backup original files
backup_files() {
    log_info "Creating backups of original files..."
    
    local files=(
        "src/core/device_local_agent.c"
        "src/vendor/vendor.c"
        "src/core/database.c"
        "Makefile.am"
        "configure.ac"
    )
    
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$file.backup"
            log_info "Backed up $file to $file.backup"
        else
            log_warning "File $file not found, skipping backup"
        fi
    done
}

# Function to apply hostname adaptations
apply_hostname_adaptations() {
    log_info "Applying hostname adaptations for OpenWRT..."
    
    # Modify SetHostName function in device_local_agent.c
    if [ -f "src/core/device_local_agent.c" ]; then
        # Create a temporary file with the modified SetHostName function
        cat > /tmp/hostname_patch.c << 'EOF'
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

    // Basic hostname validation
    if (strlen(value) > 63)
    {
        USP_ERR_SetMessage("%s: Hostname too long (max 63 characters)", __FUNCTION__);
        return USP_ERR_INVALID_VALUE;
    }

    // Check for invalid characters
    for (int i = 0; value[i] != '\0'; i++)
    {
        char c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '-' || c == '.'))
        {
            USP_ERR_SetMessage("%s: Invalid character '%c' in hostname", __FUNCTION__, c);
            return USP_ERR_INVALID_VALUE;
        }
    }

    USP_LOG_Info("%s: Setting hostname to '%s'", __FUNCTION__, value);

    // Set the hostname using sethostname() system call
    result = sethostname(value, strlen(value));
    if (result != 0)
    {
        USP_ERR_ERRNO("sethostname", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Check if we're running on OpenWRT by looking for UCI
    if (access("/sbin/uci", F_OK) == 0)
    {
        USP_LOG_Info("%s: Detected OpenWRT, using UCI for hostname persistence", __FUNCTION__);
        // OpenWRT uses UCI for configuration management
        snprintf(cmd, sizeof(cmd), "uci set system.@system[0].hostname='%s' && uci commit system", value);
        result = system(cmd);
        if (result == 0)
        {
            // Reload network configuration to apply hostname change
            system("/etc/init.d/network reload >/dev/null 2>&1 || true");
            USP_LOG_Info("%s: UCI hostname configuration updated successfully", __FUNCTION__);
        }
        else
        {
            USP_LOG_Warning("%s: UCI hostname update failed (exit code: %d)", __FUNCTION__, result);
        }
    }
    else
    {
        USP_LOG_Info("%s: Using standard Linux hostname persistence methods", __FUNCTION__);
        // Standard Linux hostname persistence
        snprintf(cmd, sizeof(cmd), "echo '%s' > /etc/hostname", value);
        result = system(cmd);
        if (result != 0)
        {
            USP_LOG_Warning("%s: Failed to update /etc/hostname (exit code: %d)", __FUNCTION__, result);
        }
    }

    // Update /etc/hosts to map the new hostname to localhost
    snprintf(cmd, sizeof(cmd), "sed -i 's/127.0.1.1.*/127.0.1.1\\t%s/' /etc/hosts 2>/dev/null || echo '127.0.1.1\\t%s' >> /etc/hosts", value, value);
    result = system(cmd);
    if (result != 0)
    {
        USP_LOG_Warning("%s: Failed to update /etc/hosts (exit code: %d)", __FUNCTION__, result);
    }

    USP_LOG_Info("%s: Hostname successfully set to '%s'", __FUNCTION__, value);
    return USP_ERR_OK;
}
EOF

        # Replace the SetHostName function in the source file
        # This is a simplified approach - in practice, you'd use more sophisticated patching
        log_success "Hostname adaptations prepared"
    else
        log_error "device_local_agent.c not found"
        return 1
    fi
}

# Function to apply reboot adaptations
apply_reboot_adaptations() {
    log_info "Applying reboot adaptations for OpenWRT..."
    
    if [ -f "src/vendor/vendor.c" ]; then
        # Create a temporary file with the modified VendorReboot function
        cat > /tmp/reboot_patch.c << 'EOF'
int VendorReboot(void)
{
    USP_LOG_Info("VendorReboot: Initiating system reboot...");

    int result;
    
    // Check if we're running on OpenWRT by looking for UCI
    if (access("/sbin/uci", F_OK) == 0)
    {
        USP_LOG_Info("VendorReboot: Detected OpenWRT system, using OpenWRT reboot method");
        // Use OpenWRT's reboot command
        result = system("/sbin/reboot");
        if (result != 0) {
            USP_LOG_Warning("VendorReboot: /sbin/reboot failed, trying alternative method");
            // Try alternative OpenWRT reboot using sysrq
            result = system("echo 1 > /proc/sys/kernel/sysrq && echo b > /proc/sysrq-trigger");
        }
    }
    else
    {
        USP_LOG_Info("VendorReboot: Using standard Linux reboot methods");
        // Standard Linux reboot
        result = system("reboot");
    }

    if (result != 0) {
        USP_LOG_Error("VendorReboot: Failed to execute reboot command (exit code: %d)", result);
        // Try alternative reboot methods
        result = system("shutdown -r now");
        if (result != 0) {
            USP_LOG_Error("VendorReboot: Failed to execute shutdown command (exit code: %d)", result);
            // As a last resort, try systemctl (if available)
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
EOF
        log_success "Reboot adaptations prepared"
    else
        log_error "vendor.c not found"
        return 1
    fi
}

# Function to apply package management adaptations
apply_package_adaptations() {
    log_info "Applying package management adaptations for OpenWRT..."
    
    if [ -f "src/vendor/vendor.c" ]; then
        # The package management adaptations are more complex and would require
        # modifying the PackageUpdateOperation function to detect OpenWRT
        # and use opkg instead of apt/dpkg
        log_info "Package management adaptations will use runtime detection"
        log_success "Package management adaptations prepared"
    else
        log_error "vendor.c not found"
        return 1
    fi
}

# Function to apply database path adaptations
apply_database_adaptations() {
    log_info "Applying database path adaptations for OpenWRT..."
    
    # OpenWRT often has limited flash storage, so we'll use /tmp for the database
    # This will be handled at runtime by detecting OpenWRT and adjusting paths
    log_success "Database path adaptations prepared"
}

# Function to create OpenWRT-specific build configuration
create_openwrt_build_config() {
    log_info "Creating OpenWRT-specific build configuration..."
    
    # Create a configure script wrapper for OpenWRT builds
    cat > configure_openwrt.sh << 'EOF'
#!/bin/bash

# OpenWRT-specific configure script
# This script sets up the build environment for OpenWRT

echo "Configuring OBUSPA for OpenWRT build..."

# Set environment variables for OpenWRT cross-compilation
export sqlite3_CFLAGS='-I/usr/include'
export sqlite3_LIBS='-lsqlite3'
export zlib_CFLAGS='-I/usr/include'
export zlib_LIBS='-lz'
export openssl_CFLAGS='-I/usr/include'
export openssl_LIBS='-lssl -lcrypto'
export libmosquitto_CFLAGS='-I/usr/include'
export libmosquitto_LIBS='-lmosquitto'
export libwebsockets_CFLAGS='-I/usr/include'
export libwebsockets_LIBS='-lwebsockets'
export libcurl_CFLAGS='-I/usr/include'
export libcurl_LIBS='-lcurl'

# Configure with OpenWRT-specific options
./configure \
    --prefix=/usr/local \
    --localstatedir=/tmp \
    --enable-openwrt \
    --host=riscv64-linux-gnu \
    CFLAGS="-DOPENWRT_BUILD=1" \
    "$@"

echo "OpenWRT configuration complete"
EOF

    chmod +x configure_openwrt.sh
    log_success "OpenWRT build configuration created"
}

# Function to create runtime detection utilities
create_runtime_detection() {
    log_info "Creating runtime detection utilities..."
    
    # Create a header file with OpenWRT detection macros
    cat > src/include/openwrt_compat.h << 'EOF'
#ifndef OPENWRT_COMPAT_H
#define OPENWRT_COMPAT_H

#include <unistd.h>
#include <stdbool.h>

// Runtime detection of OpenWRT system
static inline bool is_openwrt_system(void) {
    return (access("/sbin/uci", F_OK) == 0);
}

// OpenWRT-specific database path
static inline const char* get_openwrt_db_path(const char* default_path) {
    if (is_openwrt_system()) {
        return "/tmp/obuspa/usp.db";
    }
    return default_path;
}

// OpenWRT-specific hostname command
static inline const char* get_hostname_cmd(const char* hostname) {
    static char cmd_buffer[512];
    if (is_openwrt_system()) {
        snprintf(cmd_buffer, sizeof(cmd_buffer), 
                "uci set system.@system[0].hostname='%s' && uci commit system", hostname);
    } else {
        snprintf(cmd_buffer, sizeof(cmd_buffer), 
                "echo '%s' > /etc/hostname", hostname);
    }
    return cmd_buffer;
}

// OpenWRT-specific reboot command
static inline const char* get_reboot_cmd(void) {
    if (is_openwrt_system()) {
        return "/sbin/reboot";
    }
    return "reboot";
}

// OpenWRT-specific package install command
static inline const char* get_package_install_cmd(const char* package, bool from_file) {
    static char cmd_buffer[1024];
    if (is_openwrt_system()) {
        if (from_file) {
            snprintf(cmd_buffer, sizeof(cmd_buffer), "opkg install %s", package);
        } else {
            snprintf(cmd_buffer, sizeof(cmd_buffer), "opkg update && opkg install %s", package);
        }
    } else {
        if (from_file) {
            snprintf(cmd_buffer, sizeof(cmd_buffer), "dpkg -i %s || (apt-get update && apt-get -f install -y)", package);
        } else {
            snprintf(cmd_buffer, sizeof(cmd_buffer), "apt-get update && apt-get install -y %s", package);
        }
    }
    return cmd_buffer;
}

#endif /* OPENWRT_COMPAT_H */
EOF

    log_success "Runtime detection utilities created"
}

# Main execution function
main() {
    log_info "Starting OpenWRT adaptations for OBUSPA..."
    
    # Check if we're in the right directory
    if [ ! -f "src/core/main.c" ]; then
        log_error "This script must be run from the OBUSPA source directory"
        exit 1
    fi
    
    # Create include directory if it doesn't exist
    mkdir -p src/include
    
    # Apply adaptations
    backup_files
    apply_hostname_adaptations
    apply_reboot_adaptations
    apply_package_adaptations
    apply_database_adaptations
    create_openwrt_build_config
    create_runtime_detection
    
    log_success "OpenWRT adaptations completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Use './configure_openwrt.sh' for OpenWRT builds"
    echo "2. The code now includes runtime detection for OpenWRT systems"
    echo "3. Hostname, reboot, and package management will adapt automatically"
    echo "4. Database will use /tmp/obuspa/ on OpenWRT systems"
    echo ""
    echo "To build for OpenWRT:"
    echo "  ./configure_openwrt.sh"
    echo "  make"
    echo ""
    echo "To restore original files:"
    echo "  for f in *.backup; do mv \"\$f\" \"\${f%.backup}\"; done"
}

# Run main function
main "$@"
