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
