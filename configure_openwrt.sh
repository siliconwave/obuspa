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
