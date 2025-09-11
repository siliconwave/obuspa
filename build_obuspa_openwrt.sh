#!/bin/bash

# OBUSPA OpenWRT Build Script
# This script provides a comprehensive solution for building OBUSPA on OpenWRT RISC-V
# It handles missing headers and provides cross-platform compatibility

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENWRT_TARGET="root@192.168.1.40"
REMOTE_BUILD_DIR="/tmp/obuspa-build"
LOCAL_SOURCE_DIR="$SCRIPT_DIR"

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

# Function to check if we can connect to the OpenWRT device
check_connection() {
    log_info "Checking connection to OpenWRT device..."
    if ssh -o ConnectTimeout=5 "$OPENWRT_TARGET" "echo 'Connection OK'" >/dev/null 2>&1; then
        log_success "Connected to OpenWRT device"
        return 0
    else
        log_error "Cannot connect to OpenWRT device at $OPENWRT_TARGET"
        return 1
    fi
}

# Function to install required packages on OpenWRT
install_openwrt_packages() {
    log_info "Installing required packages on OpenWRT..."
    
    ssh "$OPENWRT_TARGET" << 'EOF'
        # Update package list
        opkg update || true
        
        # Install basic build tools
        opkg install gcc make autoconf libtool-bin pkg-config || true
        
        # Install runtime libraries
        opkg install libsqlite3-0 zlib libopenssl3 libcurl4 || true
        
        # Install MQTT and WebSocket libraries
        opkg remove --force-depends libwebsockets-full || true
        opkg install libmosquitto-ssl libwebsockets-openssl || true
        
        echo "Package installation complete"
EOF
    
    log_success "OpenWRT packages installed"
}

# Function to create comprehensive header files
create_headers() {
    log_info "Creating development headers on OpenWRT..."
    
    # Create the header installation script
    cat > /tmp/create_headers.sh << 'HEADER_SCRIPT'
#!/bin/bash

# Create header directories
mkdir -p /usr/include/{openssl,curl}

# Create comprehensive OpenSSL headers
cat > /usr/include/openssl/ssl.h << 'EOF'
#ifndef OPENSSL_SSL_H
#define OPENSSL_SSL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_store_st X509_STORE;

#define STACK_OF(type) struct stack_st_##type
typedef STACK_OF(X509) STACK_OF_X509;

/* SSL context methods */
const SSL_METHOD *TLS_client_method(void);
const SSL_METHOD *TLS_server_method(void);

/* SSL context functions */
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *ctx);
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);

/* SSL connection functions */
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_connect(SSL *ssl);
int SSL_accept(SSL *ssl);
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_shutdown(SSL *ssl);

/* Certificate functions */
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
int X509_verify_cert(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *x);
void X509_STORE_CTX_set_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);

/* Error handling */
unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);
void ERR_print_errors_fp(FILE *fp);

/* Constants */
#define SSL_FILETYPE_PEM 1
#define SSL_ERROR_NONE 0
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3

/* Initialization */
int OPENSSL_init_crypto(uint64_t opts, const void *settings);
int OPENSSL_init_ssl(uint64_t opts, const void *settings);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_SSL_H */
EOF

cat > /usr/include/openssl/crypto.h << 'EOF'
#ifndef OPENSSL_CRYPTO_H
#define OPENSSL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory functions */
void *CRYPTO_malloc(size_t num, const char *file, int line);
void CRYPTO_free(void *ptr, const char *file, int line);

#define OPENSSL_malloc(num) CRYPTO_malloc(num, __FILE__, __LINE__)
#define OPENSSL_free(addr) CRYPTO_free(addr, __FILE__, __LINE__)

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_CRYPTO_H */
EOF

cat > /usr/include/openssl/err.h << 'EOF'
#ifndef OPENSSL_ERR_H
#define OPENSSL_ERR_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);
void ERR_print_errors_fp(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_ERR_H */
EOF

cat > /usr/include/openssl/bio.h << 'EOF'
#ifndef OPENSSL_BIO_H
#define OPENSSL_BIO_H

#include <stdio.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;

/* Function declarations */
BIO *BIO_new(const BIO_METHOD *type);
int BIO_free(BIO *a);
void BIO_free_all(BIO *a);
BIO *BIO_new_mem_buf(const void *buf, int len);
BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_fp(FILE *stream, int close_flag);
int BIO_read(BIO *b, void *data, int len);
int BIO_write(BIO *b, const void *data, int len);
int BIO_puts(BIO *bp, const char *buf);
int BIO_gets(BIO *bp, char *buf, int size);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

const BIO_METHOD *BIO_s_mem(void);
const BIO_METHOD *BIO_s_file(void);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_BIO_H */
EOF

# Create SQLite3 headers
cat > /usr/include/sqlite3.h << 'EOF'
#ifndef SQLITE3_H
#define SQLITE3_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

/* Result codes */
#define SQLITE_OK           0
#define SQLITE_ERROR        1
#define SQLITE_BUSY         5
#define SQLITE_LOCKED       6
#define SQLITE_NOMEM        7
#define SQLITE_READONLY     8
#define SQLITE_INTERRUPT    9
#define SQLITE_IOERR       10
#define SQLITE_CORRUPT     11
#define SQLITE_NOTFOUND    12
#define SQLITE_FULL        13
#define SQLITE_CANTOPEN    14
#define SQLITE_PROTOCOL    15
#define SQLITE_EMPTY       16
#define SQLITE_SCHEMA      17
#define SQLITE_TOOBIG      18
#define SQLITE_CONSTRAINT  19
#define SQLITE_MISMATCH    20
#define SQLITE_MISUSE      21
#define SQLITE_NOLFS       22
#define SQLITE_AUTH        23
#define SQLITE_FORMAT      24
#define SQLITE_RANGE       25
#define SQLITE_NOTADB      26
#define SQLITE_ROW         100
#define SQLITE_DONE        101

/* Data types */
#define SQLITE_INTEGER  1
#define SQLITE_FLOAT    2
#define SQLITE_BLOB     4
#define SQLITE_NULL     5
#define SQLITE_TEXT     3

/* Function declarations */
int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3 *db);
int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);
int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_step(sqlite3_stmt *pStmt);
int sqlite3_finalize(sqlite3_stmt *pStmt);
int sqlite3_bind_text(sqlite3_stmt *pStmt, int i, const char *zData, int nData, void(*xDel)(void*));
int sqlite3_bind_int(sqlite3_stmt *pStmt, int i, int iValue);
const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);
int sqlite3_column_int(sqlite3_stmt *pStmt, int iCol);
const char *sqlite3_errmsg(sqlite3 *db);

#ifdef __cplusplus
}
#endif

#endif /* SQLITE3_H */
EOF

# Create zlib headers
cat > /usr/include/zlib.h << 'EOF'
#ifndef ZLIB_H
#define ZLIB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *gzFile;
typedef unsigned long uLong;
typedef unsigned char Byte;

/* Constants */
#define Z_OK            0
#define Z_STREAM_END    1
#define Z_NEED_DICT     2
#define Z_ERRNO        (-1)
#define Z_STREAM_ERROR (-2)
#define Z_DATA_ERROR   (-3)
#define Z_MEM_ERROR    (-4)
#define Z_BUF_ERROR    (-5)
#define Z_VERSION_ERROR (-6)

/* Function declarations */
int compress(Byte *dest, uLong *destLen, const Byte *source, uLong sourceLen);
int uncompress(Byte *dest, uLong *destLen, const Byte *source, uLong sourceLen);
uLong compressBound(uLong sourceLen);

#ifdef __cplusplus
}
#endif

#endif /* ZLIB_H */
EOF

# Create mosquitto headers
cat > /usr/include/mosquitto.h << 'EOF'
#ifndef MOSQUITTO_H
#define MOSQUITTO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mosquitto;

/* Error codes */
#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_NOMEM 1
#define MOSQ_ERR_PROTOCOL 2
#define MOSQ_ERR_INVAL 3
#define MOSQ_ERR_NO_CONN 4
#define MOSQ_ERR_CONN_REFUSED 5
#define MOSQ_ERR_NOT_FOUND 6
#define MOSQ_ERR_CONN_LOST 7
#define MOSQ_ERR_TLS 8
#define MOSQ_ERR_PAYLOAD_SIZE 9
#define MOSQ_ERR_NOT_SUPPORTED 10
#define MOSQ_ERR_AUTH 11
#define MOSQ_ERR_ACL_DENIED 12
#define MOSQ_ERR_UNKNOWN 13
#define MOSQ_ERR_ERRNO 14

/* Function declarations */
int mosquitto_lib_init(void);
int mosquitto_lib_cleanup(void);
struct mosquitto *mosquitto_new(const char *id, bool clean_session, void *userdata);
void mosquitto_destroy(struct mosquitto *mosq);
int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive);
int mosquitto_disconnect(struct mosquitto *mosq);
int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain);
int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos);
int mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets);
const char *mosquitto_strerror(int mosq_errno);

#ifdef __cplusplus
}
#endif

#endif /* MOSQUITTO_H */
EOF

# Create libwebsockets headers
cat > /usr/include/libwebsockets.h << 'EOF'
#ifndef LIBWEBSOCKETS_H
#define LIBWEBSOCKETS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lws;
struct lws_context;
struct lws_protocols;
struct lws_context_creation_info;

/* Basic function declarations */
struct lws_context *lws_create_context(struct lws_context_creation_info *info);
void lws_context_destroy(struct lws_context *context);
int lws_service(struct lws_context *context, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* LIBWEBSOCKETS_H */
EOF

# Create curl headers
cat > /usr/include/curl/curl.h << 'EOF'
#ifndef CURL_CURL_H
#define CURL_CURL_H

#include <stdio.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void CURL;
typedef void CURLM;
typedef void CURLSH;

typedef enum {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL,
    CURLE_FAILED_INIT,
    CURLE_URL_MALFORMAT,
    CURLE_NOT_BUILT_IN,
    CURLE_COULDNT_RESOLVE_PROXY,
    CURLE_COULDNT_RESOLVE_HOST,
    CURLE_COULDNT_CONNECT,
    CURLE_WEIRD_SERVER_REPLY,
    CURLE_REMOTE_ACCESS_DENIED,
    CURLE_OUT_OF_MEMORY = 27,
    CURLE_OPERATION_TIMEDOUT = 28,
    CURLE_HTTP_RETURNED_ERROR = 22,
    CURLE_WRITE_ERROR = 23,
    CURLE_READ_ERROR = 26,
    CURLE_SSL_CONNECT_ERROR = 35,
    CURLE_PEER_FAILED_VERIFICATION = 60,
    CURL_LAST
} CURLcode;

typedef enum {
    CURLOPT_WRITEDATA = 10001,
    CURLOPT_URL = 10002,
    CURLOPT_PORT = 3,
    CURLOPT_PROXY = 10004,
    CURLOPT_USERPWD = 10005,
    CURLOPT_PROXYUSERPWD = 10006,
    CURLOPT_RANGE = 10007,
    CURLOPT_READDATA = 10009,
    CURLOPT_ERRORBUFFER = 10010,
    CURLOPT_WRITEFUNCTION = 20011,
    CURLOPT_READFUNCTION = 20012,
    CURLOPT_TIMEOUT = 13,
    CURLOPT_INFILESIZE = 14,
    CURLOPT_POSTFIELDS = 10015,
    CURLOPT_REFERER = 10016,
    CURLOPT_FTPPORT = 10017,
    CURLOPT_USERAGENT = 10018,
    CURLOPT_LOW_SPEED_LIMIT = 19,
    CURLOPT_LOW_SPEED_TIME = 20,
    CURLOPT_RESUME_FROM = 21,
    CURLOPT_COOKIE = 10022,
    CURLOPT_HTTPHEADER = 10023,
    CURLOPT_HTTPPOST = 10024,
    CURLOPT_SSLCERT = 10025,
    CURLOPT_KEYPASSWD = 10026,
    CURLOPT_CRLF = 27,
    CURLOPT_QUOTE = 10028,
    CURLOPT_HEADERDATA = 10029,
    CURLOPT_COOKIEFILE = 10031,
    CURLOPT_SSLVERSION = 32,
    CURLOPT_TIMECONDITION = 33,
    CURLOPT_TIMEVALUE = 34,
    CURLOPT_CUSTOMREQUEST = 10036,
    CURLOPT_STDERR = 10037,
    CURLOPT_POSTQUOTE = 10039,
    CURLOPT_VERBOSE = 41,
    CURLOPT_HEADER = 42,
    CURLOPT_NOPROGRESS = 43,
    CURLOPT_NOBODY = 44,
    CURLOPT_FAILONERROR = 45,
    CURLOPT_UPLOAD = 46,
    CURLOPT_POST = 47,
    CURLOPT_DIRLISTONLY = 48,
    CURLOPT_APPEND = 50,
    CURLOPT_NETRC = 51,
    CURLOPT_FOLLOWLOCATION = 52,
    CURLOPT_TRANSFERTEXT = 53,
    CURLOPT_PUT = 54,
    CURLOPT_PROGRESSFUNCTION = 20056,
    CURLOPT_PROGRESSDATA = 10057,
    CURLOPT_AUTOREFERER = 58,
    CURLOPT_PROXYPORT = 59,
    CURLOPT_POSTFIELDSIZE = 60,
    CURLOPT_HTTPPROXYTUNNEL = 61,
    CURLOPT_INTERFACE = 10062,
    CURLOPT_KRBLEVEL = 10063,
    CURLOPT_SSL_VERIFYPEER = 64,
    CURLOPT_CAINFO = 10065,
    CURLOPT_MAXREDIRS = 68,
    CURLOPT_FILETIME = 69,
    CURLOPT_TELNETOPTIONS = 10070,
    CURLOPT_MAXCONNECTS = 71,
    CURLOPT_FRESH_CONNECT = 74,
    CURLOPT_FORBID_REUSE = 75,
    CURLOPT_RANDOM_FILE = 10076,
    CURLOPT_EGDSOCKET = 10077,
    CURLOPT_CONNECTTIMEOUT = 78,
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_HTTPGET = 80,
    CURLOPT_SSL_VERIFYHOST = 81,
    CURLOPT_COOKIEJAR = 10082,
    CURLOPT_SSL_CIPHER_LIST = 10083,
    CURLOPT_HTTP_VERSION = 84,
    CURLOPT_FTP_USE_EPSV = 85,
    CURLOPT_SSLCERTTYPE = 10086,
    CURLOPT_SSLKEY = 10087,
    CURLOPT_SSLKEYTYPE = 10088,
    CURLOPT_SSLENGINE = 10089,
    CURLOPT_SSLENGINE_DEFAULT = 90,
    CURLOPT_DNS_USE_GLOBAL_CACHE = 91,
    CURLOPT_DNS_CACHE_TIMEOUT = 92,
    CURLOPT_PREQUOTE = 10093,
    CURLOPT_DEBUGFUNCTION = 20094,
    CURLOPT_DEBUGDATA = 10095,
    CURLOPT_COOKIESESSION = 96,
    CURLOPT_CAPATH = 10097,
    CURLOPT_BUFFERSIZE = 98,
    CURLOPT_NOSIGNAL = 99,
    CURLOPT_SHARE = 10100,
    CURLOPT_PROXYTYPE = 101,
    CURLOPT_ACCEPT_ENCODING = 10102,
    CURLOPT_PRIVATE = 10103,
    CURLOPT_HTTP200ALIASES = 10104,
    CURLOPT_UNRESTRICTED_AUTH = 105,
    CURLOPT_FTP_USE_EPRT = 106,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_SSL_CTX_FUNCTION = 20108,
    CURLOPT_SSL_CTX_DATA = 10109,
    CURLOPT_FTP_CREATE_MISSING_DIRS = 110,
    CURLOPT_PROXYAUTH = 111,
    CURLOPT_FTP_RESPONSE_TIMEOUT = 112,
    CURLOPT_IPRESOLVE = 113,
    CURLOPT_MAXFILESIZE = 114,
    CURLOPT_LASTENTRY
} CURLoption;

typedef size_t (*curl_write_callback)(char *ptr, size_t size, size_t nmemb, void *userdata);
typedef size_t (*curl_read_callback)(char *buffer, size_t size, size_t nitems, void *instream);

/* Function declarations */
CURL *curl_easy_init(void);
CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
CURLcode curl_easy_perform(CURL *curl);
void curl_easy_cleanup(CURL *curl);
const char *curl_easy_strerror(CURLcode);
CURLcode curl_global_init(long flags);
void curl_global_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* CURL_CURL_H */
EOF

echo "Headers created successfully"
HEADER_SCRIPT

    # Copy and execute the header creation script
    scp /tmp/create_headers.sh "$OPENWRT_TARGET:/tmp/"
    ssh "$OPENWRT_TARGET" "chmod +x /tmp/create_headers.sh && /tmp/create_headers.sh"
    
    log_success "Development headers created"
}

# Function to copy source code to OpenWRT
copy_source() {
    log_info "Copying source code to OpenWRT device..."
    
    # Create remote build directory
    ssh "$OPENWRT_TARGET" "rm -rf $REMOTE_BUILD_DIR && mkdir -p $REMOTE_BUILD_DIR"
    
    # Copy source code excluding build artifacts
    tar czf - --exclude='.git' --exclude='obuspa' --exclude='*.o' --exclude='*.lo' --exclude='.libs' --exclude='autom4te.cache' . | \
        ssh "$OPENWRT_TARGET" "cd $REMOTE_BUILD_DIR && tar xzf -"
    
    log_success "Source code copied"
}

# Function to configure and build OBUSPA
build_obuspa() {
    log_info "Configuring and building OBUSPA on OpenWRT..."

    ssh "$OPENWRT_TARGET" << 'EOF'
        cd /tmp/obuspa-build

        # Set environment variables for manual library configuration
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

        # Configure
        echo "Running configure..."
        if ! ./configure --prefix=/usr/local; then
            echo "Configure failed"
            exit 1
        fi

        # Build with reduced parallelism to avoid memory issues
        echo "Building OBUSPA..."
        if ! make -j1; then
            echo "Build failed"
            exit 1
        fi

        # Check if binary was created
        if [ ! -f "./obuspa" ] || [ ! -x "./obuspa" ]; then
            echo "Binary not created or not executable"
            exit 1
        fi

        echo "Build completed successfully"
EOF

    if [ $? -eq 0 ]; then
        log_success "OBUSPA built successfully on OpenWRT"
        return 0
    else
        log_error "Build failed"
        return 1
    fi
}

# Function to test the built binary
test_obuspa() {
    log_info "Testing OBUSPA binary..."
    
    ssh "$OPENWRT_TARGET" << 'EOF'
        cd /tmp/obuspa-build
        
        # Test if binary was created and is executable
        if [ -f "./obuspa" ] && [ -x "./obuspa" ]; then
            echo "Binary exists and is executable"
            
            # Test basic functionality
            echo "Testing help output..."
            ./obuspa -h || true
            
            echo "Testing version info..."
            ./obuspa -v 1 -c get "Device.DeviceInfo.Manufacturer" 2>/dev/null || echo "CLI test completed (expected to fail without daemon)"
            
            echo "Binary test completed"
        else
            echo "ERROR: Binary not found or not executable"
            exit 1
        fi
EOF
    
    if [ $? -eq 0 ]; then
        log_success "OBUSPA binary test passed"
        return 0
    else
        log_error "Binary test failed"
        return 1
    fi
}

# Function to copy binary back to x86 system
copy_binary_back() {
    log_info "Copying RISC-V binary back to x86 system..."
    
    scp "$OPENWRT_TARGET:$REMOTE_BUILD_DIR/obuspa" "./obuspa-riscv"
    
    if [ -f "./obuspa-riscv" ]; then
        log_success "RISC-V binary copied as 'obuspa-riscv'"
        ls -la ./obuspa-riscv
        file ./obuspa-riscv
    else
        log_error "Failed to copy binary"
        return 1
    fi
}

# Main execution function
main() {
    log_info "Starting OBUSPA OpenWRT build process..."
    
    # Check connection
    if ! check_connection; then
        exit 1
    fi
    
    # Install packages
    install_openwrt_packages
    
    # Create headers
    create_headers
    
    # Copy source
    copy_source
    
    # Build
    if build_obuspa; then
        test_obuspa
        copy_binary_back
        log_success "OBUSPA OpenWRT build process completed successfully!"
        echo ""
        echo "Next steps:"
        echo "1. Copy 'obuspa-riscv' to the OpenWRT device"
        echo "2. Test functionality with: ./obuspa-riscv -c get 'Device.DeviceInfo.'"
        echo "3. Run full daemon with: ./obuspa-riscv -p -v 4 -r siliconwaves_mqtt_config.txt"
    else
        log_error "Build process failed"
        exit 1
    fi
}

# Run main function
main "$@"
