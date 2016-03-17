#ifndef MOD_DEFENDER_HPP
#define MOD_DEFENDER_HPP

#ifdef __cplusplus
#define EXTERN_C_BLOCK_BEGIN    extern "C" {
#define EXTERN_C_BLOCK_END      }
#define EXTERN_C_FUNC           extern "C"
#else
#define EXTERN_C_BLOCK_BEGIN
#define EXTERN_C_BLOCK_END
#define EXTERN_C_FUNC
#endif

#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include "RuleParser.h"

// Shell colors
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

// Extra Apache 2.4+ C++ module declaration
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(defender);
#endif

/*
 * Per-server configuration structure.
 */
typedef struct {
    char *errorlog_path;
    apr_file_t *errorlog_fd;
} server_config_t;

#endif /* MOD_DEFENDER_HPP */

