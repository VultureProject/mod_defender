#ifndef MOD_DEFENDER_HPP
#define MOD_DEFENDER_HPP

/*
 * To install mod_defender:
 * sudo apxs -n defender -i mod_defender.so
 */

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
<<<<<<< HEAD
=======
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include "NxParser.h"

/*
 * Per-server configuration structure.
 */
typedef struct {
    char *errorlog_path;
    apr_file_t *errorlog_fd;
    char *nxcorerules_path;
    apr_file_t *nxcorerules_fd;
    vector<nxrule_t> rules;
} server_config_t;
>>>>>>> fd0f819... scoring system

#endif /* MOD_DEFENDER_HPP */

