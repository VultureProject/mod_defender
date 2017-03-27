/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#ifndef MOD_DEFENDER_HPP
#define MOD_DEFENDER_HPP

#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <apr_strings.h>
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
    char *matchlog_path;
    char *jsonmatchlog_path;
    apr_file_t *matchlog_fd;
    apr_file_t *jsonmatchlog_fd;
    unsigned long requestBodyLimit;
    bool libinjection_sql;
    bool libinjection_xss;
    bool libinjection;
    bool learning;
    bool extensive;
    bool useenv;
} server_config_t;

#endif /* MOD_DEFENDER_HPP */

